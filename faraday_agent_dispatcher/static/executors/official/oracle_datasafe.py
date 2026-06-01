#!/usr/bin/env python
"""Oracle DataSafe (OCI) Database-security REST importer.

Pulls the target-database catalogue and the security-assessment
finding catalogue from an Oracle Cloud Infrastructure DataSafe tenancy
and emits Faraday bulk-create JSON on stdout.  Each registered DataSafe
target database becomes one Faraday host (keyed by the target
database OCID — DataSafe's surface is target-scoped so the host record
is keyed on the DataSafe target id rather than the underlying database
IP); the target's open security-assessment findings attach as Faraday
vulnerabilities with the engine prefix ``[DATABASE-SECURITY]``.  The
host record carries ``host.os`` set to the Oracle database product +
release string (e.g. ``Oracle Database 19c Enterprise (DataSafe
target=ACTIVE)``) so the database stack version is visible alongside
the per-finding observations.

Endpoints used:
  GET <OCI_HOST>/20181201/targetDatabases
      -> paginated catalogue of the DataSafe-registered target
      databases for ``compartmentId``.  Filtered server-side by
      ``targetDatabaseId`` when DATASAFE_TARGET_ID is set so a single
      database can be scanned without walking the whole tenancy.
  GET <OCI_HOST>/20181201/findings
      -> paginated security-assessment findings for the scoped
      ``compartmentId`` (and optional ``targetId``).  Each finding =
      one DataSafe rule observation (USER_ACCOUNTS / PRIVILEGES /
      AUTHORIZATION_CONTROL / DATA_ENCRYPTION / FINE_GRAINED_ACCESS /
      AUDITING / DATABASE_CONFIGURATION) tied to one target database.
      Pagination is OCI's canonical ``opc-next-page`` response-header
      cursor that is fed back as the ``page`` query-string param on
      the next call.

Auth: OCI Signature v1 — RSA-SHA256-signed HTTP Signatures (draft
RFC).  The signing string is
``(request-target): <method> <path>\\nhost: <host>\\ndate: <RFC1123>``
(GET / HEAD / DELETE) or with ``x-content-sha256`` /
``content-length`` / ``content-type`` appended for POST / PUT / PATCH.
The keyId is ``<OCI_TENANCY_OCID>/<OCI_USER_OCID>/<OCI_FINGERPRINT>``.
The private key (PEM) is loaded from ``OCI_PRIVATE_KEY_PATH``.

OCI_HOST defaults to the canonical regional endpoint pattern
``https://datasafe.<region>.oci.oraclecloud.com`` where ``<region>``
comes from ``OCI_REGION`` (e.g. ``us-ashburn-1``).  Explicit
``OCI_HOST`` overrides this for federated / Government Cloud / OC2 /
OC3 / OC4 deployments.
"""

import base64
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from email.utils import format_datetime

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# OCI canonical host shape: ``https://datasafe.<region>.oci.oraclecloud.com``
# but the executor accepts any ``http(s)://host[:port]`` so federated
# / on-prem / mock instances can override.
HOST_RE = re.compile(r"\Ahttps?://[A-Za-z0-9.\-]+(?::\d{1,5})?\Z")

# OCI OCIDs look like ``ocid1.{resource}.{realm}.{region?}.{id}``.
# The id portion is alphanumeric (lowercase) ~24+ chars.  Anchored
# with \A/\Z (not ^/$) so a trailing newline cannot sneak through.
OCID_RE = re.compile(r"\Aocid1\.[a-z]+\.[a-z0-9\-]+\.[a-z0-9\-]*\.[a-z0-9]{10,}\Z")

# OCI region shape — lowercase alphanumeric + ``-`` up to 32 chars
# (e.g. ``us-ashburn-1`` / ``eu-frankfurt-1`` / ``ap-tokyo-1``).
REGION_RE = re.compile(r"\A[a-z0-9\-]{1,32}\Z")

# OCI API-key fingerprint shape: 16 colon-separated hex bytes.
FINGERPRINT_RE = re.compile(r"\A[0-9a-f]{2}(?::[0-9a-f]{2}){15}\Z", re.IGNORECASE)

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 100

# DataSafe surfaces ``severity`` as a freeform string enum (HIGH /
# MEDIUM / LOW / EVALUATE / ADVISORY / PASS / DEFERRED).  HIGH /
# MEDIUM / LOW bucket onto the matching Faraday tier; EVALUATE flags
# rules that need an operator decision and lifts to medium so they
# aren't silently dropped; ADVISORY / PASS / DEFERRED are
# informational and squash to info.
DATASAFE_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "severe": "critical",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "evaluate": "medium",
    "review": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "advisory": "info",
    "pass": "info",
    "deferred": "info",
    "none": "info",
    "unknown": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# DataSafe finding lifecycle is exposed through ``lifecycleState`` on
# the parent assessment (CREATING / ACTIVE / UPDATING / INACTIVE /
# DELETING / DELETED / FAILED / NEEDS_ATTENTION) plus a per-finding
# ``isRisk`` boolean that flags whether the rule observation
# represents an actual risk.  The Faraday status is derived from the
# per-finding ``isRisk`` first (the canonical risk gate) and falls
# back to common freeform shapes for federated stacks.
DATASAFE_STATUS_BY_STATE = {
    "open": "open",
    "new": "open",
    "active": "open",
    "needs_attention": "open",
    "needsattention": "open",
    "detected": "open",
    "in_progress": "open",
    "inprogress": "open",
    "investigating": "open",
    "triaging": "open",
    "reopened": "open",
    "remediated": "closed",
    "resolved": "closed",
    "fixed": "closed",
    "mitigated": "closed",
    "closed": "closed",
    "inactive": "closed",
    "deleted": "closed",
    "pass": "closed",
    "completed": "closed",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "accepted": "risk-accepted",
    "acknowledged": "risk-accepted",
    "deferred": "risk-accepted",
    "waived": "risk-accepted",
    "will_not_fix": "risk-accepted",
    "willnotfix": "risk-accepted",
    "wontfix": "risk-accepted",
    "won't_fix": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
    "suppressed": "risk-accepted",
    "dismissed": "risk-accepted",
    "ignored": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - DataSafe: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    # Per-scan EXECUTOR_CONFIG_<name> arg wins; bare env-var is the fallback.
    if name.startswith("EXECUTOR_CONFIG_"):
        value = os.getenv(name, default)
    else:
        value = os.environ.get(f"EXECUTOR_CONFIG_{name}") or os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def severity_from_cvss(score):
    """Bucket a numeric severity (0-10 CVSS-style) onto a Faraday tier."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "info"
    if score <= 0:
        return "info"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    if score > 10:
        return "info"
    return "critical"


def severity_from_datasafe(value, numeric=None):
    """Map a DataSafe severity string onto a Faraday bucket.

    Accepts the canonical DataSafe enum (HIGH / MEDIUM / LOW /
    EVALUATE / ADVISORY / PASS / DEFERRED), Faraday-side synonyms
    (critical / severe / major / moderate / warning / minor /
    informational / information), numeric inputs (0-10 CVSS-style),
    numeric strings, and falls back to numeric bucketing on
    ``numeric`` when the primary value is missing or unrecognised.
    """
    if isinstance(value, bool):
        if numeric is not None:
            return severity_from_cvss(numeric)
        return "info"
    if isinstance(value, (int, float)):
        return severity_from_cvss(value)
    if isinstance(value, str) and value.strip():
        text = value.strip().lower().replace(" ", "_").replace("-", "_")
        if text in DATASAFE_STRING_SEVERITY:
            return DATASAFE_STRING_SEVERITY[text]
        squashed = text.replace("_", "")
        if squashed in DATASAFE_STRING_SEVERITY:
            return DATASAFE_STRING_SEVERITY[squashed]
        try:
            return severity_from_cvss(float(value.strip()))
        except ValueError:
            pass
    if numeric is not None:
        return severity_from_cvss(numeric)
    return "info"


def status_from_datasafe(item):
    """Derive Faraday status from a DataSafe finding payload.

    DataSafe's canonical risk gate is the per-finding ``isRisk``
    boolean (true => the rule observation is an actual risk =>
    open; false => the rule passed => closed).  Walks the freeform
    ``status`` / ``state`` / ``lifecycleState`` shapes after that for
    federated stacks that re-emit the catalogue under a different
    schema.
    """
    if not isinstance(item, dict):
        return "open"

    # isRisk is the canonical risk-gate on DataSafe findings; respect
    # it before falling through to freeform state strings.
    is_risk = item.get("isRisk")
    if is_risk is None:
        is_risk = item.get("is_risk")
    if isinstance(is_risk, bool):
        # An explicit false on isRisk means the rule passed — but only
        # trust it as closed when there's no overriding lifecycle /
        # status field that would say otherwise (e.g. NEEDS_ATTENTION).
        if is_risk is False:
            for key in ("status", "state", "lifecycleState", "lifecycle_state"):
                raw = item.get(key)
                if isinstance(raw, str) and raw.strip():
                    compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
                    if compact in DATASAFE_STATUS_BY_STATE:
                        return DATASAFE_STATUS_BY_STATE[compact]
            return "closed"

    for key in (
        "status",
        "state",
        "lifecycleState",
        "lifecycle_state",
        "findingStatus",
        "finding_status",
        "remediation_status",
        "remediationStatus",
        "resolutionStatus",
        "resolution_status",
        "Status",
        "State",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in DATASAFE_STATUS_BY_STATE:
                return DATASAFE_STATUS_BY_STATE[compact]
            if squashed in DATASAFE_STATUS_BY_STATE:
                return DATASAFE_STATUS_BY_STATE[squashed]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    if compact in DATASAFE_STATUS_BY_STATE:
                        return DATASAFE_STATUS_BY_STATE[compact]
    return "open"


def validate_min_severity(value):
    """Validate DS_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts canonical Faraday buckets plus DataSafe synonyms
    (evaluate / review -> medium, advisory / pass / deferred -> info)
    plus numeric-string CVSS-style input bucketed via
    severity_from_cvss.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    if not text:
        return "info"
    bucket = DATASAFE_STRING_SEVERITY.get(text)
    if bucket is None:
        bucket = DATASAFE_STRING_SEVERITY.get(text.replace("_", ""))
    if bucket is None:
        try:
            bucket = severity_from_cvss(float(str(value).strip()))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"DS_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_ocid(value, label, required=True):
    """Validate an OCI OCID.

    None / blank -> sys.exit(1) when required; returns ``None``
    when optional.  Control chars rejected on the raw value before
    .strip() so a header-injection attempt can't sneak through.
    """
    if value is None or value == "":
        if required:
            log(f"{label} is required")
            sys.exit(1)
        return None
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log(f"{label} contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        if required:
            log(f"{label} is required")
            sys.exit(1)
        return None
    if not OCID_RE.match(text):
        log(f"{label} '{text}' is not a valid OCI OCID (ocid1.<type>.<realm>.<region?>.<id>)")
        sys.exit(1)
    return text


def validate_region(value):
    """Validate OCI_REGION.  None / blank -> None (host must be supplied)."""
    if value is None or value == "":
        return None
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("OCI_REGION contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip().lower()
    if not text:
        return None
    if not REGION_RE.match(text):
        log(f"OCI_REGION '{text}' is not a valid OCI region identifier")
        sys.exit(1)
    return text


def validate_fingerprint(value):
    """Validate OCI_FINGERPRINT: 16 colon-separated hex bytes."""
    if value is None or value == "":
        log("OCI_FINGERPRINT is required")
        sys.exit(1)
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("OCI_FINGERPRINT contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not FINGERPRINT_RE.match(text):
        log(f"OCI_FINGERPRINT '{text}' is not 16 colon-separated hex bytes")
        sys.exit(1)
    return text.lower()


def validate_host(value):
    """Validate OCI_HOST. None / blank -> caller derives from OCI_REGION."""
    if value is None or value == "":
        return None
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("OCI_HOST contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip().rstrip("/")
    if not text:
        return None
    if not HOST_RE.match(text):
        log(f"OCI_HOST '{text}' is not http(s)://host[:port]")
        sys.exit(1)
    return text


def derive_host(region):
    """Derive the canonical DataSafe regional endpoint from a region id."""
    if not region:
        log("OCI_HOST or OCI_REGION must be supplied so the DataSafe " "endpoint can be resolved")
        sys.exit(1)
    return f"https://datasafe.{region}.oci.oraclecloud.com"


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def load_private_key(path):
    """Load an RSA private key from ``path`` for OCI signing.

    Uses cryptography.hazmat lazily so the smoke tests don't require
    the library to be installed.  PEM-encoded RSA private keys are
    the canonical OCI API-key format (the .pem file generated by
    ``openssl genrsa -out oci_api_key.pem 2048``).
    """
    if not path:
        log("OCI_PRIVATE_KEY_PATH is required")
        sys.exit(1)
    if not os.path.isfile(path):
        log(f"OCI_PRIVATE_KEY_PATH '{path}' does not exist or is not a file")
        sys.exit(1)
    try:
        with open(path, "rb") as fp:
            pem_bytes = fp.read()
    except OSError as exc:
        log(f"failed to read OCI_PRIVATE_KEY_PATH '{path}': {exc}")
        sys.exit(1)
    try:
        from cryptography.hazmat.primitives import serialization  # noqa: WPS433
    except ImportError:
        log(
            "cryptography is not installed in the executor environment "
            "(required for OCI Signature v1 RSA-SHA256 signing)"
        )
        sys.exit(1)
    try:
        # An OCI API-key PEM is conventionally unencrypted; pass-phrase
        # protected keys are not supported by the OCI signing spec.
        return serialization.load_pem_private_key(pem_bytes, password=None)
    except Exception as exc:  # noqa: BLE001 — surface any decode err
        log(f"failed to parse OCI_PRIVATE_KEY_PATH '{path}': {exc}")
        sys.exit(1)


def sign_with_private_key(private_key, signing_string):
    """RSA-SHA256-sign ``signing_string`` with ``private_key`` (PKCS#1 v1.5)."""
    from cryptography.hazmat.primitives import hashes  # noqa: WPS433
    from cryptography.hazmat.primitives.asymmetric import padding  # noqa: WPS433

    signature = private_key.sign(
        signing_string.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


def build_key_id(tenancy_ocid, user_ocid, fingerprint):
    """Build the OCI Signature v1 keyId pivot ``tenancy/user/fingerprint``."""
    return f"{tenancy_ocid}/{user_ocid}/{fingerprint}"


def build_signing_string(method, path, host, date_header):
    """Build the OCI Signature v1 signing string for a GET / HEAD / DELETE call.

    Per the OCI spec, GET / HEAD / DELETE requests sign only
    ``(request-target) host date`` — the body-related headers
    (``x-content-sha256`` / ``content-length`` / ``content-type``)
    are required only for POST / PUT / PATCH.
    """
    return f"(request-target): {method.lower()} {path}\n" f"host: {host}\n" f"date: {date_header}"


def build_authorization_header(key_id, signature, headers="(request-target) host date"):
    """Build the OCI Signature v1 Authorization header value."""
    return (
        f'Signature version="1",'
        f'keyId="{key_id}",'
        f'algorithm="rsa-sha256",'
        f'headers="{headers}",'
        f'signature="{signature}"'
    )


def host_from_url(url):
    """Extract the ``host[:port]`` fragment from a full http(s) URL."""
    if not isinstance(url, str):
        return ""
    text = url.strip()
    for prefix in ("https://", "http://"):
        if text.lower().startswith(prefix):
            text = text[len(prefix) :]
            break
    # Strip path / query — host runs up to the first / ? # char.
    for sep in ("/", "?", "#"):
        i = text.find(sep)
        if i >= 0:
            text = text[:i]
    return text


def path_from_url(url):
    """Extract the path + query fragment from a full http(s) URL."""
    if not isinstance(url, str):
        return "/"
    text = url.strip()
    for prefix in ("https://", "http://"):
        if text.lower().startswith(prefix):
            text = text[len(prefix) :]
            break
    i = text.find("/")
    if i < 0:
        return "/"
    return text[i:]


def signed_headers(method, url, private_key, key_id):
    """Build the per-request signed headers for an OCI Signature v1 GET call."""
    now = datetime.now(timezone.utc)
    # OCI requires RFC 1123 date (e.g. ``Tue, 11 Mar 2025 12:34:56 GMT``).
    date_header = format_datetime(now, usegmt=True)
    host = host_from_url(url)
    path = path_from_url(url)
    signing_string = build_signing_string(method, path, host, date_header)
    signature = sign_with_private_key(private_key, signing_string)
    return {
        "Date": date_header,
        "Host": host,
        "Authorization": build_authorization_header(key_id, signature),
        "Accept": "application/json",
    }


def build_target_databases_url(host):
    return f"{host}/20181201/targetDatabases"


def build_findings_url(host):
    return f"{host}/20181201/findings"


def extract_results(body):
    """Pull the result list out of an OCI pagination envelope.

    OCI list endpoints conventionally return a bare JSON array on the
    body — but DataSafe's ``listFindings`` route can also wrap the
    array in ``{"items": [...]}``.  Accept either shape (plus
    ``data`` / ``results`` / ``entries`` for federated stacks).
    """
    if isinstance(body, list):
        return [it for it in body if isinstance(it, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("items", "data", "results", "entries", "targets", "findings"):
        v = body.get(key)
        if isinstance(v, list):
            return [it for it in v if isinstance(it, dict)]
    return []


def extract_next_page(headers):
    """Pull the ``opc-next-page`` cursor token from a response header bag."""
    if headers is None:
        return None
    # Real requests.Response.headers is case-insensitive but the
    # stub used in tests is a plain dict — accept either.
    for key in ("opc-next-page", "Opc-Next-Page", "OPC-NEXT-PAGE"):
        try:
            value = headers.get(key)
        except AttributeError:
            value = None
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _serialise(obj):
    if obj is None:
        return ""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (str, int, float)):
        return str(obj)
    try:
        return json.dumps(obj, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(obj)


def collect_cves(item):
    """Walk a DataSafe finding payload for CVE-* ids."""
    found = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip().upper()
        if not CVE_RE.fullmatch(s):
            return
        if s in seen:
            return
        seen.add(s)
        found.append(s)

    def scan(text):
        if not isinstance(text, str):
            return
        for m in CVE_RE.findall(text):
            add(m)

    if not isinstance(item, dict):
        return found

    for key in ("cve", "cveId", "cve_id"):
        v = item.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cves", "cve_ids"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("id") or entry.get("cve") or entry.get("cve_id"))

    for key in (
        "title",
        "summary",
        "description",
        "details",
        "remarks",
        "justification",
        "details_description",
    ):
        v = item.get(key)
        if isinstance(v, str):
            scan(v)
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    scan(entry)

    return found


def collect_refs(item):
    """Walk a DataSafe finding payload for OCI / DataSafe pivot refs."""
    refs = []
    seen = set()

    def add(text):
        if not text:
            return
        s = str(text).strip()
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(item, dict):
        return refs

    finding_id = item.get("id") or item.get("findingId") or item.get("finding_id")
    if finding_id is not None:
        s = str(finding_id).strip()
        if s:
            add(f"DataSafe-Finding: {s}")

    key = item.get("key") or item.get("findingKey") or item.get("finding_key")
    if key is not None:
        s = str(key).strip()
        if s:
            add(f"DataSafe-FindingKey: {s}")

    rule = item.get("rule") or item.get("ruleKey") or item.get("rule_key")
    if isinstance(rule, str) and rule.strip():
        add(f"DataSafe-Rule: {rule.strip()}")

    category = item.get("category") or item.get("findingCategory") or item.get("finding_category")
    if isinstance(category, str) and category.strip():
        add(f"DataSafe-Category: {category.strip()}")

    reference = item.get("reference") or item.get("references")
    if isinstance(reference, str) and reference.strip():
        add(f"DataSafe-Reference: {reference.strip()}")
    elif isinstance(reference, list):
        for entry in reference:
            if isinstance(entry, str) and entry.strip():
                add(f"DataSafe-Reference: {entry.strip()}")
            elif isinstance(entry, dict):
                label = entry.get("name") or entry.get("ref") or entry.get("id")
                if isinstance(label, str) and label.strip():
                    add(f"DataSafe-Reference: {label.strip()}")

    for key_label, key_name in (
        ("Target", "targetId"),
        ("Target", "target_id"),
        ("Compartment", "compartmentId"),
        ("Compartment", "compartment_id"),
        ("Assessment", "assessmentId"),
        ("Assessment", "assessment_id"),
        ("AssessmentType", "type"),
    ):
        v = item.get(key_name)
        if isinstance(v, str) and v.strip():
            add(f"DataSafe-{key_label}: {v.strip()}")

    cis = item.get("cis_benchmark") or item.get("cisBenchmark")
    if isinstance(cis, str) and cis.strip():
        add(f"CIS-Benchmark: {cis.strip()}")
    elif isinstance(cis, list):
        for entry in cis:
            if isinstance(entry, str) and entry.strip():
                add(f"CIS-Benchmark: {entry.strip()}")

    stig = item.get("stig") or item.get("stigId") or item.get("stig_id")
    if isinstance(stig, str) and stig.strip():
        add(f"STIG: {stig.strip()}")

    gdpr = item.get("gdpr") or item.get("gdprArticle") or item.get("gdpr_article")
    if isinstance(gdpr, str) and gdpr.strip():
        add(f"GDPR: {gdpr.strip()}")

    for key_name in ("references", "links", "advisory_urls", "remediations"):
        entry = item.get(key_name)
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = it.get("href") or it.get("url") or it.get("link") or it.get("help_text")
                    if href:
                        add(href)
                elif isinstance(it, str):
                    add(it)
        elif isinstance(entry, str) and entry.strip():
            add(entry.strip())

    return refs


def finding_label(item):
    """Build the leading title fragment for a DataSafe finding."""
    if not isinstance(item, dict):
        return ""
    for key in ("title", "name", "shortName", "ruleKey", "key"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("category", "findingCategory", "finding_category"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("summary", "description"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            chunk = v.strip()
            return chunk if len(chunk) < 80 else chunk[:77] + "..."
    return "DataSafe finding"


def build_vulnerability(item):
    """Build a Faraday vulnerability dict from a DataSafe finding record."""
    if not isinstance(item, dict):
        return None

    severity_numeric = None
    for key in ("cvss", "cvssScore", "cvss_score", "riskScore", "risk_score", "score"):
        raw_numeric = item.get(key)
        if isinstance(raw_numeric, (int, float)) and not isinstance(raw_numeric, bool):
            severity_numeric = float(raw_numeric)
            break
        if isinstance(raw_numeric, str) and raw_numeric.strip():
            try:
                severity_numeric = float(raw_numeric.strip())
                break
            except ValueError:
                continue

    severity_string = (
        item.get("severity")
        or item.get("severityLabel")
        or item.get("severity_label")
        or item.get("risk_level")
        or item.get("riskLevel")
    )
    severity = severity_from_datasafe(severity_string, severity_numeric)
    status = status_from_datasafe(item)

    label = finding_label(item)
    name = f"[DATABASE-SECURITY] {label}" if label else "[DATABASE-SECURITY] DataSafe finding"

    desc_parts = []
    description = item.get("description") or item.get("Description") or item.get("details") or item.get("summary")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    for label_key, key in (
        ("id", "id"),
        ("key", "key"),
        ("rule", "rule"),
        ("category", "category"),
        ("assessment_id", "assessmentId"),
        ("target_id", "targetId"),
        ("compartment_id", "compartmentId"),
        ("severity", "severity"),
        ("is_risk", "isRisk"),
        ("lifecycle_state", "lifecycleState"),
        ("type", "type"),
        ("subtype", "subtype"),
        ("subCategory", "subCategory"),
        ("schema", "schema"),
        ("schemas", "schemas"),
        ("user", "user"),
        ("privilege", "privilege"),
        ("role", "role"),
        ("time_created", "timeCreated"),
        ("time_updated", "timeUpdated"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    if severity_numeric is not None:
        desc_parts.append(f"severity_score: {severity_numeric}")

    details = item.get("detail") or item.get("detailedDescription")
    if isinstance(details, str) and details.strip():
        desc_parts.append(f"detail: {details.strip()}")

    cves = collect_cves(item)
    refs = collect_refs(item)

    resolution = ""
    remediations = (
        item.get("remediation") or item.get("remediations") or item.get("recommendation") or item.get("solution")
    )
    if isinstance(remediations, list):
        bits = []
        for r in remediations:
            if isinstance(r, dict):
                txt = r.get("help_text") or r.get("description") or r.get("name") or r.get("solution")
                if isinstance(txt, str) and txt.strip():
                    bits.append(txt.strip())
            elif isinstance(r, str) and r.strip():
                bits.append(r.strip())
        if bits:
            resolution = "\n".join(bits)
    elif isinstance(remediations, str) and remediations.strip():
        resolution = remediations.strip()
    if not resolution:
        resolution = (
            "Investigate the finding in the Oracle DataSafe console "
            "(Security Assessment -> select the target database -> "
            "Findings tab) and drive remediation through the DBA / "
            "Oracle DBSAT workflow; accept the risk by setting "
            "isRisk=false on the DataSafe finding (Risk Acceptance) "
            "if the underlying issue cannot be remediated."
        )

    external_id = str(
        item.get("id")
        or item.get("findingId")
        or item.get("finding_id")
        or item.get("key")
        or (cves[0] if cves else "")
        or ""
    )

    return {
        "name": str(name).strip()[:200] or f"DataSafe finding {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": {},
        "tags": ["oracle", "oracle-datasafe", "database-security", "oci"],
    }


def target_hostname(target, fallback):
    """Pick the canonical hostname for a DataSafe target database."""
    if isinstance(target, dict):
        # Some target shapes (AUTONOMOUS_DATABASE) carry the hostname
        # under .databaseDetails.serviceName / .infrastructureType
        # while INSTALLED_DATABASE shapes carry .databaseDetails.host.
        details = target.get("databaseDetails")
        if isinstance(details, dict):
            for key in ("serviceName", "host", "hostName", "instanceName", "connectionString"):
                v = details.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()
        for key in ("displayName", "name", "hostName", "host"):
            v = target.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(fallback, str) and fallback.strip():
        return fallback.strip()
    return ""


def target_ip(target):
    """Pick an IP address for the DataSafe target (if surfaced)."""
    if not isinstance(target, dict):
        return "0.0.0.0"
    for key in ("ip", "ipAddress", "ip_address"):
        v = target.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    details = target.get("databaseDetails")
    if isinstance(details, dict):
        for key in ("ip", "ipAddress", "ip_address", "listenerIp"):
            v = details.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return "0.0.0.0"


def target_os(target):
    """Build the host.os string from a DataSafe target database record.

    DataSafe is target-scoped so host.os carries the Oracle database
    product + (optional) version + lifecycle label (e.g. ``Oracle
    Database 19c Enterprise (DataSafe target=ACTIVE)``) rather than
    the underlying OS.  Falls back to the literal ``Oracle Database
    (DataSafe target)`` if no version metadata is present.
    """
    if not isinstance(target, dict):
        return "Oracle Database (DataSafe target)"
    details = target.get("databaseDetails") if isinstance(target.get("databaseDetails"), dict) else {}
    parts = ["Oracle Database"]
    db_type = (
        details.get("databaseType")
        or details.get("database_type")
        or target.get("databaseType")
        or target.get("database_type")
    )
    if isinstance(db_type, str) and db_type.strip():
        parts.append(db_type.strip())
    version = (
        details.get("dbVersion") or details.get("db_version") or target.get("dbVersion") or target.get("db_version")
    )
    if isinstance(version, (str, int, float)) and str(version).strip():
        parts.append(str(version).strip())
    lifecycle = target.get("lifecycleState") or target.get("lifecycle_state")
    label = " ".join(parts)
    if isinstance(lifecycle, str) and lifecycle.strip():
        label = f"{label} (DataSafe target={lifecycle.strip()})"
    else:
        label = f"{label} (DataSafe target)"
    return label


def build_host(target_id, target, vulns):
    """Build a Faraday host record for a DataSafe target database."""
    if not isinstance(target, dict):
        target = {}
    hostname = target_hostname(target, target_id)
    os_str = target_os(target)
    ip = target_ip(target)

    desc_parts = [f"target_id={target_id}"]
    for label_key, key in (
        ("display_name", "displayName"),
        ("description", "description"),
        ("lifecycle_state", "lifecycleState"),
        ("compartment_id", "compartmentId"),
        ("type", "databaseType"),
        ("infrastructure_type", "infrastructureType"),
        ("region", "region"),
        ("time_created", "timeCreated"),
        ("time_updated", "timeUpdated"),
    ):
        v = target.get(key)
        if v not in (None, ""):
            desc_parts.append(f"{label_key}={v}")

    details = target.get("databaseDetails")
    if isinstance(details, dict):
        for label_key, key in (
            ("database_type", "databaseType"),
            ("db_version", "dbVersion"),
            ("infrastructure_type", "infrastructureType"),
            ("service_name", "serviceName"),
            ("instance_name", "instanceName"),
            ("host", "host"),
            ("port", "port"),
            ("listener_port", "listenerPort"),
        ):
            v = details.get(key)
            if v not in (None, ""):
                desc_parts.append(f"db.{label_key}={v}")

    if vulns:
        desc_parts.append(f"findings={len(vulns)}")

    return {
        "ip": ip,
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_target_databases(
    requests_module,
    host,
    compartment_id,
    target_id,
    private_key,
    key_id,
    max_pages=MAX_PAGES,
    page_size=PAGE_SIZE,
):
    """Walk /20181201/targetDatabases for ``compartmentId``.

    Optionally narrowed by ``targetDatabaseId`` so a single target can
    be scanned without walking the whole tenancy.
    """
    out = []
    base_url = build_target_databases_url(host)
    page = None
    pages_walked = 0
    while pages_walked < max_pages:
        params = {
            "compartmentId": compartment_id,
            "compartmentIdInSubtree": "true",
            "limit": int(page_size),
        }
        if target_id:
            params["targetDatabaseId"] = target_id
        if page:
            params["page"] = page

        # The signing string includes only the path (no query string)
        # per the OCI Signature v1 spec, so we build the headers using
        # the bare URL and let requests append the query.  But OCI
        # *does* allow signing the path + query — to stay portable
        # against future spec changes we sign the bare path.
        headers = signed_headers("GET", base_url, private_key, key_id)
        try:
            resp = requests_module.get(base_url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {base_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("OCI DataSafe request rejected (401). Check OCI signing key / OCID.")
            sys.exit(1)
        if resp.status_code == 403:
            log("OCI DataSafe request rejected (403). Check the user's IAM policy on DataSafe.")
            return out
        if resp.status_code == 404:
            log(f"OCI DataSafe targetDatabases endpoint 404 for {base_url}")
            return out
        if resp.status_code >= 400:
            log(
                f"OCI DataSafe targetDatabases request failed ({resp.status_code}) "
                f"for {base_url}: {resp.text[:500]}"
            )
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"OCI DataSafe targetDatabases response was not JSON ({base_url})")
            return out
        results = extract_results(payload)
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        next_page = extract_next_page(getattr(resp, "headers", None))
        if not next_page:
            break
        page = next_page
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping targetDatabases pagination")
    return out


def fetch_findings(
    requests_module,
    host,
    compartment_id,
    target_id,
    private_key,
    key_id,
    max_pages=MAX_PAGES,
    page_size=PAGE_SIZE,
):
    """Walk /20181201/findings for ``compartmentId`` (+ optional targetId)."""
    out = []
    base_url = build_findings_url(host)
    page = None
    pages_walked = 0
    while pages_walked < max_pages:
        params = {
            "compartmentId": compartment_id,
            "compartmentIdInSubtree": "true",
            "limit": int(page_size),
        }
        if target_id:
            params["targetId"] = target_id
        if page:
            params["page"] = page

        headers = signed_headers("GET", base_url, private_key, key_id)
        try:
            resp = requests_module.get(base_url, headers=headers, params=params, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {base_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("OCI DataSafe request rejected (401). Check OCI signing key / OCID.")
            sys.exit(1)
        if resp.status_code == 403:
            log("OCI DataSafe request rejected (403). Check the user's IAM policy on DataSafe.")
            return out
        if resp.status_code == 404:
            log(f"OCI DataSafe findings endpoint 404 for {base_url}")
            return out
        if resp.status_code >= 400:
            log(f"OCI DataSafe findings request failed ({resp.status_code}) " f"for {base_url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"OCI DataSafe findings response was not JSON ({base_url})")
            return out
        results = extract_results(payload)
        if not results:
            break
        for entry in results:
            if isinstance(entry, dict):
                out.append(entry)
        next_page = extract_next_page(getattr(resp, "headers", None))
        if not next_page:
            break
        page = next_page
        pages_walked += 1
    if pages_walked >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping findings pagination")
    return out


def main():
    started = time.time()

    compartment_id = validate_ocid(
        env("EXECUTOR_CONFIG_OCI_COMPARTMENT_ID", required=True),
        "OCI_COMPARTMENT_ID",
        required=True,
    )
    datasafe_target_id = validate_ocid(
        env("EXECUTOR_CONFIG_DATASAFE_TARGET_ID"),
        "DATASAFE_TARGET_ID",
        required=False,
    )
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_DS_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    user_ocid = validate_ocid(env("OCI_USER_OCID", required=True), "OCI_USER_OCID", required=True)
    tenancy_ocid = validate_ocid(env("OCI_TENANCY_OCID", required=True), "OCI_TENANCY_OCID", required=True)
    fingerprint = validate_fingerprint(env("OCI_FINGERPRINT", required=True))
    private_key_path = env("OCI_PRIVATE_KEY_PATH", required=True)
    region = validate_region(env("OCI_REGION"))
    host = validate_host(env("OCI_HOST")) or derive_host(region)

    private_key = load_private_key(private_key_path)
    key_id = build_key_id(tenancy_ocid, user_ocid, fingerprint)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    targets = fetch_target_databases(requests, host, compartment_id, datasafe_target_id, private_key, key_id)
    findings = fetch_findings(requests, host, compartment_id, datasafe_target_id, private_key, key_id)

    log(
        f"Processing {len(findings)} DataSafe findings across "
        f"{len(targets)} target database(s) (min_severity={min_severity})"
    )

    # Group findings by their targetId so each finding attaches to
    # the matching host record.  Findings with no resolvable targetId
    # attach to a synthetic catch-all host so they're not silently
    # dropped.
    findings_by_target = {}
    orphaned = []
    for finding in findings:
        built = build_vulnerability(finding)
        if built is None:
            continue
        if allowed_severities and built["severity"] not in allowed_severities:
            continue
        target_key = (
            finding.get("targetId")
            or finding.get("target_id")
            or finding.get("targetDatabaseId")
            or finding.get("target_database_id")
        )
        if isinstance(target_key, str) and target_key.strip():
            findings_by_target.setdefault(target_key.strip(), []).append(built)
        else:
            orphaned.append(built)

    hosts = []
    seen_target_ids = set()
    for target in targets:
        if not isinstance(target, dict):
            continue
        tid = target.get("id") or target.get("targetDatabaseId") or target.get("target_database_id")
        tid_str = str(tid).strip() if tid is not None else ""
        if not tid_str:
            continue
        seen_target_ids.add(tid_str)
        target_vulns = findings_by_target.pop(tid_str, [])
        hosts.append(build_host(tid_str, target, target_vulns))

    # Any findings whose targetId did not match a target in the
    # catalogue (e.g. the catalogue was narrowed but the findings
    # pull wasn't) still attach to a synthetic host keyed on the
    # finding's targetId.
    for tid, vulns in findings_by_target.items():
        hosts.append(build_host(tid, {}, vulns))
        seen_target_ids.add(tid)

    # Findings without any resolvable targetId attach to a synthetic
    # catch-all host so they don't get silently dropped.
    if orphaned:
        hosts.append(
            {
                "ip": "0.0.0.0",
                "os": "Oracle Database (DataSafe target=unknown)",
                "hostnames": [],
                "mac": "",
                "description": (
                    f"compartment_id={compartment_id} | "
                    f"datasafe_target_id={datasafe_target_id or ''} | "
                    f"orphaned_findings={len(orphaned)}"
                ),
                "vulnerabilities": orphaned,
            }
        )

    # Always emit a synthetic placeholder if nothing came back so the
    # Faraday workspace records the DataSafe query was processed.
    if not hosts:
        hosts.append(
            {
                "ip": "0.0.0.0",
                "os": "Oracle Database (DataSafe target=empty)",
                "hostnames": [],
                "mac": "",
                "description": (
                    f"compartment_id={compartment_id} | "
                    f"datasafe_target_id={datasafe_target_id or ''} | "
                    "no DataSafe targets or findings returned"
                ),
                "vulnerabilities": [],
            }
        )

    params_bits = [f"compartment_id={compartment_id}"]
    if datasafe_target_id:
        params_bits.append(f"datasafe_target_id={datasafe_target_id}")
    params_bits.append(f"min_severity={min_severity}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "oracle_datasafe",
            "command": "oracle_datasafe",
            "params": ",".join(params_bits),
            "user": os.environ.get("USER", ""),
            "hostname": socket.gethostname(),
            "start_date": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
            "duration": int((time.time() - started) * 1000),
            "import_source": "report",
        },
    }
    print(json.dumps(output))


if __name__ == "__main__":
    main()
