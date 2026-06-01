#!/usr/bin/env python
"""BlackBerry Cylance (CylancePROTECT) REST importer.

Pulls managed devices, threats and policies from a BlackBerry Cylance
(CylancePROTECT, formerly Cylance Inc.) tenant.  Emits Faraday
bulk-create JSON to stdout.  Each Cylance device becomes one Faraday
host (``ip`` = the first non-loopback entry in ``ip_addresses``,
falling back to synthetic ``0.0.0.0``); per-device threats attach as
Faraday vulnerabilities — one per Cylance threat ``sha256`` with
engine prefix ``[EDR]``.

Endpoints used:
  POST {CYLANCE_HOST}/auth/v2/token
      -> JWT exchange.  POST body carries ``{"auth_token": "<signed jwt>"}``
      where the JWT is built locally (HS256, App Secret as the signing
      key) carrying the App Id (``sub``), Tenant Id (``tid``), random
      ``jti`` and a comma-separated ``sco`` scope string.  Response
      shape is ``{"access_token": "<bearer jwt>"}`` carried on every
      subsequent ``/devices`` / ``/threats`` / ``/policies`` request as
      ``Authorization: Bearer <token>``.
  GET {CYLANCE_HOST}/devices/v2/?page=N&page_size=M
      -> paginated device inventory.  Response shape is
      ``{"page_number": N, "page_size": M, "total_pages": X,
      "total_number_of_items": Y, "page_items": [...]}``.  Each entry
      carries id / name / host_name / os_versions / state / agent_version /
      ip_addresses / mac_addresses / policy{id,name} /
      date_first_registered / date_last_modified / date_offline.
  GET {CYLANCE_HOST}/devices/v2/{device_id}/threats?page=N
      -> paginated per-device threats.  Same envelope as the list
      endpoint but each entry adds device-specific fields
      (file_status / date_found / file_path).  Used to fan threats out
      across the devices that actually have them so each Faraday host
      surfaces the threats Cylance pinned to that endpoint.
  GET {CYLANCE_HOST}/threats/v2/?page=N&page_size=M
      -> paginated threat catalogue.  Response envelope mirrors the
      devices endpoint; each entry carries
      sha256 / md5 / name / cylance_score / classification /
      sub_classification / file_size / signed / cert_publisher /
      av_industry / last_found / first_found / global_quarantined.
      The catalogue is fetched up-front so the per-device threat walks
      can be enriched with the global catalogue metadata (classification,
      score, etc.) without re-walking the catalogue per device.
  GET {CYLANCE_HOST}/policies/v2/?page=N
      -> paginated device policy catalogue.  Each entry carries
      policy_id / name / device_count.  Used to enrich the host record
      with the policy_name when the device record's policy block only
      carries the id.

Auth: BlackBerry Cylance uses a per-tenant JWT auth flow.  The
operator creates a Custom Application in the Cylance console (Settings
-> Integrations -> Custom Application -> Create) with the requested
scopes (``device:read``, ``device:list``, ``threat:read``,
``threat:list``, ``policy:read``, ``policy:list``) and receives an App
Id + App Secret pair.  The dispatcher signs an HS256 JWT locally with
the App Secret carrying the App Id (``sub``) + Tenant Id (``tid``) +
random ``jti``, POSTs it to ``/auth/v2/token`` and stores the returned
bearer token for the rest of the run.  Credentials are exposed as
``CYLANCE_APP_ID`` + ``CYLANCE_APP_SECRET``; ``CYLANCE_TENANT_ID`` is
the tenant identifier shown in the console under the Custom Application
list; ``CYLANCE_REGION`` selects the regional API endpoint (na | euc1 |
au | sae1 | jp — Cylance has region-pinned endpoints, one per cloud).
"""

import base64
import hashlib
import hmac
import json
import os
import re
import socket
import sys
import time
import uuid
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

TIMEOUT = 60
MAX_PAGES = 200
PAGE_SIZE = 200  # Cylance caps page_size at 200 on the v2 surfaces.
TOKEN_TTL = 1800  # JWT expiry in seconds (30 minutes — Cylance maxes at 30m).

# Cylance regional API endpoints.  Each region is pinned to its own
# cloud — north america (na), western europe (euc1), asia-pacific (au),
# south-asia / middle-east (sae1), japan (jp).
CYLANCE_REGION_HOSTS = {
    "na": "https://protectapi.cylance.com",
    "us": "https://protectapi.cylance.com",  # alias
    "euc1": "https://protectapi-euc1.cylance.com",
    "eu": "https://protectapi-euc1.cylance.com",  # alias
    "au": "https://protectapi-au.cylance.com",
    "apac": "https://protectapi-au.cylance.com",  # alias
    "sae1": "https://protectapi-sae1.cylance.com",
    "sa": "https://protectapi-sae1.cylance.com",  # alias
    "jp": "https://protectapi-jp.cylance.com",
    "jpn": "https://protectapi-jp.cylance.com",  # alias
}

VALID_REGIONS = ("na", "euc1", "au", "sae1", "jp")

# Cylance scopes the bearer token can request.  The minimal posture for
# this importer is device + threat + policy read + list.
DEFAULT_SCOPES = (
    "device:list",
    "device:read",
    "threat:list",
    "threat:read",
    "policy:list",
    "policy:read",
)

# Cylance classifications (the threat-catalogue ``classification`` field
# plus the per-device ``cylance_score`` derived bucketing).  PUP =
# Potentially Unwanted Program (low risk); Malware = high / critical;
# Trusted = info; Abnormal / Suspicious = medium.
CYLANCE_CLASSIFICATION_SEVERITY = {
    "malware": "high",
    "malicious": "high",
    "ransomware": "critical",
    "trojan": "high",
    "worm": "high",
    "virus": "high",
    "rootkit": "critical",
    "backdoor": "critical",
    "exploit": "high",
    "dropper": "high",
    "downloader": "high",
    "spyware": "high",
    "infostealer": "high",
    "keylogger": "high",
    "fileinfector": "high",
    "pup": "low",
    "potentiallyunwanted": "low",
    "potentially_unwanted": "low",
    "adware": "low",
    "gameplay": "low",
    "porntool": "low",
    "hacktool": "medium",
    "tool": "medium",
    "crackingtool": "medium",
    "abnormal": "medium",
    "suspicious": "medium",
    "dual_use": "medium",
    "dualuse": "medium",
    "trusted": "info",
    "trust": "info",
    "safe": "info",
    "clean": "info",
    "unknown": "info",
    "none": "info",
    "unspecified": "info",
}

CYLANCE_STRING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "unspecified": "info",
    "trivial": "info",
    "negligible": "info",
    "unknown": "info",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Cylance file_status -> Faraday status.  Cylance surfaces the
# per-device threat lifecycle through the ``file_status`` enum
# (Default / Allowed / Quarantined / Waived / Blocked / Whitelisted /
# Listed).  Waived / Allowed / Whitelisted (operator decided the threat
# was acceptable on this endpoint) collapse onto risk-accepted;
# Quarantined / Blocked collapse onto closed; Default / Listed
# (active threat awaiting disposition) collapses onto open.
CYLANCE_STATUS_BY_FILE_STATUS = {
    "default": "open",
    "listed": "open",
    "active": "open",
    "new": "open",
    "open": "open",
    "running": "open",
    "quarantined": "closed",
    "quarantine": "closed",
    "blocked": "closed",
    "blockedfromdevice": "closed",
    "remediated": "closed",
    "removed": "closed",
    "deleted": "closed",
    "resolved": "closed",
    "closed": "closed",
    "waived": "risk-accepted",
    "allowed": "risk-accepted",
    "whitelisted": "risk-accepted",
    "approved": "risk-accepted",
    "excluded": "risk-accepted",
    "ignored": "risk-accepted",
    "muted": "risk-accepted",
    "suppressed": "risk-accepted",
    "trusted": "risk-accepted",
    "safe": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - Cylance: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def severity_from_cvss(score):
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


def severity_from_cylance_score(value):
    """Map a Cylance ``cylance_score`` (-1.0 .. 1.0) to a Faraday bucket.

    Cylance scores are a regression output where 1.0 = very malicious
    and -1.0 = trustworthy.  The Cylance console buckets >= 0.6 as
    Unsafe (red), [0, 0.6) as Abnormal (yellow) and < 0 as Safe (green).
    We expand that onto the Faraday 5-bucket scale so analysts get a
    finer-grained read.
    """
    if isinstance(value, bool):
        return "info"
    try:
        score = float(value)
    except (TypeError, ValueError):
        return "info"
    if score >= 0.8:
        return "critical"
    if score >= 0.4:
        return "high"
    if score >= 0.0:
        return "medium"
    if score >= -0.5:
        return "low"
    return "info"


def severity_from_classification(classification):
    """Map a Cylance classification string to a Faraday bucket."""
    if not isinstance(classification, str) or not classification.strip():
        return None
    key = re.sub(r"[^a-z0-9_]", "", classification.strip().lower())
    if key in CYLANCE_CLASSIFICATION_SEVERITY:
        return CYLANCE_CLASSIFICATION_SEVERITY[key]
    squashed = key.replace("_", "")
    if squashed in CYLANCE_CLASSIFICATION_SEVERITY:
        return CYLANCE_CLASSIFICATION_SEVERITY[squashed]
    return None


def severity_from_cylance(item, cvss=None):
    """Map a Cylance threat / device payload to a Faraday severity bucket.

    Walks ``cylance_score`` first (the canonical numeric signal), then
    the ``classification`` / ``sub_classification`` enum, then the
    string ``severity`` field (rare but appears on re-emitted shapes),
    and finally falls back to CVSS bucketing if a CVSS score is
    available.
    """
    if not isinstance(item, dict):
        if isinstance(item, str):
            classification = severity_from_classification(item)
            if classification is not None:
                return classification
            text = item.strip().lower()
            if text in CYLANCE_STRING_SEVERITY:
                return CYLANCE_STRING_SEVERITY[text]
        if cvss is not None:
            return severity_from_cvss(cvss)
        return "info"

    score = item.get("cylance_score")
    if score is None:
        score = item.get("cylanceScore")
    if score is not None and not isinstance(score, bool):
        try:
            return severity_from_cylance_score(float(score))
        except (TypeError, ValueError):
            pass

    for key in ("classification", "Classification", "sub_classification", "subClassification"):
        bucket = severity_from_classification(item.get(key))
        if bucket is not None:
            return bucket

    for key in ("severity", "Severity"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if text in CYLANCE_STRING_SEVERITY:
                return CYLANCE_STRING_SEVERITY[text]
            bucket = severity_from_classification(raw)
            if bucket is not None:
                return bucket

    if cvss is not None:
        return severity_from_cvss(cvss)
    return "info"


def status_from_cylance(item):
    """Derive Faraday status from a Cylance threat / device payload.

    Walks ``file_status`` first (the canonical per-device threat
    lifecycle), then ``status`` / ``state`` fallbacks for re-emitted
    shapes; ``quarantined`` / ``blocked`` / ``waived`` boolean flags
    are honoured as a final fallback because some Cylance shapes only
    surface the disposition via the boolean.
    """
    if not isinstance(item, dict):
        return "open"
    for key in (
        "file_status",
        "fileStatus",
        "FileStatus",
        "status",
        "Status",
        "state",
        "State",
        "threat_status",
        "threatStatus",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in CYLANCE_STATUS_BY_FILE_STATUS:
                return CYLANCE_STATUS_BY_FILE_STATUS[compact]
            if squashed in CYLANCE_STATUS_BY_FILE_STATUS:
                return CYLANCE_STATUS_BY_FILE_STATUS[squashed]
    # Boolean disposition flags as a fallback.
    if item.get("waived") is True or item.get("Waived") is True:
        return "risk-accepted"
    if item.get("global_quarantined") is True or item.get("globalQuarantined") is True:
        return "closed"
    if item.get("quarantined") is True or item.get("Quarantined") is True:
        return "closed"
    if item.get("safelisted") is True or item.get("whitelisted") is True:
        return "risk-accepted"
    return "open"


def validate_min_severity(value):
    """Validate CYLANCE_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus Cylance-side synonyms.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if not text:
        return "info"
    bucket = CYLANCE_STRING_SEVERITY.get(text)
    if bucket is None:
        # Maybe a numeric cylance_score floor?
        try:
            bucket = severity_from_cylance_score(float(text))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"CYLANCE_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_tenant_id(value):
    """Validate CYLANCE_TENANT_ID.

    None / blank -> None (caller sys.exits with a clear message; the
    tenant id is mandatory and carried in the JWT claims).  Whitespace
    is trimmed.  Cylance tenant ids are GUIDs in the canonical
    `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` shape but we don't enforce
    the format because Cylance has historically accepted free-form
    tenant identifiers on legacy stacks.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        text = str(value).strip()
    else:
        text = value.strip()
    if not text:
        return None
    return text


def validate_region(value):
    """Validate CYLANCE_REGION.

    Accepts the canonical region codes (na | euc1 | au | sae1 | jp)
    plus operator-friendly aliases (us / eu / apac / sa / jpn) which
    are folded onto the canonical code so the auth + REST URL helpers
    look up the same regional host.  None / blank / garbage -> ``na``
    (the default cloud) with a log line.
    """
    if value is None:
        return "na"
    if not isinstance(value, str):
        text = str(value).strip()
    else:
        text = value.strip()
    if not text:
        return "na"
    keyed = text.lower()
    if keyed in CYLANCE_REGION_HOSTS:
        # Fold aliases onto canonical codes.
        if keyed in ("us",):
            return "na"
        if keyed in ("eu",):
            return "euc1"
        if keyed in ("apac",):
            return "au"
        if keyed in ("sa",):
            return "sae1"
        if keyed in ("jpn",):
            return "jp"
        return keyed
    log(f"CYLANCE_REGION '{value}' not recognised; defaulting to 'na'")
    return "na"


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


def region_to_host(region):
    """Return the Cylance API host for the canonical region code."""
    return CYLANCE_REGION_HOSTS.get(region, CYLANCE_REGION_HOSTS["na"])


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on the Cylance host."""
    if not isinstance(host, str):
        return ""
    text = host.strip().rstrip("/")
    if not text:
        return ""
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def build_token_url(host):
    base = normalize_base_url(host)
    return f"{base}/auth/v2/token"


def build_devices_url(host):
    base = normalize_base_url(host)
    return f"{base}/devices/v2/"


def build_device_threats_url(host, device_id):
    base = normalize_base_url(host)
    return f"{base}/devices/v2/{device_id}/threats"


def build_threats_url(host):
    base = normalize_base_url(host)
    return f"{base}/threats/v2/"


def build_policies_url(host):
    base = normalize_base_url(host)
    return f"{base}/policies/v2/"


def _b64url(data):
    """RFC-7515 base64url encoding (no padding, url-safe alphabet)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_jwt(app_id, app_secret, tenant_id, scopes=DEFAULT_SCOPES, ttl=TOKEN_TTL, now=None):
    """Build a Cylance auth JWT.

    Cylance uses HS256 — the JWT is signed with the App Secret as the
    HMAC key.  Claims carry the App Id (``sub``), Tenant Id (``tid``),
    issue / expiry timestamps + a random ``jti`` (Cylance rejects
    replays so a fresh jti per call is mandatory).  ``sco`` is a
    comma-separated string of the scopes the app requested.
    """
    if now is None:
        now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {
        "exp": int(now) + int(ttl),
        "iat": int(now),
        "iss": "http://cylance.com",
        "sub": str(app_id),
        "tid": str(tenant_id),
        "jti": uuid.uuid4().hex,
    }
    if scopes:
        if isinstance(scopes, str):
            claims["sco"] = scopes
        else:
            claims["sco"] = ",".join(str(s) for s in scopes)
    header_b64 = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    claims_b64 = _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    secret_bytes = app_secret.encode("utf-8") if isinstance(app_secret, str) else app_secret
    sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{claims_b64}.{_b64url(sig)}"


def decode_jwt_payload(token):
    """Decode the JWT payload segment for diagnostic logging.

    Cylance bearer tokens are also JWTs; we don't verify the signature
    here (the issuing tenant signs them and we trust the TLS channel)
    but we surface the ``exp`` claim so operators can spot a stale
    token in the logs.  Returns ``None`` on any decode error.
    """
    if not isinstance(token, str) or token.count(".") != 2:
        return None
    try:
        _header, payload_b64, _sig = token.split(".")
        # base64url decode with padding tolerance.
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def auth_headers(access_token):
    """Cylance v2 surfaces expect ``Authorization: Bearer <token>``."""
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_items(payload):
    """Pull the result list out of a Cylance v2 paginated envelope.

    Cylance uses ``{"page_number": N, "page_size": M, "total_pages": X,
    "total_number_of_items": Y, "page_items": [...]}`` consistently
    across /devices/v2/, /threats/v2/, /policies/v2/.  The alt keys
    appear on legacy / federated stacks — be defensive.
    """
    if not isinstance(payload, dict):
        return []
    for key in ("page_items", "pageItems", "items", "results", "data"):
        v = payload.get(key)
        if isinstance(v, list):
            return v
    return []


def cvss_score(item):
    """Pull a numeric CVSS score from a Cylance threat payload.

    Cylance rarely surfaces CVSS on its own (the platform's primary
    signal is ``cylance_score``), but re-emitted shapes can carry CVSS
    so we walk the standard surfaces defensively.
    """
    if not isinstance(item, dict):
        return None
    for key in ("cvssScore", "cvss_score", "baseScore", "base_score"):
        v = item.get(key)
        if v is None or isinstance(v, (dict, list, bool)):
            continue
        try:
            return float(v)
        except (TypeError, ValueError):
            continue
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3", "cvss2"):
        nested = item.get(nested_key)
        if isinstance(nested, dict):
            for inner_key in ("3.0", "3.1", "2.0"):
                inner = nested.get(inner_key)
                if isinstance(inner, dict):
                    for k in ("base", "score", "baseScore", "base_score"):
                        v = inner.get(k)
                        if v is None or isinstance(v, (dict, list, bool)):
                            continue
                        try:
                            return float(v)
                        except (TypeError, ValueError):
                            continue
            for k in ("score", "baseScore", "base_score", "base"):
                v = nested.get(k)
                if v is None or isinstance(v, (dict, list, bool)):
                    continue
                try:
                    return float(v)
                except (TypeError, ValueError):
                    continue
        elif isinstance(nested, list):
            for entry in nested:
                if not isinstance(entry, dict):
                    continue
                for k in ("baseScore", "base_score", "score", "base"):
                    v = entry.get(k)
                    if v is None or isinstance(v, (dict, list, bool)):
                        continue
                    try:
                        return float(v)
                    except (TypeError, ValueError):
                        continue
    return None


def cvss_vector(item):
    if not isinstance(item, dict):
        return ""
    for k in ("cvssVector", "cvss_vector", "vector", "vectorString", "vector_string"):
        s = item.get(k)
        if isinstance(s, str) and s.strip():
            return s.strip()
    for nested_key in ("cvss", "cvss3", "cvssV3", "cvss_v3"):
        nested = item.get(nested_key)
        if isinstance(nested, dict):
            for inner_key in ("3.0", "3.1", "2.0"):
                inner = nested.get(inner_key)
                if isinstance(inner, dict):
                    for k in ("vector", "vectorString", "vector_string"):
                        s = inner.get(k)
                        if isinstance(s, str) and s.strip():
                            return s.strip()
            for k in ("vector", "vectorString", "vector_string"):
                s = nested.get(k)
                if isinstance(s, str) and s.strip():
                    return s.strip()
    return ""


def collect_cves(item):
    """Pull CVE-* ids out of a Cylance threat / device payload.

    Cylance does not surface CVEs natively, but the ``av_industry``
    enrichment field plus ``name`` / ``classification`` / ``cert_publisher``
    occasionally carry CVE strings on hand-curated entries.  Walk
    everything defensively.
    """
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
        if isinstance(v, str) and v.strip():
            add(v)
        elif isinstance(v, dict):
            add(v.get("id") or v.get("name") or v.get("value"))
    for key in ("cves", "cveIds", "cve_ids", "aliases"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(
                        entry.get("id")
                        or entry.get("name")
                        or entry.get("cve")
                        or entry.get("cveId")
                        or entry.get("value")
                    )

    for key in (
        "name",
        "Name",
        "description",
        "Description",
        "classification",
        "sub_classification",
        "subClassification",
        "av_industry",
        "avIndustry",
        "cert_publisher",
        "certPublisher",
        "file_path",
        "filePath",
        "detected_by",
        "detectedBy",
        "title",
        "reason",
    ):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, str):
            scan(v)
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    scan(entry)
                elif isinstance(entry, dict):
                    for sub_key in ("name", "value", "id"):
                        s = entry.get(sub_key)
                        if isinstance(s, str):
                            scan(s)
    return found


def collect_refs(item):
    """Walk a Cylance threat for advisory URLs / pivots.

    Surfaces Cylance-side pivots (``Cylance-Threat: {sha256}``,
    ``Cylance-MD5: {md5}``, ``Cylance-Classification: {class}``,
    ``Cylance-SubClassification: {sub_class}``,
    ``Cylance-Policy: {policy}``, ``Cylance-CertPublisher: {publisher}``)
    plus any inline URLs from the threat's ``references`` block.
    """
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

    sha = item.get("sha256") or item.get("Sha256") or item.get("SHA256")
    if isinstance(sha, str) and sha.strip():
        add(f"Cylance-Threat: {sha.strip()}")

    md5 = item.get("md5") or item.get("MD5") or item.get("Md5")
    if isinstance(md5, str) and md5.strip():
        add(f"Cylance-MD5: {md5.strip()}")

    classification = item.get("classification") or item.get("Classification")
    if isinstance(classification, str) and classification.strip():
        add(f"Cylance-Classification: {classification.strip()}")

    sub_classification = item.get("sub_classification") or item.get("subClassification")
    if isinstance(sub_classification, str) and sub_classification.strip():
        add(f"Cylance-SubClassification: {sub_classification.strip()}")

    file_status = item.get("file_status") or item.get("fileStatus")
    if isinstance(file_status, str) and file_status.strip():
        add(f"Cylance-FileStatus: {file_status.strip()}")

    policy = item.get("policy")
    if isinstance(policy, dict):
        name = policy.get("name") or policy.get("Name")
        if isinstance(name, str) and name.strip():
            add(f"Cylance-Policy: {name.strip()}")
        pid = policy.get("id") or policy.get("policy_id") or policy.get("Id")
        if isinstance(pid, str) and pid.strip():
            add(f"Cylance-PolicyId: {pid.strip()}")
    elif isinstance(policy, str) and policy.strip():
        add(f"Cylance-Policy: {policy.strip()}")

    cert_publisher = item.get("cert_publisher") or item.get("certPublisher")
    if isinstance(cert_publisher, str) and cert_publisher.strip():
        add(f"Cylance-CertPublisher: {cert_publisher.strip()}")

    av_industry = item.get("av_industry") or item.get("avIndustry")
    if isinstance(av_industry, str) and av_industry.strip():
        add(f"Cylance-AVIndustry: {av_industry.strip()}")

    device_id = item.get("device_id") or item.get("deviceId")
    if isinstance(device_id, str) and device_id.strip():
        add(f"Cylance-Device: {device_id.strip()}")

    detected_by = item.get("detected_by") or item.get("detectedBy")
    if isinstance(detected_by, str) and detected_by.strip():
        add(f"Cylance-DetectedBy: {detected_by.strip()}")

    for key in ("references", "links", "References", "Links"):
        entry = item.get(key) if isinstance(item, dict) else None
        if isinstance(entry, list):
            for it in entry:
                if isinstance(it, dict):
                    href = it.get("href") or it.get("url") or it.get("name") or it.get("value")
                    if href:
                        add(href)
                elif it:
                    add(str(it))
        elif isinstance(entry, str) and entry.strip():
            add(entry.strip())

    return refs


def device_label(device):
    """Build a friendly label for a Cylance device record."""
    if not isinstance(device, dict):
        return ""
    for key in ("name", "Name", "host_name", "hostName", "hostname", "fqdn"):
        v = device.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("id", "Id", "device_id", "deviceId"):
        v = device.get(key)
        if v is not None:
            s = str(v).strip()
            if s:
                return s
    return ""


def threat_label(item):
    """Build the leading title fragment for a Cylance threat finding."""
    if not isinstance(item, dict):
        return ""
    name = item.get("name") or item.get("Name") or item.get("file_name") or item.get("fileName")
    if isinstance(name, str) and name.strip():
        return name.strip()
    classification = item.get("classification") or item.get("Classification")
    sub_classification = item.get("sub_classification") or item.get("subClassification")
    if isinstance(classification, str) and classification.strip():
        if isinstance(sub_classification, str) and sub_classification.strip():
            return f"{classification.strip()} / {sub_classification.strip()}"
        return classification.strip()
    sha = item.get("sha256")
    if isinstance(sha, str) and sha.strip():
        return f"Threat {sha.strip()[:12]}"
    return "Cylance threat"


def host_bucket_key(item):
    """Pick a stable bucket key for a Cylance device or threat record."""
    if not isinstance(item, dict):
        return "__unknown__"
    for key in ("id", "Id", "device_id", "deviceId"):
        v = item.get(key)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    for key in ("host_name", "hostName", "name", "hostname"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "__unknown__"


def host_ip(item):
    """Pick the host IP from a Cylance device record.

    Cylance surfaces ``ip_addresses`` as a list of strings; the first
    non-loopback entry is preferred.  Falls back to ``ipAddress`` /
    ``ip`` scalars on legacy shapes, then synthetic ``0.0.0.0``.
    """
    if not isinstance(item, dict):
        return "0.0.0.0"
    for key in ("ip_addresses", "ipAddresses"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip() and entry.strip() not in ("0.0.0.0", "127.0.0.1"):
                    return entry.strip()
    for key in ("ip_address", "ipAddress", "ip"):
        v = item.get(key)
        if isinstance(v, str) and v.strip() and v.strip() not in ("0.0.0.0", "127.0.0.1"):
            return v.strip()
    return "0.0.0.0"


def host_mac(item):
    if not isinstance(item, dict):
        return ""
    for key in ("mac_addresses", "macAddresses"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip():
                    return entry.strip()
    for key in ("mac_address", "macAddress", "mac"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def host_os(item):
    if not isinstance(item, dict):
        return ""
    for key in ("os_versions", "osVersions"):
        v = item.get(key)
        if isinstance(v, list):
            bits = [str(x).strip() for x in v if str(x).strip()]
            if bits:
                return " ".join(bits[:2])
    os_name = item.get("os") or item.get("operating_system") or item.get("os_version") or item.get("osVersion") or ""
    return str(os_name).strip()


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


def build_vulnerability(item, threat_catalogue=None, policy_lookup=None):
    """Build a Faraday vulnerability dict from a Cylance threat record.

    ``threat_catalogue`` is an optional ``{sha256: catalogue_entry}`` map
    used to enrich a per-device threat record with the global threat
    catalogue's classification / score / cert_publisher / av_industry
    fields when the per-device shape only carries the minimal envelope.
    ``policy_lookup`` is an optional ``{policy_id: policy_record}`` map
    used to look up the device's policy name when only the id is
    surfaced.
    """
    if not isinstance(item, dict):
        return None

    enriched = dict(item)
    sha = enriched.get("sha256") or enriched.get("Sha256") or enriched.get("SHA256")
    if isinstance(threat_catalogue, dict) and isinstance(sha, str) and sha.strip():
        cat_entry = threat_catalogue.get(sha.strip())
        if isinstance(cat_entry, dict):
            for key, value in cat_entry.items():
                if enriched.get(key) in (None, "") and value not in (None, ""):
                    enriched[key] = value

    score = cvss_score(enriched)
    severity = severity_from_cylance(enriched, cvss=score)
    status = status_from_cylance(enriched)

    label = threat_label(enriched)
    name = f"[EDR] {label}" if label else "[EDR] Cylance threat"

    desc_parts = []
    description = enriched.get("description") or enriched.get("Description")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())

    for label_key, key in (
        ("threat_name", "name"),
        ("sha256", "sha256"),
        ("md5", "md5"),
        ("classification", "classification"),
        ("sub_classification", "sub_classification"),
        ("cylance_score", "cylance_score"),
        ("file_size", "file_size"),
        ("file_status", "file_status"),
        ("file_path", "file_path"),
        ("signed", "signed"),
        ("cert_publisher", "cert_publisher"),
        ("cert_issuer", "cert_issuer"),
        ("cert_thumbprint", "cert_thumbprint"),
        ("cert_timestamp", "cert_timestamp"),
        ("av_industry", "av_industry"),
        ("running", "running"),
        ("auto_run", "auto_run"),
        ("date_found", "date_found"),
        ("first_found", "first_found"),
        ("last_found", "last_found"),
        ("date_modified", "date_modified"),
        ("global_quarantined", "global_quarantined"),
        ("safelisted", "safelisted"),
        ("waived", "waived"),
        ("unique_to_cylance", "unique_to_cylance"),
        ("detected_by", "detected_by"),
        ("device_id", "device_id"),
        ("device_name", "device_name"),
    ):
        v = enriched.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    if score is not None:
        desc_parts.append(f"score: {score}")
    vector = cvss_vector(enriched)
    if vector:
        desc_parts.append(f"vector: {vector}")

    # Surface the resolved device policy name when only the id was
    # carried on the per-device threat envelope.
    if isinstance(policy_lookup, dict):
        policy_block = enriched.get("policy")
        pid = None
        if isinstance(policy_block, dict):
            pid = policy_block.get("id") or policy_block.get("policy_id")
        elif isinstance(enriched.get("policy_id"), str):
            pid = enriched.get("policy_id")
        if isinstance(pid, str) and pid.strip():
            policy = policy_lookup.get(str(pid).strip())
            if isinstance(policy, dict):
                pname = policy.get("name") or policy.get("policy_name")
                if isinstance(pname, str) and pname.strip():
                    desc_parts.append(f"policy_name: {pname.strip()}")

    cves = collect_cves(enriched)
    refs = collect_refs(enriched)

    resolution = ""
    rem = enriched.get("remediation") or enriched.get("Remediation") or enriched.get("remediationDescription")
    if isinstance(rem, list):
        bits = [str(r).strip() for r in rem if str(r).strip()]
        if bits:
            resolution = "\n".join(bits)
    elif isinstance(rem, str) and rem.strip():
        resolution = rem.strip()
    if not resolution:
        file_status = enriched.get("file_status") or enriched.get("fileStatus")
        if isinstance(file_status, str) and file_status.strip():
            resolution = (
                f"Cylance file_status: {file_status.strip()}. "
                "Confirm the disposition in the Cylance console "
                "(Protection -> Threats -> select threat) and tune the "
                "policy / safelist if the action was incorrect."
            )
    if not resolution:
        resolution = (
            "Investigate the threat in the BlackBerry Cylance console "
            "(Protection -> Threats -> select sha256) and decide a "
            "disposition (true positive -> quarantine / global quarantine; "
            "false positive -> waive / safelist)."
        )

    external_id = str(enriched.get("sha256") or enriched.get("md5") or enriched.get("id") or (cves[0] if cves else ""))

    cvss3 = {}
    if score is not None:
        cvss3["base_score"] = score
    if vector:
        cvss3["vector_string"] = vector

    return {
        "name": str(name).strip()[:200] or f"Cylance threat {external_id}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": cves,
        "cvss3": cvss3,
        "tags": ["cylance", "edr", "endpoint-edr"],
    }


def build_host(bucket_key, sample_device, vulns, policy_lookup=None):
    """Build a Faraday host record for the supplied device bucket."""
    sample = sample_device if isinstance(sample_device, dict) else {}
    label = device_label(sample) if sample else ""
    hostname = ""
    if label:
        hostname = label
    elif bucket_key and bucket_key != "__unknown__":
        hostname = bucket_key

    ip = host_ip(sample) if sample else "0.0.0.0"
    mac = host_mac(sample) if sample else ""
    os_str = host_os(sample) if sample else ""

    desc_parts = []
    if bucket_key and bucket_key != "__unknown__":
        desc_parts.append(f"device_id={bucket_key}")

    if isinstance(sample, dict):
        for label_key, key in (
            ("name", "name"),
            ("host_name", "host_name"),
            ("state", "state"),
            ("agent_version", "agent_version"),
            ("date_first_registered", "date_first_registered"),
            ("date_last_modified", "date_last_modified"),
            ("date_offline", "date_offline"),
            ("policy_id", "policy_id"),
            ("is_safe", "is_safe"),
            ("update_type", "update_type"),
            ("update_available", "update_available"),
            ("background_detection", "background_detection"),
            ("days_to_deletion", "days_to_deletion"),
        ):
            v = sample.get(key)
            if v not in (None, ""):
                desc_parts.append(f"{label_key}={v}")
        policy_block = sample.get("policy")
        if isinstance(policy_block, dict):
            pname = policy_block.get("name")
            pid = policy_block.get("id") or policy_block.get("policy_id")
            if pname:
                desc_parts.append(f"policy_name={pname}")
            if pid:
                desc_parts.append(f"policy_id={pid}")
                if isinstance(policy_lookup, dict) and not pname:
                    policy = policy_lookup.get(str(pid))
                    if isinstance(policy, dict):
                        resolved = policy.get("name") or policy.get("policy_name")
                        if resolved:
                            desc_parts.append(f"policy_name={resolved}")

    if vulns:
        desc_parts.append(f"findings={len(vulns)}")

    return {
        "ip": ip,
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_pages(
    requests_module, url, headers, max_pages=MAX_PAGES, page_size=PAGE_SIZE, extra_params=None, verify=True
):
    """Walk a Cylance v2 ``page_items`` envelope.

    ``extra_params`` is an optional dict of query parameters merged
    into each request (e.g. for /threats/v2/?detected_after=... filters).
    """
    out = []
    page = 1
    pages = 0
    while pages < max_pages:
        params = {"page": page, "page_size": page_size}
        if extra_params:
            for k, v in extra_params.items():
                params[k] = v
        try:
            resp = requests_module.get(
                url,
                headers=headers,
                params=params,
                timeout=TIMEOUT,
                verify=verify,
            )
        except Exception as exc:  # noqa: BLE001
            log(f"GET {url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Cylance request rejected (401). Check CYLANCE_APP_ID / CYLANCE_APP_SECRET / CYLANCE_TENANT_ID.")
            sys.exit(1)
        if resp.status_code == 403:
            log("Cylance request rejected (403). Check that the App scope grants the requested resource.")
            return out
        if resp.status_code == 404:
            log(f"Cylance request 404 for {url} — endpoint not found")
            return out
        if resp.status_code >= 400:
            log(f"Cylance request failed ({resp.status_code}) for {url}: {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Cylance response was not JSON ({url})")
            return out
        items = extract_items(payload)
        if not items:
            break
        for entry in items:
            if isinstance(entry, dict):
                out.append(entry)
        if len(items) < page_size:
            break
        total_pages = payload.get("total_pages") if isinstance(payload, dict) else None
        if isinstance(total_pages, int) and page >= total_pages:
            break
        page += 1
        pages += 1
    if pages >= max_pages:
        log(f"hit MAX_PAGES={max_pages}; stopping pagination on {url}")
    return out


def request_access_token(requests_module, host, app_id, app_secret, tenant_id, verify=True):
    """Exchange a locally-signed JWT for a Cylance access token."""
    token_url = build_token_url(host)
    auth_jwt = build_jwt(app_id, app_secret, tenant_id)
    try:
        resp = requests_module.post(
            token_url,
            json={"auth_token": auth_jwt},
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=TIMEOUT,
            verify=verify,
        )
    except Exception as exc:  # noqa: BLE001
        log(f"Auth POST {token_url} failed: {exc}")
        sys.exit(1)
    if resp.status_code >= 400:
        log(f"Cylance auth failed ({resp.status_code}): {resp.text[:500]}")
        sys.exit(1)
    try:
        body = resp.json()
    except ValueError:
        log("Cylance auth response was not JSON")
        sys.exit(1)
    token = body.get("access_token") if isinstance(body, dict) else None
    if not isinstance(token, str) or not token.strip():
        log("Cylance auth response did not carry an access_token")
        sys.exit(1)
    return token.strip()


def main():
    started = time.time()

    tenant_id = validate_tenant_id(env("EXECUTOR_CONFIG_CYLANCE_TENANT_ID"))
    if not tenant_id:
        log("CYLANCE_TENANT_ID is required")
        sys.exit(1)
    region = validate_region(env("EXECUTOR_CONFIG_CYLANCE_REGION"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_CYLANCE_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    app_id = env("CYLANCE_APP_ID", required=True)
    app_secret = env("CYLANCE_APP_SECRET", required=True)
    verify_env = (os.getenv("CYLANCE_VERIFY_SSL") or "").strip().lower()
    verify = verify_env not in ("0", "false", "no", "off")

    host = region_to_host(region)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    access_token = request_access_token(
        requests,
        host,
        app_id,
        app_secret,
        tenant_id,
        verify=verify,
    )
    headers = auth_headers(access_token)

    devices = fetch_pages(requests, build_devices_url(host), headers, verify=verify)
    threats = fetch_pages(requests, build_threats_url(host), headers, verify=verify)
    policies = fetch_pages(requests, build_policies_url(host), headers, verify=verify)

    log(
        f"Processing {len(devices)} Cylance devices + {len(threats)} threats + "
        f"{len(policies)} policies (tenant={tenant_id}, region={region}, "
        f"min_severity={min_severity})"
    )

    threat_catalogue = {}
    for threat in threats:
        if not isinstance(threat, dict):
            continue
        sha = threat.get("sha256") or threat.get("Sha256") or threat.get("SHA256")
        if isinstance(sha, str) and sha.strip():
            threat_catalogue[sha.strip()] = threat

    policy_lookup = {}
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        pid = policy.get("policy_id") or policy.get("id") or policy.get("Id")
        if pid is not None:
            policy_lookup[str(pid).strip()] = policy

    device_lookup = {}
    for device in devices:
        if not isinstance(device, dict):
            continue
        did = device.get("id") or device.get("Id") or device.get("device_id")
        if did is not None:
            device_lookup[str(did).strip()] = device

    buckets = {}
    sample_devices = {}
    for did, device in device_lookup.items():
        buckets.setdefault(did, [])
        sample_devices.setdefault(did, device)
        # Pull per-device threats so each Faraday host surfaces only
        # the threats Cylance pinned to that endpoint.
        per_device = fetch_pages(
            requests,
            build_device_threats_url(host, did),
            headers,
            verify=verify,
        )
        for threat in per_device:
            if not isinstance(threat, dict):
                continue
            # Stamp the device id onto the per-device threat envelope
            # so build_vulnerability can surface it in the description.
            threat.setdefault("device_id", did)
            threat.setdefault("device_name", device_label(device))
            buckets[did].append(threat)

    hosts = []
    for key, threat_items in buckets.items():
        vulns = []
        for threat in threat_items:
            built = build_vulnerability(
                threat,
                threat_catalogue=threat_catalogue,
                policy_lookup=policy_lookup,
            )
            if built is None:
                continue
            if allowed_severities and built["severity"] not in allowed_severities:
                continue
            vulns.append(built)
        sample_device = sample_devices.get(key)
        hosts.append(build_host(key, sample_device, vulns, policy_lookup=policy_lookup))

    params_bits = [
        f"tenant_id={tenant_id}",
        f"region={region}",
        f"min_severity={min_severity}",
    ]

    output = {
        "hosts": hosts,
        "command": {
            "tool": "cylance",
            "command": "cylance",
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
