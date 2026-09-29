#!/usr/bin/env python
"""Microsoft WSUS (Windows Server Update Services) patch-management importer.

Pulls the WSUS Server's managed computer catalogue (one Windows host
per ``ComputerTarget``) and the per-computer missing-update list and
emits Faraday bulk-create JSON to stdout.  Each WSUS-managed
computer becomes one Faraday host (keyed by the WSUS ComputerID --
``FullDomainName`` / ``IPAddress`` / ``OSDescription`` /
``OSArchitecture`` / ``RequestedTargetGroupNames`` /
``LastSyncTime``); each missing update attaches as a Faraday
vulnerability with the engine prefix ``[PATCH-MGMT]``.

The WSUS SOAP API at ``/ApiRemoting30/WebService.asmx`` exposes the
admin-remoting interface used by the WSUS console, but it is not
documented for external callers and the only sanctioned Microsoft
client is the ``Microsoft.UpdateServices.Administration`` .NET
assembly.  The portable, documented integration path is therefore
via the PowerShell ``UpdateServices`` module (``Get-WsusServer`` /
``Get-WsusComputer`` / ``Get-WsusUpdate``) wrapped in a single
``pwsh -NoProfile -NonInteractive -Command -`` invocation that emits
one JSON envelope on stdout for the Python wrapper to parse.

Endpoints / cmdlets used (inside the generated PowerShell script):
  Get-WsusServer -Name $env:WSUS_HOST [-PortNumber $port -UseSsl]
      -> returns the IUpdateServer proxy.  When WSUS_USER /
      WSUS_PASSWORD are set the script wraps the WSUS-querying code
      in ``Invoke-Command -ComputerName $env:WSUS_HOST -Credential
      $cred -ScriptBlock {...}`` so alternate credentials can drive
      the .NET interop.
  $srv.GetComputerTargets()
      -> walks the WSUS computer catalogue.
  $computer.GetUpdateInstallationInfoPerUpdate()
      -> per-target missing / failed / pending updates.
  $srv.GetUpdate($info.UpdateId)
      -> resolves each UpdateID into the full update record
      (Title / MsrcSeverity / KnowledgebaseArticles /
      SecurityBulletins / UpdateClassificationTitle / CreationDate
      / Description).

Args:
  WSUS_CLASSIFICATIONS  Optional CSV of WSUS update classifications
                        ("Critical Updates", "Security Updates",
                        "Definition Updates", "Updates", "Update
                        Rollups", "Service Packs", "Tools", "Feature
                        Packs", "Drivers", "Driver Sets").  When set,
                        the executor narrows the Get-WsusUpdate query
                        to those classifications via the
                        ``-Classification`` parameter.  Defaults to
                        all classifications when unset.
  WSUS_MIN_SEVERITY     Optional client-side severity floor
                        (info | low | medium | high | critical).

Env vars:
  WSUS_HOST     WSUS Server hostname (FQDN preferred, e.g.
                "wsus.contoso.local").  Hard-validated client-side
                as a DNS label (alphanumeric + dot + hyphen).  An
                optional ``:port`` suffix selects the WSUS HTTP port
                (defaults: 8530 plain / 8531 SSL); an ``https://``
                prefix forces the SSL port.
  WSUS_USER     Optional WSUS-administrator account (``DOMAIN\\user``
                or ``user@DOMAIN``) used when the executor is not
                already running as a member of the WSUS Administrators
                group on the WSUS server.
  WSUS_PASSWORD Optional plaintext password paired with WSUS_USER.

Auth: when WSUS_USER / WSUS_PASSWORD are set the generated PowerShell
wraps the WSUS-querying code in ``Invoke-Command -ComputerName
<host> -Credential $cred -ScriptBlock {...}`` so the .NET
``AdminProxy.GetUpdateServer`` call runs under the supplied
identity; when they are not set the script calls the WSUS module
directly under the executor's current Windows session (the
documented deployment shape for an executor running on the WSUS
server itself).
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# WSUS canonical KB shape is ``KB<digits>`` in the update title /
# description and bare digits in the ``KnowledgebaseArticles``
# collection.  Accept both with optional spacing.
KB_RE = re.compile(r"\bKB\s?\d{4,10}\b", re.IGNORECASE)
# WSUS_HOST validation -- accept a bare DNS label (``wsus.contoso.local``),
# optionally prefixed with ``http(s)://`` and optionally suffixed with
# ``:<port>``.  Control chars (newline / tab / null / etc) rejected
# outright on the *raw* value so a header-injection attempt can't
# sneak through.  Anchored with \A/\Z (not ^/$) so a trailing newline
# cannot sneak through -- Python's default ``$`` matches just before
# a trailing ``\n``.
HOST_RE = re.compile(r"\A(?:https?://)?[A-Za-z0-9][A-Za-z0-9.\-]{0,253}(?::\d{1,5})?\Z")
# WSUS update classifications -- the canonical list shipped by the
# Microsoft.UpdateServices.Administration assembly.  Used to validate
# the WSUS_CLASSIFICATIONS CSV so garbage tokens don't sneak through
# into the PowerShell ``-Classification`` parameter.
WSUS_CLASSIFICATIONS_CANONICAL = (
    "critical updates",
    "security updates",
    "definition updates",
    "updates",
    "update rollups",
    "service packs",
    "tools",
    "feature packs",
    "drivers",
    "driver sets",
    "applications",
    "upgrades",
)
# Classification token validation -- letters / digits / single spaces /
# hyphens only (after .strip()), max 64 chars.  Belt-and-braces; the
# real validation is the canonical list above, this guard rejects
# control chars before the lowercase canonical lookup.
CLASS_TOKEN_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9 \-]{0,63}\Z")

TIMEOUT = 600  # PowerShell can take a while on a large WSUS catalogue.

# WSUS exposes update severity via the ``MsrcSeverity`` string enum
# (Microsoft Security Response Center) -- Critical / Important /
# Moderate / Low / Unspecified -- on every Update record returned by
# ``IUpdateServer.GetUpdate()``.  The enum buckets onto Faraday tiers;
# legacy / federated WSUS deployments occasionally surface an
# ``MsrcSeverity = "None"`` on advisories without a classified
# severity, which delegates to the numeric / classification fallback
# chain rather than bucketing straight to ``info``.
WSUS_STRING_SEVERITY = {
    "critical": "critical",
    "severe": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "unspecified": "info",
    "none": "info",
    "unknown": "info",
}

# WSUS does not vend a numeric severity column on the Update record
# (unlike SCCM's 0/2/6/8/10) -- the ``MsrcSeverity`` string enum is
# the canonical source.  Numeric input on WSUS_MIN_SEVERITY is treated
# as a CVSS-style 0-10 score for parity with the other patch-mgmt
# executors and bucketed via severity_from_cvss().

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# WSUS UpdateInstallationState (Microsoft.UpdateServices.Administration
# enum):
#   Unknown         -> open (default -- the update has not been
#                            evaluated yet against the target)
#   NotApplicable   -> closed (the update does not apply to this host)
#   NotInstalled    -> open (the update is needed but not deployed)
#   Downloaded      -> open (the update has been staged but not
#                            installed)
#   Installed       -> closed (the update is applied)
#   Failed          -> open (the install attempt failed -- the
#                            machine still needs it)
#   InstalledPendingReboot -> open (the install completed but a
#                            reboot is required to take effect --
#                            still considered exposed by patch-mgmt
#                            convention)
WSUS_INSTALLATION_STATE = {
    "unknown": "open",
    "notapplicable": "closed",
    "not_applicable": "closed",
    "notinstalled": "open",
    "not_installed": "open",
    "downloaded": "open",
    "installed": "closed",
    "failed": "open",
    "installedpendingreboot": "open",
    "installed_pending_reboot": "open",
}

# WSUS approval-action freeform fallback for federated stacks.
WSUS_STATUS_BY_STATE = {
    "open": "open",
    "missing": "open",
    "needed": "open",
    "pending": "open",
    "new": "open",
    "detected": "open",
    "applicable": "open",
    "scheduled": "open",
    "in_progress": "open",
    "inprogress": "open",
    "installing": "open",
    "downloading": "open",
    "reboot_pending": "open",
    "rebootpending": "open",
    "failed": "open",
    "notinstalled": "open",
    "not_installed": "open",
    "downloaded": "open",
    "installed": "closed",
    "applied": "closed",
    "succeeded": "closed",
    "success": "closed",
    "fixed": "closed",
    "patched": "closed",
    "resolved": "closed",
    "mitigated": "closed",
    "closed": "closed",
    "completed": "closed",
    "superseded": "closed",
    "not_applicable": "closed",
    "notapplicable": "closed",
    "compliant": "closed",
    "declined": "risk-accepted",
    "ignored": "risk-accepted",
    "suppressed": "risk-accepted",
    "deferred": "risk-accepted",
    "excluded": "risk-accepted",
    "waived": "risk-accepted",
    "accepted": "risk-accepted",
    "acknowledged": "risk-accepted",
    "risk_accepted": "risk-accepted",
    "riskaccepted": "risk-accepted",
    "notapproved": "risk-accepted",
    "not_approved": "risk-accepted",
    "uninstall": "risk-accepted",
    "will_not_install": "risk-accepted",
    "willnotinstall": "risk-accepted",
    "false_positive": "risk-accepted",
    "falsepositive": "risk-accepted",
}


def log(msg):
    print(f"{datetime.utcnow()} - WSUS: {msg}", file=sys.stderr, flush=True)


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
    """Bucket a numeric severity (0-10 CVSS-style) onto a Faraday tier.

    WSUS does not vend a numeric severity column on the Update
    record, so this is used only when an explicit CVSS score is
    parsed out of the update description / KB advisory text or when
    WSUS_MIN_SEVERITY is given as numeric input.
    """
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


def severity_from_wsus(value, cvss_numeric=None):
    """Map a WSUS update severity onto a Faraday bucket.

    Accepts the freeform ``MsrcSeverity`` string enum (Critical /
    Important / Moderate / Low / Unspecified) plus Faraday-side
    synonyms (severe / high / medium / minor / informational /
    information / none / unknown) and falls back to ``cvss_numeric``
    bucket via severity_from_cvss when a CVSS score has been parsed
    out of the description / KB advisory text.  Placeholder string
    values ("none" / "unspecified" / "unknown") delegate to the
    numeric fallback rather than bucketing straight to ``info``.
    """
    placeholder = {"none", "unspecified", "unknown"}
    if isinstance(value, bool):
        if cvss_numeric is not None:
            return severity_from_cvss(cvss_numeric)
        return "info"
    if isinstance(value, (int, float)):
        # WSUS doesn't vend numeric severity -- treat as CVSS-style.
        return severity_from_cvss(value)
    if isinstance(value, str) and value.strip():
        text = value.strip().lower().replace(" ", "_").replace("-", "_")
        if text not in placeholder and text.replace("_", "") not in placeholder:
            if text in WSUS_STRING_SEVERITY:
                return WSUS_STRING_SEVERITY[text]
            squashed = text.replace("_", "")
            if squashed in WSUS_STRING_SEVERITY:
                return WSUS_STRING_SEVERITY[squashed]
            try:
                return severity_from_cvss(float(value.strip()))
            except ValueError:
                pass
    if cvss_numeric is not None:
        return severity_from_cvss(cvss_numeric)
    return "info"


def status_from_wsus(item):
    """Derive Faraday status from a WSUS missing-update payload.

    Preferred source is the ``InstallationState`` field returned by
    ``ComputerTarget.GetUpdateInstallationInfoPerUpdate()`` (Unknown
    / NotApplicable / NotInstalled / Downloaded / Installed / Failed
    / InstalledPendingReboot).  Falls back to freeform ``status`` /
    ``state`` / ``approvalAction`` for federated stacks.
    """
    if not isinstance(item, dict):
        return "open"
    for key in (
        "InstallationState",
        "installationState",
        "installation_state",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "").replace("-", "_")
            if compact in WSUS_INSTALLATION_STATE:
                return WSUS_INSTALLATION_STATE[compact]
            snake = raw.strip().lower().replace(" ", "_").replace("-", "_")
            if snake in WSUS_INSTALLATION_STATE:
                return WSUS_INSTALLATION_STATE[snake]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "").replace("-", "_")
                    if compact in WSUS_INSTALLATION_STATE:
                        return WSUS_INSTALLATION_STATE[compact]

    for key in (
        "status",
        "Status",
        "state",
        "State",
        "approvalAction",
        "approval_action",
        "ApprovalAction",
        "deploymentStatus",
        "deployment_status",
    ):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            compact = raw.strip().lower().replace(" ", "_").replace("-", "_")
            squashed = compact.replace("_", "")
            if compact in WSUS_STATUS_BY_STATE:
                return WSUS_STATUS_BY_STATE[compact]
            if squashed in WSUS_STATUS_BY_STATE:
                return WSUS_STATUS_BY_STATE[squashed]
        elif isinstance(raw, dict):
            for sub_key in ("value", "name", "state", "status"):
                sub = raw.get(sub_key)
                if isinstance(sub, str) and sub.strip():
                    compact = sub.strip().lower().replace(" ", "_").replace("-", "_")
                    squashed = compact.replace("_", "")
                    if compact in WSUS_STATUS_BY_STATE:
                        return WSUS_STATUS_BY_STATE[compact]
                    if squashed in WSUS_STATUS_BY_STATE:
                        return WSUS_STATUS_BY_STATE[squashed]
    if item.get("IsSuperseded") is True or item.get("isSuperseded") is True:
        return "closed"
    return "open"


def validate_min_severity(value):
    """Validate WSUS_MIN_SEVERITY (severity floor).

    None / blank / garbage -> ``info`` (no client-side floor applied).
    Accepts the canonical Faraday buckets plus Microsoft synonyms
    (severe -> critical, important -> high, moderate / warning ->
    medium, minor -> low, informational / information / unspecified /
    none / unknown -> info) plus numeric-string CVSS-style input.
    """
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    if not text:
        return "info"
    bucket = WSUS_STRING_SEVERITY.get(text)
    if bucket is None:
        bucket = WSUS_STRING_SEVERITY.get(text.replace("_", ""))
    if bucket is None:
        try:
            bucket = severity_from_cvss(float(str(value).strip()))
            if bucket not in VALID_MIN_SEVERITY:
                bucket = None
        except ValueError:
            bucket = None
    if bucket is None:
        log(f"WSUS_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return bucket


def validate_classifications(value):
    """Validate WSUS_CLASSIFICATIONS (CSV of update classifications).

    None / blank -> [] (no classification filter applied -- the
    executor walks every classification the WSUS server can see).
    Accepts the canonical Microsoft.UpdateServices.Administration
    classification names (case-insensitive); malformed tokens are
    logged + skipped rather than failing the run.  Control chars on
    the *raw* CSV drop the whole filter (a header-injection attempt
    can't sneak through).
    """
    if value is None or value == "":
        return []
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw if c not in "\t"):
        # tab is technically a control char but harmless inside a CSV;
        # newline / CR / NUL are not.
        log("WSUS_CLASSIFICATIONS contains a control char; refusing to use it")
        return []
    tokens = []
    seen = set()
    for token in raw.split(","):
        text = token.strip()
        if not text:
            continue
        if not CLASS_TOKEN_RE.match(text):
            log(f"WSUS_CLASSIFICATIONS token '{text}' rejected (bad chars); skipping")
            continue
        canon = text.lower()
        if canon not in WSUS_CLASSIFICATIONS_CANONICAL:
            log(f"WSUS_CLASSIFICATIONS token '{text}' is not a canonical " "WSUS classification; skipping")
            continue
        if canon in seen:
            continue
        seen.add(canon)
        # Normalise to the canonical Title Case shape so the PowerShell
        # ``-Classification`` parameter accepts it.
        tokens.append(" ".join(w.capitalize() for w in text.split()))
    return tokens


def validate_host(value):
    """Validate WSUS_HOST.

    None / blank -> sys.exit(1).  Accepts a bare DNS label
    (``wsus.contoso.local``), optionally prefixed with ``http(s)://``
    and optionally suffixed with ``:<port>``.  Control chars rejected
    so a header / command-injection attempt can't sneak through.
    Returns the normalised ``(hostname, port, use_ssl)`` tuple so the
    generated PowerShell can drive ``Get-WsusServer`` with the right
    port / SSL flag.
    """
    if value is None or value == "":
        log("WSUS_HOST is required")
        sys.exit(1)
    raw = str(value)
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in raw):
        log("WSUS_HOST contains a control char; refusing to use it")
        sys.exit(1)
    text = raw.strip()
    if not text:
        log("WSUS_HOST is required")
        sys.exit(1)
    text = text.rstrip("/")
    if not HOST_RE.match(text):
        log(f"WSUS_HOST '{text}' is not a valid hostname[:port]")
        sys.exit(1)
    use_ssl = False
    host_text = text
    if host_text.lower().startswith("https://"):
        use_ssl = True
        host_text = host_text[len("https://") :]
    elif host_text.lower().startswith("http://"):
        host_text = host_text[len("http://") :]
    port = None
    if ":" in host_text:
        host_only, port_str = host_text.rsplit(":", 1)
        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                raise ValueError(port)
        except ValueError:
            log(f"WSUS_HOST port '{port_str}' is not in range 1..65535")
            sys.exit(1)
        host_text = host_only
    if not host_text:
        log("WSUS_HOST has no hostname")
        sys.exit(1)
    # Default WSUS ports: 8530 plain / 8531 SSL.
    if port is None:
        port = 8531 if use_ssl else 8530
    return host_text, port, use_ssl


def severities_at_or_above(min_severity):
    """Return the Faraday severity buckets at or above ``min_severity``."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [bucket for bucket, order in SEVERITY_ORDER.items() if order >= floor]


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
    """Walk a WSUS update payload for CVE-* ids.

    WSUS update records carry CVE ids inline in the Title /
    Description / SecurityBulletins text rather than in a dedicated
    column, so the regex scan is the canonical source.  Federated
    stacks that surface a ``CVEs`` / ``cve`` column have it honoured.
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

    for key in ("cve", "CVE", "cveId", "CVEId", "cve_id"):
        v = item.get(key)
        if isinstance(v, str):
            add(v)
    for key in ("cves", "CVEs", "cveIds", "CVEIds", "cve_ids"):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("id") or entry.get("cve") or entry.get("cve_id"))

    for key in (
        "Title",
        "title",
        "Description",
        "description",
        "summary",
        "Summary",
        "name",
        "Name",
        "SecurityBulletins",
        "securityBulletins",
        "security_bulletins",
    ):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, str):
            scan(v)
        elif isinstance(v, list):
            for entry in v:
                if isinstance(entry, str):
                    scan(entry)
    return found


def collect_kb_ids(item):
    """Walk a WSUS update payload for Microsoft KB ids.

    WSUS's canonical KB reference is the ``KnowledgebaseArticles``
    collection (a list of bare digit strings).  Also inline-scan
    Title / Description for ``KB<digits>`` references so federated
    stacks with non-canonical KB columns still surface their KB
    pivots.
    """
    found = []
    seen = set()

    def add(num):
        if not num:
            return
        s = str(num).strip().upper()
        if s.startswith("KB"):
            s = s[2:].lstrip()
        if not s.isdigit() or not (4 <= len(s) <= 10):
            return
        if s in seen:
            return
        seen.add(s)
        found.append(s)

    def scan(text):
        if not isinstance(text, str):
            return
        for m in KB_RE.findall(text):
            add(m.replace(" ", ""))

    if not isinstance(item, dict):
        return found

    for key in (
        "KnowledgebaseArticles",
        "knowledgebaseArticles",
        "knowledgebase_articles",
        "kbArticles",
        "kb_articles",
    ):
        v = item.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, (int, str)):
                    add(entry)
                elif isinstance(entry, dict):
                    add(entry.get("id") or entry.get("article") or entry.get("articleId") or entry.get("kb"))
        elif isinstance(v, (int, str)):
            add(v)

    for key in ("kb", "kbId", "kb_id", "ArticleID", "articleId", "article_id"):
        v = item.get(key)
        if isinstance(v, (int, str)):
            add(v)

    for key in (
        "Title",
        "title",
        "Description",
        "description",
        "summary",
        "Summary",
        "name",
        "Name",
        "BulletinID",
        "bulletinId",
        "bulletin_id",
    ):
        v = item.get(key)
        if isinstance(v, str):
            scan(v)
    return found


def collect_refs(item):
    """Walk a WSUS update payload for advisory pivots."""
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

    update_id = (
        item.get("UpdateId") or item.get("updateId") or item.get("update_id") or item.get("Id") or item.get("id")
    )
    if update_id is not None:
        s = str(update_id).strip()
        if s:
            add(f"WSUS-UpdateId: {s}")

    classification = (
        item.get("UpdateClassificationTitle")
        or item.get("updateClassificationTitle")
        or item.get("update_classification_title")
        or item.get("Classification")
        or item.get("classification")
    )
    if isinstance(classification, str) and classification.strip():
        add(f"WSUS-Classification: {classification.strip()}")
    elif isinstance(classification, dict):
        label = classification.get("name") or classification.get("title")
        if isinstance(label, str) and label.strip():
            add(f"WSUS-Classification: {label.strip()}")

    severity_raw = (
        item.get("MsrcSeverity")
        or item.get("msrcSeverity")
        or item.get("msrc_severity")
        or item.get("SeverityName")
        or item.get("severity")
    )
    if (
        isinstance(severity_raw, str)
        and severity_raw.strip()
        and severity_raw.strip().lower() not in ("none", "unspecified")
    ):
        add(f"WSUS-MsrcSeverity: {severity_raw.strip()}")

    product = item.get("ProductTitles") or item.get("productTitles") or item.get("Product")
    if isinstance(product, list):
        for entry in product:
            if isinstance(entry, str) and entry.strip():
                add(f"WSUS-Product: {entry.strip()}")
    elif isinstance(product, str) and product.strip():
        add(f"WSUS-Product: {product.strip()}")

    bulletins = item.get("SecurityBulletins") or item.get("securityBulletins") or item.get("security_bulletins")
    if isinstance(bulletins, list):
        for entry in bulletins:
            if isinstance(entry, str) and entry.strip():
                add(f"WSUS-Bulletin: {entry.strip()}")
    elif isinstance(bulletins, str) and bulletins.strip():
        add(f"WSUS-Bulletin: {bulletins.strip()}")

    creation = (
        item.get("CreationDate") or item.get("creationDate") or item.get("creation_date") or item.get("ArrivalDate")
    )
    if isinstance(creation, str) and creation.strip():
        add(f"WSUS-CreationDate: {creation.strip()}")

    install_state = item.get("InstallationState") or item.get("installationState") or item.get("installation_state")
    if isinstance(install_state, str) and install_state.strip():
        add(f"WSUS-InstallationState: {install_state.strip()}")

    approval = item.get("ApprovalAction") or item.get("approvalAction") or item.get("approval_action")
    if isinstance(approval, str) and approval.strip():
        add(f"WSUS-ApprovalAction: {approval.strip()}")

    if item.get("IsSuperseded") is True or item.get("isSuperseded") is True:
        add("WSUS-Superseded: true")

    if item.get("RebootBehavior") and isinstance(item.get("RebootBehavior"), str):
        rb = item.get("RebootBehavior").strip()
        if rb and rb.lower() != "neverreboots":
            add(f"WSUS-RebootBehavior: {rb}")

    machine = (
        item.get("MachineName") or item.get("FullDomainName") or item.get("computer_name") or item.get("computerName")
    )
    if isinstance(machine, str) and machine.strip():
        add(f"WSUS-Computer: {machine.strip()}")

    msrc_links = item.get("MoreInfoUrls") or item.get("more_info_urls")
    if isinstance(msrc_links, list):
        for entry in msrc_links:
            if isinstance(entry, str) and entry.strip():
                add(entry.strip())
    elif isinstance(msrc_links, str) and msrc_links.strip():
        add(msrc_links.strip())

    return refs


def update_label(item):
    """Build the leading title fragment for a WSUS missing-update finding."""
    if not isinstance(item, dict):
        return ""
    for key in (
        "Title",
        "title",
        "displayName",
        "DisplayName",
        "display_name",
        "name",
        "Name",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in (
        "SecurityBulletins",
        "securityBulletins",
        "BulletinID",
        "bulletinId",
        "bulletin",
    ):
        v = item.get(key)
        if isinstance(v, list) and v:
            first = v[0]
            if isinstance(first, str) and first.strip():
                return first.strip()
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("KnowledgebaseArticles", "knowledgebaseArticles", "kbArticles"):
        v = item.get(key)
        if isinstance(v, list) and v:
            first = v[0]
            if isinstance(first, (str, int)):
                s = str(first).strip()
                if s:
                    return s if s.upper().startswith("KB") else f"KB{s}"
    for key in ("Description", "description", "summary"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "Missing update"


def build_vulnerability(item):
    """Build a Faraday vulnerability dict from a WSUS missing-update record."""
    if not isinstance(item, dict):
        return None

    cvss_numeric = None
    for key in (
        "CVSS3Score",
        "cvss3Score",
        "cvss3_score",
        "CVSS2Score",
        "cvss2Score",
        "cvss2_score",
        "cvssScore",
        "cvss_score",
        "cvss",
    ):
        raw_numeric = item.get(key)
        if isinstance(raw_numeric, (int, float)) and not isinstance(raw_numeric, bool):
            cvss_numeric = float(raw_numeric)
            break
        if isinstance(raw_numeric, str) and raw_numeric.strip():
            try:
                cvss_numeric = float(raw_numeric.strip())
                break
            except ValueError:
                continue

    severity_string = (
        item.get("MsrcSeverity")
        or item.get("msrcSeverity")
        or item.get("msrc_severity")
        or item.get("SeverityName")
        or item.get("severityName")
        or item.get("severity")
        or item.get("severityLabel")
        or item.get("risk_level")
    )
    severity = severity_from_wsus(severity_string, cvss_numeric)
    status = status_from_wsus(item)

    label = update_label(item)
    if label and label != "Missing update":
        name = f"[PATCH-MGMT] Missing update: {label}"
    else:
        name = "[PATCH-MGMT] Missing update"

    desc_parts = []
    description = item.get("Description") or item.get("description") or item.get("summary") or item.get("Summary")
    if isinstance(description, str) and description.strip():
        desc_parts.append(description.strip())
    elif isinstance(description, list):
        chunks = [str(x).strip() for x in description if str(x).strip()]
        if chunks:
            desc_parts.append("\n".join(chunks))

    for label_key, key in (
        ("update_id", "UpdateId"),
        ("classification", "UpdateClassificationTitle"),
        ("msrc_severity", "MsrcSeverity"),
        ("legacy_name", "LegacyName"),
        ("creation_date", "CreationDate"),
        ("arrival_date", "ArrivalDate"),
        ("installation_state", "InstallationState"),
        ("approval_action", "ApprovalAction"),
        ("is_approved", "IsApproved"),
        ("is_declined", "IsDeclined"),
        ("is_superseded", "IsSuperseded"),
        ("is_wsus_infrastructure", "IsWsusInfrastructureUpdate"),
        ("reboot_behavior", "RebootBehavior"),
        ("requires_license_agreement", "RequiresLicenseAgreementAcceptance"),
        ("computer_id", "ComputerId"),
        ("computer_name", "FullDomainName"),
        ("ip", "IPAddress"),
        ("os", "OSDescription"),
        ("target_groups", "RequestedTargetGroupNames"),
    ):
        v = item.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            desc_parts.append(f"{label_key}: {_serialise(v)}")
        else:
            desc_parts.append(f"{label_key}: {v}")

    if cvss_numeric is not None:
        desc_parts.append(f"cvss_score: {cvss_numeric}")

    cves = collect_cves(item)
    kb_ids = collect_kb_ids(item)
    refs = collect_refs(item)
    for kb in kb_ids:
        ref_name = f"KB: KB{kb}"
        if ref_name not in {r.get("name") for r in refs}:
            refs.append({"name": ref_name, "type": "other"})
        url_name = f"https://support.microsoft.com/help/{kb}"
        if url_name not in {r.get("name") for r in refs}:
            refs.append({"name": url_name, "type": "other"})

    info_url = item.get("InfoURL") or item.get("infoUrl") or item.get("info_url")
    if isinstance(info_url, str) and info_url.strip():
        url_name = info_url.strip()
        if url_name not in {r.get("name") for r in refs}:
            refs.append({"name": url_name, "type": "other"})

    resolution = ""
    remediations = item.get("remediation") or item.get("resolution") or item.get("recommendation")
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
        kb_hint = ""
        if kb_ids:
            kb_hint = f" Apply KB{', KB'.join(kb_ids[:5])}."
        resolution = (
            "Approve the missing update through the WSUS Update "
            "Services console (Updates -> All Updates -> select the "
            "update -> Approve) targeting the affected target group; "
            "or run ''wuauclt /detectnow'' (or ''UsoClient StartScan'' "
            "on Windows 10+) on the affected machine to force a "
            "WSUS check-in; or decline the update in WSUS if it "
            "should not be applied."
            f"{kb_hint}"
        )

    external_id = str(
        item.get("UpdateId")
        or item.get("updateId")
        or item.get("update_id")
        or (f"KB{kb_ids[0]}" if kb_ids else "")
        or (cves[0] if cves else "")
    )

    return {
        "name": str(name).strip()[:200] or f"Missing update {external_id}",
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
        "tags": ["microsoft", "patch-management", "wsus", "missing-patch"],
    }


def computer_hostname(computer, fallback):
    """Pick the canonical hostname for a WSUS ComputerTarget record."""
    if isinstance(computer, dict):
        for key in (
            "FullDomainName",
            "fullDomainName",
            "full_domain_name",
            "ComputerName",
            "computerName",
            "computer_name",
            "Name",
            "name",
            "NetbiosName",
            "netbios_name",
            "hostname",
            "Hostname",
        ):
            v = computer.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(fallback, str) and fallback.strip():
        return fallback.strip()
    return ""


def computer_ip(computer):
    """Pick an IP address for the WSUS ComputerTarget record."""
    if not isinstance(computer, dict):
        return "0.0.0.0"
    for key in (
        "IPAddress",
        "ipAddress",
        "ip_address",
        "ip",
        "IpAddress",
    ):
        v = computer.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("IPAddresses", "ipAddresses", "ip_addresses"):
        v = computer.get(key)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip():
                    return entry.strip()
    return "0.0.0.0"


def computer_os(computer):
    """Build the host.os string from a WSUS ComputerTarget record."""
    if not isinstance(computer, dict):
        return "unknown"
    arch = computer.get("OSArchitecture") or computer.get("os_architecture") or ""
    for key in (
        "OSDescription",
        "osDescription",
        "os_description",
        "OperatingSystem",
        "operating_system",
        "operatingSystem",
        "os",
        "osName",
        "os_name",
        "Platform",
        "platform",
    ):
        v = computer.get(key)
        if isinstance(v, str) and v.strip():
            text = v.strip()
            if arch and isinstance(arch, str) and arch.strip() and arch.strip().lower() not in text.lower():
                text = f"{text} ({arch.strip()})"
            return text
    return "unknown"


def build_host(computer_id, computer, vulns, scoping=None):
    """Build a Faraday host record for a WSUS-managed computer."""
    if not isinstance(computer, dict):
        computer = {}
    if not isinstance(scoping, dict):
        scoping = {}
    hostname = computer_hostname(computer, str(computer_id or ""))
    os_str = computer_os(computer)
    ip = computer_ip(computer)

    desc_parts = []
    if computer_id:
        desc_parts.append(f"computer_id={computer_id}")
    for label_key, key in (
        ("fqdn", "FullDomainName"),
        ("name", "Name"),
        ("os", "OSDescription"),
        ("arch", "OSArchitecture"),
        ("last_sync", "LastSyncTime"),
        ("last_reported_status", "LastReportedStatusTime"),
        ("client_version", "ClientVersion"),
        ("last_sync_result", "LastSyncResult"),
        ("requested_target_group", "RequestedTargetGroupName"),
    ):
        v = computer.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, (dict, list)):
            continue
        desc_parts.append(f"{label_key}={v}")

    target_groups = (
        computer.get("RequestedTargetGroupNames")
        or computer.get("ComputerTargetGroupNames")
        or computer.get("target_groups")
    )
    if isinstance(target_groups, list):
        joined = ",".join(str(x).strip() for x in target_groups if str(x).strip())
        if joined:
            desc_parts.append(f"target_groups={joined}")
    elif isinstance(target_groups, str) and target_groups.strip():
        desc_parts.append(f"target_groups={target_groups.strip()}")

    for label_key, key in (
        ("scope_classifications", "classifications"),
        ("scope_min_severity", "min_severity"),
    ):
        v = scoping.get(key)
        if v in (None, ""):
            continue
        if isinstance(v, list):
            joined = ",".join(str(x).strip() for x in v if str(x).strip())
            if joined:
                desc_parts.append(f"{label_key}={joined}")
        else:
            desc_parts.append(f"{label_key}={v}")

    if vulns:
        desc_parts.append(f"missing_updates={len(vulns)}")

    return {
        "ip": ip,
        "os": os_str,
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def computer_id_for(record):
    """Pick a computer id (GUID string) out of a WSUS ComputerTarget record."""
    if not isinstance(record, dict):
        return None
    for key in (
        "ComputerId",
        "computerId",
        "computer_id",
        "Id",
        "id",
        "TargetId",
        "targetId",
        "target_id",
    ):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, int) and not isinstance(v, bool):
            return str(v)
    return None


def detect_powershell():
    """Locate ``pwsh`` (PowerShell Core) or ``powershell`` (legacy) on PATH.

    Returns the absolute path of the chosen executable or None when
    neither is available.  Prefers ``pwsh`` (cross-platform Core 7+)
    since the WSUS ``UpdateServices`` module ships there as well as
    in Windows PowerShell 5.1.
    """
    for name in ("pwsh", "powershell"):
        path = shutil.which(name)
        if path:
            return path
    return None


def build_powershell_script(hostname, port, use_ssl, classifications, has_credentials):
    """Build the PowerShell script that drives the WSUS query.

    The script reads every parameter from environment variables (so
    user-controlled input is never interpolated into PowerShell
    source) and emits one JSON envelope on stdout.  When
    ``has_credentials`` is true the script wraps the WSUS calls in
    ``Invoke-Command -ComputerName $env:WSUS_HOST -Credential $cred
    -ScriptBlock {...}`` so the .NET interop runs under the supplied
    identity; otherwise it calls the WSUS module directly under the
    executor's current Windows session.
    """
    # Only the connection settings (host / port / SSL flag) are baked
    # into the script body because they were already validated; any
    # PowerShell-special character in them would have failed the
    # validator.  Even so, defence in depth -- single-quote-escape the
    # hostname.
    safe_host = str(hostname).replace("'", "''")
    cls_block = ""
    if classifications:
        # Build a PowerShell array literal of the canonical
        # classification names; each name is single-quote-escaped.
        items = ",".join("'" + str(c).replace("'", "''") + "'" for c in classifications)
        cls_block = f"$classifications = @({items})"
    else:
        cls_block = "$classifications = @()"

    invoke_open = ""
    invoke_close = ""
    if has_credentials:
        invoke_open = (
            "$pw = ConvertTo-SecureString $env:WSUS_PASSWORD -AsPlainText -Force\n"
            "$cred = New-Object System.Management.Automation.PSCredential("
            "$env:WSUS_USER, $pw)\n"
            f"Invoke-Command -ComputerName '{safe_host}' -Credential $cred "
            "-ScriptBlock {\n"
            "    param($wsusHost, $wsusPort, $useSsl, $classifications)\n"
        )
        invoke_close = (
            "} -ArgumentList '" + safe_host + "', "
            f"{int(port)}, ${str(bool(use_ssl)).lower()}, "
            "$classifications | ConvertTo-Json -Depth 6 -Compress\n"
        )
        body_host = "$wsusHost"
        body_port = "$wsusPort"
        body_ssl = "$useSsl"
        body_cls = "$classifications"
        emit = ""  # JSON emitted by the outer ConvertTo-Json pipeline.
    else:
        invoke_open = ""
        invoke_close = ""
        body_host = f"'{safe_host}'"
        body_port = str(int(port))
        body_ssl = "$" + str(bool(use_ssl)).lower()
        body_cls = "$classifications"
        emit = "$result | ConvertTo-Json -Depth 6 -Compress\n"

    script = f"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
{cls_block}
{invoke_open}
try {{
    [reflection.assembly]::LoadWithPartialName(
        'Microsoft.UpdateServices.Administration') | Out-Null
}} catch {{
    Write-Error ("WSUS .NET assembly not available: " + $_.Exception.Message)
    exit 2
}}
try {{
    $srv = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer(
        {body_host}, {body_ssl}, {body_port})
}} catch {{
    Write-Error ("Get-WsusServer failed: " + $_.Exception.Message)
    exit 3
}}

$computerOut = New-Object System.Collections.ArrayList
$updateCache = @{{}}

$computers = $srv.GetComputerTargets()
foreach ($computer in $computers) {{
    $rec = @{{
        ComputerId       = [string]$computer.Id
        FullDomainName   = [string]$computer.FullDomainName
        IPAddress        = [string]$computer.IPAddress
        OSDescription    = [string]$computer.OSDescription
        OSArchitecture   = [string]$computer.OSInfo.OSArchitecture
        LastSyncTime     = [string]$computer.LastSyncTime
        LastReportedStatusTime = [string]$computer.LastReportedStatusTime
        ClientVersion    = [string]$computer.ClientVersion
        LastSyncResult   = [string]$computer.LastSyncResult
        RequestedTargetGroupNames = @($computer.RequestedTargetGroupNames | ForEach-Object {{ [string]$_ }})
        ComputerTargetGroupNames  = @($computer.ComputerTargetGroupIds | ForEach-Object {{ [string]$_ }})
        MissingUpdates   = @()
    }}
    try {{
        $infos = $computer.GetUpdateInstallationInfoPerUpdate()
    }} catch {{
        $rec.MissingUpdates = @()
        [void]$computerOut.Add($rec)
        continue
    }}
    foreach ($info in $infos) {{
        $state = [string]$info.UpdateInstallationState
        if ($state -eq 'Installed' -or $state -eq 'NotApplicable') {{ continue }}
        $approval = [string]$info.UpdateApprovalAction
        $uid = [string]$info.UpdateId
        if ($updateCache.ContainsKey($uid)) {{
            $u = $updateCache[$uid]
        }} else {{
            try {{
                $u = $srv.GetUpdate($info.UpdateId)
            }} catch {{
                $u = $null
            }}
            $updateCache[$uid] = $u
        }}
        if ($null -eq $u) {{ continue }}
        if (${body_cls}.Count -gt 0) {{
            $cls = [string]$u.UpdateClassificationTitle
            $match = $false
            foreach ($want in ${body_cls}) {{
                if ($cls -ieq $want) {{ $match = $true; break }}
            }}
            if (-not $match) {{ continue }}
        }}
        $upd = @{{
            UpdateId                   = [string]$u.Id.UpdateId
            Title                      = [string]$u.Title
            Description                = [string]$u.Description
            MsrcSeverity               = [string]$u.MsrcSeverity
            UpdateClassificationTitle  = [string]$u.UpdateClassificationTitle
            CreationDate               = [string]$u.CreationDate
            ArrivalDate                = [string]$u.ArrivalDate
            IsApproved                 = [bool]$u.IsApproved
            IsDeclined                 = [bool]$u.IsDeclined
            IsSuperseded               = [bool]$u.IsSuperseded
            IsWsusInfrastructureUpdate = [bool]$u.IsWsusInfrastructureUpdate
            RebootBehavior             = [string]$u.InstallationBehavior.RebootBehavior
            RequiresLicenseAgreementAcceptance = [bool]$u.RequiresLicenseAgreementAcceptance
            LegacyName                 = [string]$u.LegacyName
            KnowledgebaseArticles      = @($u.KnowledgebaseArticles | ForEach-Object {{ [string]$_ }})
            SecurityBulletins          = @($u.SecurityBulletins | ForEach-Object {{ [string]$_ }})
            ProductTitles              = @($u.ProductTitles | ForEach-Object {{ [string]$_ }})
            MoreInfoUrls               = @($u.AdditionalInformationUrls | ForEach-Object {{ [string]$_.AbsoluteUri }})
            InstallationState          = $state
            ApprovalAction             = $approval
        }}
        $rec.MissingUpdates += $upd
    }}
    [void]$computerOut.Add($rec)
}}

$result = @{{
    wsus_host    = {body_host}
    wsus_port    = {body_port}
    wsus_use_ssl = {body_ssl}
    computers    = $computerOut
}}
{emit}{invoke_close}""".strip() + "\n"
    return script


def run_powershell(executable, script, env_overrides, timeout=TIMEOUT):
    """Run the generated PowerShell script and return its stdout.

    The script is piped via stdin to ``pwsh -NoProfile -NonInteractive
    -Command -`` so we don't have to write a temp file.  All
    user-controlled parameters (WSUS_HOST / WSUS_USER /
    WSUS_PASSWORD) are passed through the subprocess environment so
    they never reach the command line.
    """
    proc_env = dict(os.environ)
    for k, v in (env_overrides or {}).items():
        if v is None:
            continue
        proc_env[k] = str(v)
    cmd = [executable, "-NoProfile", "-NonInteractive", "-Command", "-"]
    try:
        result = subprocess.run(
            cmd,
            input=script,
            env=proc_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
        )
    except subprocess.TimeoutExpired:
        log(f"PowerShell invocation timed out after {timeout}s")
        return None
    except OSError as exc:
        log(f"PowerShell invocation failed to spawn: {exc}")
        return None
    if result.stderr:
        for line in result.stderr.splitlines():
            if line.strip():
                log(f"pwsh: {line.strip()}")
    if result.returncode != 0:
        log(f"PowerShell exited with non-zero code {result.returncode}")
        return None
    return result.stdout


def parse_wsus_envelope(stdout):
    """Parse the JSON envelope emitted by the generated PowerShell script.

    The envelope shape is::
      {
        "wsus_host": "...",
        "wsus_port": 8530,
        "wsus_use_ssl": false,
        "computers": [
          {
            "ComputerId": "...",
            "FullDomainName": "...",
            ...
            "MissingUpdates": [ {...}, ... ]
          }, ...
        ]
      }

    Returns ``(envelope, computers)`` where ``computers`` is always a
    list (possibly empty) so the caller can walk it without
    re-checking the type.
    """
    if not stdout or not stdout.strip():
        return None, []
    try:
        payload = json.loads(stdout)
    except (TypeError, ValueError):
        log("PowerShell output was not valid JSON")
        return None, []
    if isinstance(payload, list):
        # ConvertTo-Json on a single-element collection unwraps to a
        # bare object in PowerShell 5.1; on a multi-element it stays
        # a list.  Accept both shapes for the envelope.
        if len(payload) == 1 and isinstance(payload[0], dict):
            payload = payload[0]
    if not isinstance(payload, dict):
        log("PowerShell output JSON was not an object")
        return None, []
    computers = payload.get("computers")
    if not isinstance(computers, list):
        computers = []
    cleaned = []
    for c in computers:
        if isinstance(c, dict):
            cleaned.append(c)
    return payload, cleaned


def main():
    started = time.time()

    classifications = validate_classifications(env("EXECUTOR_CONFIG_WSUS_CLASSIFICATIONS"))
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_WSUS_MIN_SEVERITY"))
    allowed_severities = set(severities_at_or_above(min_severity))

    hostname, port, use_ssl = validate_host(env("WSUS_HOST", required=True))
    user = env("WSUS_USER")
    password = env("WSUS_PASSWORD")
    has_credentials = bool(user) and bool(password)

    pwsh = detect_powershell()
    if not pwsh:
        log("neither 'pwsh' nor 'powershell' found on PATH; cannot drive WSUS")
        sys.exit(1)

    script = build_powershell_script(hostname, port, use_ssl, classifications, has_credentials)

    log(
        f"Invoking WSUS via {os.path.basename(pwsh)} against "
        f"{hostname}:{port} (ssl={use_ssl}, classifications="
        f"{classifications or '<all>'}, min_severity={min_severity})"
    )

    env_overrides = {
        "WSUS_HOST": hostname,
    }
    if has_credentials:
        env_overrides["WSUS_USER"] = user
        env_overrides["WSUS_PASSWORD"] = password

    stdout = run_powershell(pwsh, script, env_overrides)
    payload, computers = parse_wsus_envelope(stdout)

    scoping = {
        "classifications": classifications,
        "min_severity": min_severity,
    }

    hosts = []
    for computer in computers:
        cid = computer_id_for(computer)
        if cid is None and isinstance(computer, dict):
            cid = computer.get("FullDomainName") or computer.get("Name") or ""
        missing = computer.get("MissingUpdates") if isinstance(computer, dict) else None
        if not isinstance(missing, list):
            missing = []
        vulns = []
        for entry in missing:
            if not isinstance(entry, dict):
                continue
            enriched = dict(entry)
            enriched.setdefault("ComputerId", cid)
            fqdn = computer.get("FullDomainName") if isinstance(computer, dict) else None
            if isinstance(fqdn, str) and fqdn.strip():
                enriched.setdefault("FullDomainName", fqdn.strip())
            ip = computer.get("IPAddress") if isinstance(computer, dict) else None
            if isinstance(ip, str) and ip.strip():
                enriched.setdefault("IPAddress", ip.strip())
            os_desc = computer.get("OSDescription") if isinstance(computer, dict) else None
            if isinstance(os_desc, str) and os_desc.strip():
                enriched.setdefault("OSDescription", os_desc.strip())
            tgt = computer.get("RequestedTargetGroupNames") if isinstance(computer, dict) else None
            if isinstance(tgt, list):
                enriched.setdefault("RequestedTargetGroupNames", tgt)
            built = build_vulnerability(enriched)
            if built is None:
                continue
            if allowed_severities and built["severity"] not in allowed_severities:
                continue
            vulns.append(built)
        hosts.append(build_host(cid, computer, vulns, scoping))

    if not hosts:
        hosts.append(
            build_host(
                hostname,
                {"FullDomainName": hostname, "OSDescription": "WSUS Server"},
                [],
                scoping,
            )
        )

    params_bits = []
    if classifications:
        params_bits.append("classifications=" + ",".join(classifications))
    params_bits.append(f"min_severity={min_severity}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "wsus",
            "command": "wsus",
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
