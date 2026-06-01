#!/usr/bin/env python
"""LDAP / Active Directory weak-userAccountControl auditor.

Walks an LDAP / Active Directory tree via the ldap3 Python
client (``ldap3.Server`` + ``Connection.search`` / paged
``extend.standard.paged_search``) and emits one Faraday host +
one Faraday vulnerability for every user / group / computer
object whose ``userAccountControl`` carries a weakness flag
combination:

    ACCOUNTDISABLE bit clear  (i.e. account is enabled)
    AND
    (PASSWD_NOTREQD bit set OR DONT_EXPIRE_PASSWORD bit set)

These are the two canonical AD hardening defects we surface as
red-team-ready findings:

    PASSWD_NOTREQD (0x0020)
        The account is permitted to authenticate with an empty
        password.  Severe — surfaced as ``critical``.

    DONT_EXPIRE_PASSWORD (0x10000)
        The account's password never expires; long-lived
        credentials sit indefinitely.  Surfaced as ``medium``.

ACCOUNTDISABLE (0x0002) is the gate — accounts with that bit set
are silently dropped from the output (we don't surface findings
on disabled accounts because they can't be authenticated against
in their current state).

The executor accepts an operator-supplied LDAP filter so the
walk can be scoped to a single OU / group / sAMAccountName
prefix, and an operator-supplied attribute CSV so the
projection covers the operator's per-tenant schema additions
(custom attribute names like ``employeeNumber`` /
``departmentNumber``); ``userAccountControl`` is always added
to the attribute set because weak-UAC detection requires it.

Each emitted Faraday host carries:

    Computers — keyed on ``dNSHostName`` when present; ``host.os``
    carries the Active Directory ``operatingSystem`` +
    ``operatingSystemVersion`` strings (e.g. ``"Windows Server
    2019 Standard 10.0 (17763)"``).  IP harvested from
    ``ipv4Address`` when the schema vends it, else the
    ``0.0.0.0`` sentinel (Active Directory does not always
    record an IP on computer objects).

    Users / groups — keyed on ``sAMAccountName`` / ``cn`` (LDAP
    user / group records aren't IP-keyed); IP is the
    ``0.0.0.0`` sentinel.

Tags: ``[ldap, ldap-audit, identity, active-directory,
user|group|computer]``.  Engine prefix: ``[IDENTITY]`` (matches
the BloodHound Enterprise / identity-graph convention).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

TIMEOUT = 60
DEFAULT_PAGE_SIZE = 500
MAX_PAGES = 200

# AD userAccountControl flag bits we audit (https://learn.microsoft.com
# /en-us/windows/win32/api/iads/ne-iads-ads_user_flag_enum).
UAC_ACCOUNTDISABLE = 0x0002
UAC_PASSWD_NOTREQD = 0x0020
UAC_DONT_EXPIRE_PASSWORD = 0x10000

# Walk users + groups + computers by default.  The ``person`` /
# ``group`` / ``computer`` objectCategory tokens are canonical AD
# schema names; the OR keeps the walk inclusive when the operator
# leaves LDAP_FILTER unset.
DEFAULT_FILTER = "(|(objectCategory=person)(objectCategory=group)(objectCategory=computer))"

# Default attribute projection — covers users / groups / computers
# with the UAC, identity, and host columns we shape host.os / refs /
# description from.  Operators can override via LDAP_ATTRIBUTES; the
# executor always re-injects ``userAccountControl`` since weak-UAC
# detection requires it.
DEFAULT_ATTRIBUTES = [
    "sAMAccountName",
    "cn",
    "distinguishedName",
    "objectClass",
    "userAccountControl",
    "userPrincipalName",
    "memberOf",
    "operatingSystem",
    "operatingSystemVersion",
    "dNSHostName",
    "ipv4Address",
    "whenCreated",
    "whenChanged",
    "lastLogonTimestamp",
    "pwdLastSet",
    "displayName",
    "mail",
    "description",
]

# Sentinel IP for non-network-keyed records (LDAP users / groups).
SENTINEL_IP = "0.0.0.0"


def log(msg):
    print(f"{datetime.utcnow()} - LdapAudit: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def _has_control_chars(value):
    if not isinstance(value, str):
        return False
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)


def validate_host(value):
    """Validate LDAP_HOST.

    Accepts a bare hostname / IP, ``ldap://host[:port]``, or
    ``ldaps://host[:port]``.  Control chars (CR / LF / NUL /
    other 0x00-0x1F + 0x7F) are rejected on the raw value
    before ``.strip()`` runs so a header-injection attempt
    can't sneak through.  Regex is anchored with ``\\A`` /
    ``\\Z`` not ``^`` / ``$`` so ``$``-matches-before-newline
    can't slip past either.  Trailing slash is stripped.
    """
    if value is None:
        return ""
    raw = str(value)
    if _has_control_chars(raw):
        return ""
    text = raw.strip().rstrip("/")
    if not text:
        return ""
    if not re.match(r"\A(?:ldap://|ldaps://)?[A-Za-z0-9.\-_]+(?::\d{1,5})?\Z", text):
        return ""
    return text


def validate_base_dn(value):
    """Validate LDAP_BASE_DN (e.g. ``DC=corp,DC=local``).

    Mandatory upstream in ``main()``.  Control chars rejected,
    whitespace trimmed, charset restricted to the RDN-safe
    alphabet (alphanumeric + ``=,.+ _-\\:#;`` + forward / back
    slash) so an injected ``)`` or NUL byte can't fan out into a
    forged search base.  Anchored with ``\\A`` / ``\\Z``.
    """
    if value is None:
        return ""
    raw = str(value)
    if _has_control_chars(raw):
        return ""
    text = raw.strip()
    if not text:
        return ""
    if not re.match(r"\A[A-Za-z0-9=,. _\-+/\\:#;]+\Z", text):
        return ""
    return text


def validate_filter(value):
    """Validate LDAP_FILTER.

    None / blank -> ``DEFAULT_FILTER`` (users + groups +
    computers).  Control chars in the raw value drop the
    filter back to the default.  A valid LDAP RFC 4515 filter
    must be wrapped in matching parens; the executor enforces
    a balanced-parens check (without trying to be a full LDAP
    filter parser) so a malformed filter doesn't fan out into
    an unfiltered tree walk.
    """
    if value is None:
        return DEFAULT_FILTER
    raw = str(value)
    if _has_control_chars(raw):
        log("LDAP_FILTER contains control chars; falling back to default")
        return DEFAULT_FILTER
    text = raw.strip()
    if not text:
        return DEFAULT_FILTER
    if not text.startswith("(") or not text.endswith(")"):
        log("LDAP_FILTER not parenthesised; falling back to default")
        return DEFAULT_FILTER
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                log("LDAP_FILTER unbalanced parens; falling back to default")
                return DEFAULT_FILTER
    if depth != 0:
        log("LDAP_FILTER unbalanced parens; falling back to default")
        return DEFAULT_FILTER
    return text


def validate_attributes(value):
    """Validate LDAP_ATTRIBUTES (CSV of LDAP attribute names).

    None / blank -> ``DEFAULT_ATTRIBUTES``.  Control chars
    drop the CSV back to defaults.  Per-token validation
    against the RFC 4512 attribute-description ABNF (letter
    followed by letters / digits / ``-`` / ``_`` / ``;``) —
    malformed tokens are logged + skipped rather than fanned
    out into the search projection.  ``userAccountControl`` is
    always re-injected since weak-UAC detection requires it.
    """
    if value is None:
        return list(DEFAULT_ATTRIBUTES)
    raw = str(value)
    if _has_control_chars(raw):
        log("LDAP_ATTRIBUTES contains control chars; falling back to defaults")
        return list(DEFAULT_ATTRIBUTES)
    text = raw.strip()
    if not text:
        return list(DEFAULT_ATTRIBUTES)
    out = []
    seen = set()
    for tok in text.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if not re.match(r"\A[A-Za-z][A-Za-z0-9\-_;]{0,64}\Z", tok):
            log(f"LDAP_ATTRIBUTES skipping malformed attribute '{tok}'")
            continue
        if tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
    if "userAccountControl" not in seen:
        out.append("userAccountControl")
    return out


def validate_use_tls(value):
    """Truthy parser for LDAP_USE_TLS.

    Accepts the common bool-string spellings (``true`` /
    ``yes`` / ``on`` / ``1`` / single-char ``y`` / ``t``,
    case-insensitive) -> True.  Anything else -> False.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on", "y", "t"):
        return True
    return False


def parse_uac(value):
    """Coerce a ``userAccountControl`` attribute value into an int.

    ldap3 returns attributes as either a single value or a
    list (single-valued attrs typically arrive as a single
    int; multi-valued attrs as a list).  Tolerate both shapes
    plus the int-shaped-string ldap3 sometimes returns when
    ``raw_attributes`` is the source dict.
    """
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        value = value[0]
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None


def is_weak_uac(uac):
    """Return True for accounts that are *enabled* AND carry at
    least one of the weak UAC flags we audit."""
    if uac is None:
        return False
    if uac & UAC_ACCOUNTDISABLE:
        return False
    return bool(uac & (UAC_PASSWD_NOTREQD | UAC_DONT_EXPIRE_PASSWORD))


def uac_flags(uac):
    """Return the canonical UAC flag names set on ``uac``.

    We only enumerate the three flags this executor audits —
    callers that want the full UAC flag catalogue should read
    the int from the host description.
    """
    if uac is None:
        return []
    flags = []
    if uac & UAC_ACCOUNTDISABLE:
        flags.append("ACCOUNTDISABLE")
    if uac & UAC_PASSWD_NOTREQD:
        flags.append("PASSWD_NOTREQD")
    if uac & UAC_DONT_EXPIRE_PASSWORD:
        flags.append("DONT_EXPIRE_PASSWORD")
    return flags


def severity_for_uac(uac):
    """Map a weak-UAC int onto a Faraday severity slot.

    PASSWD_NOTREQD permits empty-password binds — surfaced as
    ``critical``.  DONT_EXPIRE_PASSWORD alone is a hardening
    defect (the account remains password-protected, just
    indefinitely) — surfaced as ``medium``.
    """
    if uac is None:
        return "info"
    if uac & UAC_PASSWD_NOTREQD:
        return "critical"
    if uac & UAC_DONT_EXPIRE_PASSWORD:
        return "medium"
    return "info"


def _attr(entry_attrs, key):
    """Pull an attribute from an ldap3-shaped attribute dict.

    LDAP attribute names are case-insensitive — when ldap3
    returns ``raw_attributes`` the keys arrive lower-cased,
    so we tolerate both case-folded and original-cased lookups.
    Single-element lists flatten to their member; longer lists
    are returned as-is for callers that want to render them.
    """
    if not isinstance(entry_attrs, dict):
        return None
    if key in entry_attrs:
        v = entry_attrs[key]
    else:
        lower = {k.lower(): val for k, val in entry_attrs.items()}
        v = lower.get(key.lower())
    if v is None:
        return None
    if isinstance(v, list):
        if not v:
            return None
        if len(v) == 1:
            return v[0]
        return v
    return v


def _str(value):
    """Coerce an LDAP attribute value into a stripped str."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace").strip()
        except Exception:  # noqa: BLE001
            return ""
    if isinstance(value, list):
        return ", ".join(_str(x) for x in value if x is not None and _str(x))
    return str(value).strip()


def classify_object(entry_attrs):
    """Return ``user`` / ``group`` / ``computer`` / ``other``.

    Active Directory objectClass is multi-valued; we look at
    the lower-cased class list and prefer the most-specific
    class (``computer`` beats ``user`` / ``person``, ``group``
    beats neither).
    """
    raw = _attr(entry_attrs, "objectClass") or _attr(entry_attrs, "objectclass")
    if isinstance(raw, str):
        classes = [raw]
    elif isinstance(raw, list):
        classes = raw
    else:
        classes = []
    lowered = [str(c).lower() for c in classes]
    if "computer" in lowered:
        return "computer"
    if "group" in lowered:
        return "group"
    if "user" in lowered or "person" in lowered or "organizationalperson" in lowered:
        return "user"
    return "other"


def build_host(dn, entry_attrs):
    """Build a Faraday host record for one LDAP entry.

    Returns ``None`` for entries whose UAC is missing / does
    not match the weak combination (so non-weak entries are
    silently dropped from the output).
    """
    if not isinstance(entry_attrs, dict):
        return None
    uac = parse_uac(_attr(entry_attrs, "userAccountControl"))
    if not is_weak_uac(uac):
        return None

    kind = classify_object(entry_attrs)
    sam = _str(_attr(entry_attrs, "sAMAccountName"))
    cn = _str(_attr(entry_attrs, "cn"))
    primary = sam or cn or dn or "unknown"
    flags = uac_flags(uac)
    weak_flag_str = ", ".join(f for f in flags if f != "ACCOUNTDISABLE") or "weak-UAC"

    desc_parts = []
    for key in (
        "distinguishedName",
        "sAMAccountName",
        "cn",
        "userPrincipalName",
        "objectClass",
        "userAccountControl",
        "memberOf",
        "operatingSystem",
        "operatingSystemVersion",
        "dNSHostName",
        "ipv4Address",
        "displayName",
        "mail",
        "description",
        "whenCreated",
        "whenChanged",
        "lastLogonTimestamp",
        "pwdLastSet",
    ):
        v = _attr(entry_attrs, key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_str(v)}")
    desc_parts.append(f"uac_flags: {flags}")
    desc_parts.append(f"dn: {dn}")

    refs = []
    seen = set()

    def add_ref(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    add_ref(f"LDAP-DN: {dn}")
    if sam:
        add_ref(f"LDAP-sAMAccountName: {sam}")
    upn = _str(_attr(entry_attrs, "userPrincipalName"))
    if upn:
        add_ref(f"LDAP-UPN: {upn}")
    add_ref(f"LDAP-Kind: {kind}")
    add_ref(f"LDAP-UAC: {uac}")
    for f in flags:
        add_ref(f"LDAP-Flag: {f}")

    severity = severity_for_uac(uac)

    vuln = {
        "name": (f"[IDENTITY] LDAP weak userAccountControl: " f"{primary} ({weak_flag_str})")[:200],
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": f"ldap-audit-{dn}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Weak userAccountControl flags expose Active Directory "
            "principals to credential abuse: PASSWD_NOTREQD permits "
            "empty-password binds, and DONT_EXPIRE_PASSWORD lets "
            "long-lived credentials sit indefinitely. Re-enable the "
            "flagged constraint via Active Directory Users and "
            "Computers (or Set-ADUser -PasswordNotRequired $false / "
            "-PasswordNeverExpires $false) and rotate the principal's "
            "password if PASSWD_NOTREQD was set."
        ),
        "data": "",
        "refs": refs,
        "cve": [],
        "cvss3": {},
        "tags": ["ldap", "ldap-audit", "identity", "active-directory", kind],
    }

    if kind == "computer":
        ip = _str(_attr(entry_attrs, "ipv4Address")) or SENTINEL_IP
        hostnames = []
        dnsname = _str(_attr(entry_attrs, "dNSHostName"))
        if dnsname:
            hostnames.append(dnsname)
        if cn and cn not in hostnames:
            hostnames.append(cn)
        os_str = _str(_attr(entry_attrs, "operatingSystem"))
        osver = _str(_attr(entry_attrs, "operatingSystemVersion"))
        os_label = f"{os_str} {osver}".strip() if osver else os_str
    else:
        ip = SENTINEL_IP
        hostnames = []
        if sam:
            hostnames.append(sam)
        if cn and cn not in hostnames:
            hostnames.append(cn)
        os_label = ""

    return {
        "ip": ip,
        "os": os_label,
        "hostnames": hostnames,
        "mac": "",
        "description": f"LDAP {kind} {primary} (UAC={uac})",
        "vulnerabilities": [vuln],
    }


def normalize_entries(response):
    """Normalise an ldap3 search response into ``[(dn, attrs), ...]``.

    ldap3 returns entries as either dicts (``conn.response``
    with ``dn`` / ``attributes`` keys) or Entry objects
    (``conn.entries`` with ``.entry_dn`` /
    ``.entry_attributes_as_dict``).  Tolerate both shapes for
    testability — and skip ``searchResRef`` referral rows
    that ldap3 mixes into ``conn.response``.
    """
    out = []
    if response is None:
        return out
    if not isinstance(response, list):
        try:
            response = list(response)
        except TypeError:
            return out
    for item in response:
        if isinstance(item, dict):
            kind = item.get("type")
            if kind and kind != "searchResEntry":
                continue
            dn = item.get("dn") or item.get("distinguishedName") or ""
            attrs = item.get("attributes") or item.get("raw_attributes") or {}
            if isinstance(attrs, dict):
                out.append((str(dn), attrs))
        else:
            try:
                dn = getattr(item, "entry_dn", None) or ""
                attrs = item.entry_attributes_as_dict
            except Exception:  # noqa: BLE001
                continue
            if isinstance(attrs, dict):
                out.append((str(dn), attrs))
    return out


def make_server(ldap3_module, host, use_tls):
    """Build an ``ldap3.Server`` for the supplied host + tls setting.

    A bare hostname / IP is paired with the default port (389
    plain, 636 SSL).  ``ldap://`` / ``ldaps://`` URL prefixes
    are honoured and override the ``use_tls`` env hint when
    ``ldaps://`` is supplied.  Embedded ``:port`` is split out
    and forwarded explicitly to ``ldap3.Server(port=...)`` so
    on-prem deployments running ldap on non-default ports work.
    """
    text = host
    use_ssl = False
    port = None
    if text.lower().startswith("ldaps://"):
        use_ssl = True
        text = text[len("ldaps://") :]
    elif text.lower().startswith("ldap://"):
        text = text[len("ldap://") :]
    if ":" in text:
        host_only, _, port_str = text.rpartition(":")
        try:
            port = int(port_str)
            text = host_only
        except (TypeError, ValueError):
            pass
    if use_tls:
        use_ssl = True
    return ldap3_module.Server(
        text,
        port=port,
        use_ssl=use_ssl,
        get_info=ldap3_module.NONE,
    )


def perform_search(
    ldap3_module,
    server,
    user,
    password,
    base_dn,
    ldap_filter,
    attributes,
    page_size=DEFAULT_PAGE_SIZE,
    max_pages=MAX_PAGES,
):
    """Bind + paged search; return the raw ldap3 response list.

    Anonymous bind when ``user`` is blank, simple bind
    otherwise.  ``raise_exceptions=False`` so a failed bind
    returns a structured result rather than raising — the
    caller checks ``conn.bound`` and bails out cleanly when
    the credentials are wrong.  Paged-search hit cap is
    ``page_size * max_pages`` (default 500 * 200 = 100 000
    entries) so a stray wide-open filter can't fan out into
    millions of records against a large AD forest.
    """
    auth = ldap3_module.SIMPLE if user else ldap3_module.ANONYMOUS
    conn = ldap3_module.Connection(
        server,
        user=user or None,
        password=password or None,
        authentication=auth,
        auto_bind=True,
        raise_exceptions=False,
    )
    if not getattr(conn, "bound", True):
        log(f"LDAP bind failed: {getattr(conn, 'result', '')}")
        try:
            conn.unbind()
        except Exception:  # noqa: BLE001
            pass
        return []
    try:
        out = []
        hit_cap = page_size * max_pages
        for entry in conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=ldap_filter,
            search_scope=ldap3_module.SUBTREE,
            attributes=attributes,
            paged_size=page_size,
            generator=True,
        ):
            if entry is None:
                continue
            out.append(entry)
            if len(out) >= hit_cap:
                log(f"ldap_audit hit MAX hits={hit_cap}; stopping pagination")
                break
        return out
    finally:
        try:
            conn.unbind()
        except Exception:  # noqa: BLE001
            pass


def main():
    started = time.time()

    base_dn = validate_base_dn(env("EXECUTOR_CONFIG_LDAP_BASE_DN"))
    if not base_dn:
        log("LDAP_BASE_DN is required (e.g. DC=corp,DC=local)")
        sys.exit(1)
    ldap_filter = validate_filter(env("EXECUTOR_CONFIG_LDAP_FILTER"))
    attributes = validate_attributes(env("EXECUTOR_CONFIG_LDAP_ATTRIBUTES"))

    host = validate_host(env("LDAP_HOST", required=True))
    if not host:
        log("LDAP_HOST must be a valid LDAP URL or hostname")
        sys.exit(1)
    user = env("LDAP_USER")
    password = env("LDAP_PASSWORD")
    use_tls = validate_use_tls(env("LDAP_USE_TLS"))

    try:
        import ldap3  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("ldap3 is not installed in the executor environment")
        sys.exit(1)

    try:
        server = make_server(ldap3, host, use_tls)
    except Exception as exc:  # noqa: BLE001
        log(f"LDAP server setup failed: {exc}")
        sys.exit(1)

    try:
        response = perform_search(
            ldap3,
            server,
            user,
            password,
            base_dn,
            ldap_filter,
            attributes,
        )
    except Exception as exc:  # noqa: BLE001
        log(f"LDAP search failed: {exc}")
        sys.exit(1)

    entries = normalize_entries(response)
    log(f"Processing {len(entries)} LDAP entries " f"(base_dn={base_dn!r}, filter={ldap_filter!r}, use_tls={use_tls})")

    hosts_out = []
    for dn, attrs in entries:
        built = build_host(dn, attrs)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "ldap_audit",
            "command": "ldap_audit",
            "params": (
                f"base_dn={base_dn},"
                f"filter={ldap_filter},"
                f"attributes={','.join(attributes)},"
                f"use_tls={use_tls}"
            ),
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
