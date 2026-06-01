#!/usr/bin/env python
"""IriusRisk Threat Modeling importer.

Pulls product + per-product threat records from the IriusRisk
REST API (the platform's documented public surface at
``/api/v1/products`` and ``/api/v1/products/{ref}/threats``) and
emits Faraday bulk-create JSON to stdout.  IriusRisk is a
threat-modeling SaaS — architects build a product model in the
console, the platform's threat library + STRIDE / OWASP / NIST
rule packs auto-populate per-product threats with mapped
weaknesses (CWE) + countermeasures, and the operator's risk
team tracks each threat through the Exposed -> Reviewed ->
Mitigated lifecycle.  This executor surfaces those threats as
Faraday vulnerabilities so the threat-model output joins the
operator's existing host-side scanner output under a single
workspace.

Endpoints used:
  GET {IRIUS_HOST}/api/v1/products?page=N&size=100
      -> Paginated product inventory under the operator's
      tenant.  The canonical IriusRisk v1 envelope is
      ``{"_embedded": {"products": [...]}, "page":
      {"size": N, "totalElements": N, "totalPages": N,
      "number": N}}`` (Spring HATEOAS); some federated /
      mirror stacks collapse this into ``{"products": [...]}``
      or a bare list — both are accepted.  Each product
      record carries ``id``, ``ref`` (operator-chosen slug —
      the natural key the threats endpoint pivots on),
      ``name``, ``description``, ``createdAt``, ``updatedAt``,
      ``state``, optional ``tags``, optional ``productOwner``,
      and optional ``businessUnit``.

  GET {IRIUS_HOST}/api/v1/products/{ref}/threats
      -> The threats attached to one product.  The canonical
      envelope is ``{"_embedded": {"threats": [...]}}`` (or
      ``{"threats": [...]}`` / bare list on mirrors).  Each
      threat carries ``ref`` (IriusRisk's natural threat key),
      ``name``, ``description``, ``riskRating`` (numeric
      0..100), ``riskLevel`` (``Very High`` / ``High`` /
      ``Medium`` / ``Low`` / ``Very Low`` / ``Nothing`` —
      the operator-facing label IriusRisk's rule packs emit),
      ``state`` (``Exposed`` / ``Vulnerable`` / ``Reviewed``
      / ``Mitigated`` / ``NotApplicable`` / ``Rejected``),
      ``category`` (STRIDE / OWASP / NIST classification),
      ``weakness`` (CWE id or list), optional
      ``countermeasures`` (list of mitigation objects with
      ``ref`` + ``name`` + ``state``), optional ``tags``,
      ``createdAt`` / ``updatedAt``.

Auth: IriusRisk uses a per-user API token issued by the
console (User Settings -> API Token -> generate).  The
dispatcher sends the token as the ``api-token: <IRIUS_TOKEN>``
HTTP header on every request — IriusRisk's documented
authentication header (lowercase ``api-token``).

Args:
  ``IRIUS_PRODUCT_REF`` (optional) — a single IriusRisk
  product ``ref`` (the operator-chosen slug) to narrow the
  fetch to.  When set, the executor skips the
  ``/api/v1/products`` walk and goes straight to
  ``/api/v1/products/{ref}/threats``.  When blank / missing
  (the typical operational mode for first-time imports), the
  executor walks ``/api/v1/products`` page-by-page and pulls
  threats for every product the operator's tenant exposes.
  Whitespace is trimmed.

Env vars:
  ``IRIUS_HOST`` (mandatory) — the IriusRisk base URL, e.g.
  ``https://acme.iriusrisk.com`` or the canonical SaaS host
  ``https://eu.iriusrisk.com``.  IriusRisk is a tenant-keyed
  SaaS / on-prem product so there is no global default —
  the executor exits cleanly when ``IRIUS_HOST`` is missing.
  Whitespace is trimmed and ``https://`` is added when the
  operator pasted in a bare FQDN.

  ``IRIUS_TOKEN`` (mandatory) — the per-user API token issued
  by the IriusRisk console.  Forwarded as the
  ``api-token: <...>`` HTTP header on every request.  The
  executor exits cleanly when the token is missing.

Each IriusRisk threat becomes one Faraday vulnerability under
a single synthetic ``0.0.0.0`` host with hostname
``iriusrisk``.  IriusRisk threats are product-keyed not
host-keyed — the operator's other agents emit the host-side
findings this feed is correlated against.  The vulnerability
carries ``tags: ['iriusrisk']`` and surfaces the product ref +
name, the threat ref + name + category, the risk rating +
level + state, the mapped CWE, the countermeasure list +
their states, and the IriusRisk console deep-link in both
the description and the refs list so the operator can pivot
from a Faraday finding back to the exact IriusRisk threat
record.

Severity is bucketed from IriusRisk's published ``riskLevel``:
  - ``Very High`` -> critical
  - ``High``      -> high
  - ``Medium``    -> medium
  - ``Low``       -> low
  - ``Very Low``  -> info
  - ``Nothing``   -> info
Falls back to the numeric ``riskRating`` (0..100) ladder when
``riskLevel`` is missing / unparseable:
  - ``>= 75`` -> critical
  - ``>= 50`` -> high
  - ``>= 25`` -> medium
  - ``> 0``   -> low
  - ``0``     -> info
Threats in the terminal ``Mitigated`` / ``NotApplicable`` /
``Rejected`` states are floored to ``info`` regardless of the
rating ladder (the threat is no longer live).  Records with
no parseable risk default to ``info`` — we don't synthesise a
ranking IriusRisk hasn't published.

Status is always ``open`` (an IriusRisk threat can transition
to ``Mitigated`` in the console but the underlying threat
model entry lives on; Faraday surfaces the finding as open so
the operator's remediation workflow takes over — the Mitigated
state is preserved via the info-severity floor + an explicit
``Irius-State: Mitigated`` pivot).
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

TIMEOUT = 60
PRODUCTS_PATH = "/api/v1/products"
THREATS_PATH_TPL = "/api/v1/products/{ref}/threats"

PRODUCTS_PAGE_SIZE = 100
MAX_PRODUCTS_PAGES = 100
MAX_PRODUCTS = 5000
INTER_REQUEST_SLEEP = 0.3

CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")

# IriusRisk uses both numeric riskRating (0..100) and named
# riskLevel labels in different parts of the v1 surface; we
# accept both forms + operator-friendly aliases.
RISK_LEVEL_ALIASES = {
    "very high": "Very High",
    "veryhigh": "Very High",
    "very-high": "Very High",
    "very_high": "Very High",
    "critical": "Very High",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "med": "Medium",
    "low": "Low",
    "very low": "Very Low",
    "verylow": "Very Low",
    "very-low": "Very Low",
    "very_low": "Very Low",
    "informational": "Very Low",
    "info": "Very Low",
    "nothing": "Nothing",
    "none": "Nothing",
    "n/a": "Nothing",
}

RISK_LEVEL_SEVERITY = {
    "Very High": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Very Low": "info",
    "Nothing": "info",
}

# IriusRisk threat-state vocabulary — the terminal "closed"
# states are floored to ``info`` regardless of the rating
# ladder (the threat is no longer actively in play).
CLOSED_STATES = {
    "mitigated",
    "notapplicable",
    "not applicable",
    "not-applicable",
    "n/a",
    "rejected",
}


def log(msg):
    print(f"{datetime.utcnow()} - IriusRisk: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on IRIUS_HOST.

    IriusRisk is a tenant-keyed SaaS / on-prem product so
    there is no global default — empty / missing / non-string
    inputs return ``""`` (the caller hard-fails with a helpful
    error).  Whitespace is trimmed and ``https://`` is added
    automatically when the operator pasted in a bare FQDN
    (on-prem stacks typically use raw hostnames).
    """
    if not host:
        return ""
    if not isinstance(host, str):
        return ""
    text = host.strip().rstrip("/")
    if not text:
        return ""
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def build_products_url(host, page=0, size=PRODUCTS_PAGE_SIZE):
    """Build the paginated /api/v1/products URL.

    IriusRisk's v1 surface uses Spring's standard ``page=N&
    size=N`` query string with zero-based page indices.  Bad
    inputs (non-int / negative) are coerced to safe defaults
    so a typo never crashes the dispatcher.
    """
    base = normalize_base_url(host)
    try:
        p = int(page)
    except (TypeError, ValueError):
        p = 0
    if p < 0:
        p = 0
    try:
        s = int(size)
    except (TypeError, ValueError):
        s = PRODUCTS_PAGE_SIZE
    if s <= 0:
        s = PRODUCTS_PAGE_SIZE
    query = urlencode([("page", p), ("size", s)])
    return f"{base}{PRODUCTS_PATH}?{query}"


def build_threats_url(host, ref):
    """Build the /api/v1/products/{ref}/threats URL.

    The product ``ref`` is the operator-chosen slug (often
    ``acme-payments`` or ``billing-svc``) so we url-encode it
    to tolerate ``:`` / ``/`` / spaces in the slug without
    breaking the request path.  Empty / non-string refs
    produce an empty path segment so the caller's hard-fail
    surfaces a useful error rather than blindly walking the
    products endpoint.
    """
    base = normalize_base_url(host)
    if ref is None or isinstance(ref, bool):
        encoded = ""
    else:
        encoded = quote(str(ref).strip(), safe="")
    return f"{base}{THREATS_PATH_TPL.format(ref=encoded)}"


def request_headers(token):
    """Build the request-header dict for one IriusRisk GET.

    IriusRisk's documented authentication header is the
    lowercase ``api-token`` — the dispatcher forwards the
    operator-supplied token verbatim.  ``Accept:
    application/json`` is always sent.  Missing / blank
    tokens are coerced to an empty string so the request
    still goes through and the server can return a useful 401.
    """
    token_str = ""
    if isinstance(token, str):
        token_str = token.strip()
    elif token not in (None, False, True):
        token_str = str(token).strip()
    headers = {"Accept": "application/json"}
    if token_str:
        headers["api-token"] = token_str
    return headers


def parse_product_ref(value):
    """Normalise IRIUS_PRODUCT_REF into a non-empty string.

    Returns ``None`` for missing / blank / non-string inputs
    so the caller falls back to the walk-every-product mode.
    Whitespace is trimmed but case is preserved (IriusRisk
    refs are case-sensitive in the v1 surface).
    """
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:  # noqa: BLE001
            return None
    text = value.strip()
    if not text:
        return None
    return text


def normalize_risk_level(value):
    """Coerce a riskLevel string into IriusRisk's canonical label.

    Accepts the canonical title-cased labels (``Very High`` /
    ``High`` / ``Medium`` / ``Low`` / ``Very Low`` /
    ``Nothing``) plus operator-friendly aliases
    (``critical`` -> ``Very High``, ``moderate`` -> ``Medium``,
    ``info`` -> ``Very Low``, ``none`` / ``n/a`` ->
    ``Nothing``).  Returns ``None`` for missing / non-string
    / unknown inputs so the caller falls back to the numeric
    riskRating ladder.
    """
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    alias = RISK_LEVEL_ALIASES.get(text.lower())
    if alias is not None:
        return alias
    if text in RISK_LEVEL_SEVERITY:
        return text
    return None


def parse_risk_rating(value):
    """Parse an IriusRisk numeric riskRating into a float.

    IriusRisk emits ``riskRating`` as either a float
    (``78.5``) or a string (``"78.5"``).  Returns ``None``
    for missing / non-numeric / bool inputs so the caller can
    fall back to the riskLevel ladder.  Negative values are
    clamped to 0.0; values above 100 are clamped to 100.0
    (IriusRisk's documented 0..100 range).
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        rating = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if rating != rating:  # NaN check
        return None
    if rating < 0.0:
        return 0.0
    if rating > 100.0:
        return 100.0
    return rating


def severity_from_risk(risk_level, risk_rating, state=None):
    """Bucket Faraday severity from IriusRisk risk + state.

    Prefers the canonical ``riskLevel`` label when present;
    falls back to the numeric ``riskRating`` 0..100 ladder
    otherwise.  Threats in the terminal Mitigated /
    NotApplicable / Rejected states are floored to ``info``
    regardless of the rating ladder (the threat is no longer
    live).  Returns ``info`` when both risk inputs are
    missing — we don't synthesise a ranking IriusRisk hasn't
    published.
    """
    if is_closed_state(state):
        return "info"
    level = normalize_risk_level(risk_level)
    if level is not None:
        return RISK_LEVEL_SEVERITY.get(level, "info")
    rating = parse_risk_rating(risk_rating)
    if rating is None:
        return "info"
    if rating >= 75.0:
        return "critical"
    if rating >= 50.0:
        return "high"
    if rating >= 25.0:
        return "medium"
    if rating > 0.0:
        return "low"
    return "info"


def is_closed_state(value):
    """True when an IriusRisk threat state is terminally closed."""
    if value is None or isinstance(value, bool):
        return False
    if not isinstance(value, str):
        return False
    return value.strip().lower() in CLOSED_STATES


def parse_iso_datetime(value):
    """Parse an ISO-8601 timestamp into a UTC datetime.

    IriusRisk emits ``createdAt`` / ``updatedAt`` as
    ``YYYY-MM-DDTHH:MM:SSZ`` (or with a numeric offset on
    federated mirrors).  Returns ``None`` for missing /
    malformed inputs.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_products(body):
    """Pull the product list from an IriusRisk products envelope.

    Canonical IriusRisk v1 envelope is Spring HATEOAS:
    ``{"_embedded": {"products": [...]}, "page": {...}}``.
    We also accept ``{"products": [...]}``, ``{"data": [...]}``,
    ``{"results": [...]}``, ``{"items": [...]}``, and a bare
    list for federated / mirror stacks.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    embedded = body.get("_embedded")
    if isinstance(embedded, dict):
        for key in ("products", "productList", "items", "data", "results"):
            v = embedded.get(key)
            if isinstance(v, list):
                return [entry for entry in v if isinstance(entry, dict)]
    for key in ("products", "productList", "items", "data", "results"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_threats(body):
    """Pull the threat list from an IriusRisk threats envelope.

    Canonical envelope is ``{"_embedded": {"threats": [...]}}``
    (Spring HATEOAS).  Falls back to ``{"threats": [...]}``,
    ``{"data": [...]}``, ``{"results": [...]}``, ``{"items":
    [...]}``, and bare-list for federated / mirror stacks.
    """
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    if not isinstance(body, dict):
        return []
    embedded = body.get("_embedded")
    if isinstance(embedded, dict):
        for key in ("threats", "threatList", "items", "data", "results"):
            v = embedded.get(key)
            if isinstance(v, list):
                return [entry for entry in v if isinstance(entry, dict)]
    for key in ("threats", "threatList", "items", "data", "results"):
        v = body.get(key)
        if isinstance(v, list):
            return [entry for entry in v if isinstance(entry, dict)]
    return []


def extract_page_meta(body):
    """Pull Spring HATEOAS page metadata for paged walks.

    Returns whatever ``page`` block fields are present
    (``size`` / ``totalElements`` / ``totalPages`` /
    ``number``).  Returns an empty dict for missing / non-dict
    inputs.  The caller uses ``totalPages`` (when present) to
    bound the walk so a mirror that never returns an empty
    page can't loop forever.
    """
    if not isinstance(body, dict):
        return {}
    page = body.get("page")
    if not isinstance(page, dict):
        return {}
    out = {}
    for key in ("size", "totalElements", "totalPages", "number"):
        v = page.get(key)
        if v in (None, ""):
            continue
        out[key] = v
    return out


def collect_cwes(threat):
    """Pull CWE ids from an IriusRisk threat record.

    IriusRisk emits CWE mappings under ``weakness`` (a single
    CWE id like ``"CWE-79"`` or a list of CWE objects) and
    occasionally under ``cwes`` / ``weaknesses``.  We accept
    the bare-string + bare-int + list-of-strings + list-of-
    dict-with-id-or-ref shapes for resilience.  Returned as a
    deduped list of ``CWE-N`` strings preserving discovery
    order.
    """
    out = []
    seen = set()
    if not isinstance(threat, dict):
        return out

    def add(token):
        if not token:
            return
        match = CWE_RE.search(str(token))
        if not match:
            try:
                num = int(str(token).strip())
                cwe = f"CWE-{num}"
            except (TypeError, ValueError):
                return
        else:
            cwe = f"CWE-{match.group(1)}"
        if cwe in seen:
            return
        seen.add(cwe)
        out.append(cwe)

    for key in ("weakness", "weaknesses", "cwe", "cwes"):
        value = threat.get(key)
        if value is None:
            continue
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    for ident in ("ref", "id", "name", "code"):
                        if ident in item:
                            add(item.get(ident))
                else:
                    add(item)
        elif isinstance(value, dict):
            for ident in ("ref", "id", "name", "code"):
                if ident in value:
                    add(value.get(ident))
        else:
            add(value)
    return out


def collect_cves(threat):
    """Pull any CVE ids surfaced in the threat description / refs.

    IriusRisk threats don't carry a structured CVE field, but
    some operator-curated threats embed a ``CVE-YYYY-N+``
    string in the description / references — we extract those
    with a regex sweep so the Faraday vuln's ``cve`` list is
    populated where possible.  Deduped + uppercased.
    """
    out = []
    seen = set()
    if not isinstance(threat, dict):
        return out
    haystacks = [
        threat.get("name"),
        threat.get("description"),
        threat.get("notes"),
        threat.get("reference"),
        threat.get("references"),
    ]
    for blob in haystacks:
        if blob is None:
            continue
        text = blob if isinstance(blob, str) else str(blob)
        for match in CVE_RE.finditer(text):
            upper = match.group(0).upper()
            if upper in seen:
                continue
            seen.add(upper)
            out.append(upper)
    return out


def collect_countermeasures(threat):
    """Pull the list of countermeasure name + state pairs.

    IriusRisk's countermeasure objects carry ``ref`` +
    ``name`` + ``state`` (``Recommended`` / ``Implemented`` /
    ``Required`` / ``Rejected``).  Returns a list of
    ``"<name> [state]"`` strings preserving discovery order so
    operators can pivot back to the IriusRisk console.
    """
    out = []
    if not isinstance(threat, dict):
        return out
    raw = threat.get("countermeasures") or threat.get("controls")
    if not isinstance(raw, list):
        return out
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("ref") or entry.get("id")
        if not name:
            continue
        state = entry.get("state") or entry.get("status")
        label = str(name).strip()
        if state:
            label = f"{label} [{state}]"
        if label not in out:
            out.append(label)
    return out


def product_console_url(host, product_ref):
    """Build a best-effort IriusRisk console deep-link for a product.

    IriusRisk's console UI surfaces products under
    ``/productLandingPage/{ref}`` (the operator-facing
    landing-page URL); we url-encode the ref so slugs with
    spaces / slashes still produce a clickable URL.  Returns
    ``""`` for missing host / ref so the caller can decide
    whether to add the ref or not.
    """
    base = normalize_base_url(host)
    if not base or not product_ref:
        return ""
    encoded = quote(str(product_ref).strip(), safe="")
    return f"{base}/productLandingPage/{encoded}"


def collect_refs(threat, product, host):
    """Build the refs list for one IriusRisk threat.

    Includes the IriusRisk console deep-link for the product,
    the canonical NVD CVE permalink for any CVE ids surfaced
    in the description, and explicit ``Irius-*`` pivots
    (product ref / name, threat ref / name, riskRating /
    riskLevel / state / category, mapped CWE, and the
    countermeasure list) so operators can pivot from a
    Faraday finding back to the exact IriusRisk threat record.
    """
    refs = []
    seen = set()

    def add(text, ref_type="other"):
        if not text:
            return
        s = str(text).strip()
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": ref_type})

    if not isinstance(threat, dict):
        return refs
    product = product if isinstance(product, dict) else {}

    p_ref = str(product.get("ref") or "").strip()
    p_name = str(product.get("name") or "").strip()
    if p_ref:
        url = product_console_url(host, p_ref)
        if url:
            add(url)
        add(f"Irius-ProductRef: {p_ref}")
    if p_name:
        add(f"Irius-ProductName: {p_name}")

    t_ref = str(threat.get("ref") or "").strip()
    t_name = str(threat.get("name") or "").strip()
    if t_ref:
        add(f"Irius-ThreatRef: {t_ref}")
    if t_name:
        add(f"Irius-ThreatName: {t_name}")

    risk_level = normalize_risk_level(threat.get("riskLevel"))
    if risk_level:
        add(f"Irius-RiskLevel: {risk_level}")
    rating = parse_risk_rating(threat.get("riskRating"))
    if rating is not None:
        add(f"Irius-RiskRating: {rating}")
    state = threat.get("state")
    if isinstance(state, str) and state.strip():
        add(f"Irius-State: {state.strip()}")
    category = threat.get("category")
    if isinstance(category, str) and category.strip():
        add(f"Irius-Category: {category.strip()}")
    elif isinstance(category, dict):
        cat_name = category.get("name") or category.get("ref")
        if cat_name:
            add(f"Irius-Category: {cat_name}")

    for cwe in collect_cwes(threat):
        add(f"Irius-CWE: {cwe}")

    for cm in collect_countermeasures(threat):
        add(f"Irius-Countermeasure: {cm}")

    for cve in collect_cves(threat):
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    return refs


def threat_external_id(threat, product):
    """Build a stable Faraday external_id for one IriusRisk threat.

    Combines the product ref + threat ref so a Faraday
    workspace that imports IriusRisk for many products
    doesn't collide two threats with the same ref under
    different products.  Falls back to the threat name when
    refs are missing.
    """
    product = product if isinstance(product, dict) else {}
    threat = threat if isinstance(threat, dict) else {}
    p_ref = str(product.get("ref") or "").strip()
    t_ref = str(threat.get("ref") or "").strip()
    if p_ref and t_ref:
        return f"{p_ref}::{t_ref}"
    if t_ref:
        return t_ref
    name = str(threat.get("name") or "").strip()
    return name or "iriusrisk-threat"


def build_vulnerability(threat, product, host):
    """Build a Faraday vulnerability dict for one IriusRisk threat."""
    if not isinstance(threat, dict):
        return None

    product = product if isinstance(product, dict) else {}
    p_name = str(product.get("name") or product.get("ref") or "").strip()
    p_ref = str(product.get("ref") or "").strip()

    t_name = str(threat.get("name") or "").strip()
    t_ref = str(threat.get("ref") or "").strip()
    risk_level = normalize_risk_level(threat.get("riskLevel"))
    rating = parse_risk_rating(threat.get("riskRating"))
    state = threat.get("state") if isinstance(threat.get("state"), str) else None
    severity = severity_from_risk(threat.get("riskLevel"), threat.get("riskRating"), state)

    title_parts = []
    if p_name:
        title_parts.append(p_name)
    if t_name:
        title_parts.append(t_name)
    elif t_ref:
        title_parts.append(t_ref)
    raw_name = " :: ".join(title_parts) if title_parts else "IriusRisk threat"
    name = f"[IriusRisk] {raw_name}"

    description = str(threat.get("description") or "").strip()
    desc_parts = []
    if description:
        desc_parts.append(description)
    if p_name or p_ref:
        desc_parts.append(f"product: {p_name or p_ref}")
    if t_ref:
        desc_parts.append(f"threatRef: {t_ref}")
    category = threat.get("category")
    if isinstance(category, str) and category.strip():
        desc_parts.append(f"category: {category.strip()}")
    elif isinstance(category, dict):
        cat_name = category.get("name") or category.get("ref")
        if cat_name:
            desc_parts.append(f"category: {cat_name}")
    if risk_level:
        desc_parts.append(f"riskLevel: {risk_level}")
    if rating is not None:
        desc_parts.append(f"riskRating: {rating}")
    if state:
        desc_parts.append(f"state: {state}")
    cwes = collect_cwes(threat)
    if cwes:
        desc_parts.append(f"cwe: {', '.join(cwes)}")
    countermeasures = collect_countermeasures(threat)
    if countermeasures:
        desc_parts.append("countermeasures: " + "; ".join(countermeasures))

    if is_closed_state(state):
        resolution = (
            f"IriusRisk has marked this threat as {state}. No further "
            "remediation action is required in IriusRisk; verify the "
            "mitigation is reflected on the affected hosts before "
            "closing the Faraday finding."
        )
    elif countermeasures:
        resolution = (
            "Apply the IriusRisk-recommended countermeasures listed "
            "below and update the threat state in the IriusRisk console "
            "once verified."
        )
    else:
        resolution = (
            "Review the threat in the IriusRisk console, attach "
            "appropriate countermeasures from the threat library, and "
            "transition the state from Exposed -> Reviewed -> Mitigated."
        )

    external_id = threat_external_id(threat, product)

    return {
        "name": str(name).strip()[:200] or "IriusRisk threat",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution,
        "data": "",
        "refs": collect_refs(threat, product, host),
        "cve": collect_cves(threat),
        "cwe": cwes,
        "cvss3": {},
        "tags": ["iriusrisk"],
    }


def build_host(vulns, host, product_count, narrow_ref=None):
    """Build the single synthetic host that carries every IriusRisk vuln.

    IriusRisk threats are product-keyed not host-keyed (the
    operator's other agents emit the host-side findings this
    feed is correlated against) so we collapse the whole
    fetch under one synthetic ``0.0.0.0`` host with hostname
    ``iriusrisk``.  The host description carries the
    canonical host URL + product count + (optionally) the
    narrowed product ref so operators can pivot from the
    host page back to the exact IriusRisk fetch.
    """
    desc_parts = ["source=iriusrisk"]
    base = normalize_base_url(host)
    if base:
        desc_parts.append(f"host={base}")
    if narrow_ref:
        desc_parts.append(f"product_ref={narrow_ref}")
    try:
        desc_parts.append(f"products={int(product_count)}")
    except (TypeError, ValueError):
        desc_parts.append("products=?")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["iriusrisk"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_url(requests_module, url, headers):
    """GET a single IriusRisk URL and return the parsed JSON body.

    Network / HTTP / JSON errors are logged but never raised
    upstream so a transient IriusRisk outage doesn't crash the
    dispatcher.  Returns ``None`` on any failure; the caller
    is expected to treat that as "no records" and continue.
    """
    try:
        resp = requests_module.get(url, timeout=TIMEOUT, headers=headers)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"IriusRisk record not found at {url} (404)")
        return None
    if resp.status_code == 401 or resp.status_code == 403:
        log(f"IriusRisk auth failed ({resp.status_code}) for {url}: " "check IRIUS_TOKEN")
        return None
    if resp.status_code >= 400:
        log(f"IriusRisk request failed ({resp.status_code}) for {url}: " f"{resp.text[:500]}")
        return None
    try:
        return resp.json()
    except ValueError:
        log(f"IriusRisk response was not JSON ({url})")
        return None


def fetch_products(
    requests_module,
    host,
    headers,
    sleep_fn=time.sleep,
    page_size=PRODUCTS_PAGE_SIZE,
    max_pages=MAX_PRODUCTS_PAGES,
    max_products=MAX_PRODUCTS,
):
    """Walk /api/v1/products page-by-page and return the product list.

    Pagination follows Spring's standard ``page=N&size=N``
    pattern; we break when (1) the page comes back empty,
    (2) ``totalPages`` (when present) is exhausted, (3)
    ``max_products`` (5000) is hit, or (4) ``max_pages`` (100)
    is hit.  ``sleep_fn`` is injectable to keep unit tests
    fast.
    """
    out = []
    for page in range(max_pages):
        if page > 0 and INTER_REQUEST_SLEEP > 0:
            sleep_fn(INTER_REQUEST_SLEEP)
        url = build_products_url(host, page=page, size=page_size)
        body = fetch_url(requests_module, url, headers)
        if body is None:
            break
        batch = extract_products(body)
        if not batch:
            break
        out.extend(batch)
        if len(out) >= max_products:
            log(f"IriusRisk product walk hit max_products={max_products}; " "truncating")
            break
        meta = extract_page_meta(body)
        total_pages = meta.get("totalPages")
        if isinstance(total_pages, int) and page + 1 >= total_pages:
            break
    return out


def fetch_threats(requests_module, host, product_ref, headers):
    """Walk /api/v1/products/{ref}/threats and return the threat list.

    IriusRisk's threats endpoint does not paginate in the v1
    surface — every threat for a product fits in a single
    response — so this is a single GET.  Returns an empty list
    on any failure (the caller continues with the next
    product).
    """
    if not product_ref:
        return []
    url = build_threats_url(host, product_ref)
    body = fetch_url(requests_module, url, headers)
    if body is None:
        return []
    return extract_threats(body)


def main():
    started = time.time()

    host = env("IRIUS_HOST", required=True)
    token = env("IRIUS_TOKEN", required=True)
    product_ref = parse_product_ref(env("EXECUTOR_CONFIG_IRIUS_PRODUCT_REF"))

    base = normalize_base_url(host)
    if not base:
        log("IRIUS_HOST is empty after normalisation; cannot proceed")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = request_headers(token)

    if product_ref:
        products = [{"ref": product_ref, "name": product_ref}]
        log(f"IriusRisk narrowed to product_ref={product_ref}")
    else:
        products = fetch_products(requests, host, headers)
        log(f"IriusRisk discovered {len(products)} products")

    vulns = []
    for product in products:
        if not isinstance(product, dict):
            continue
        p_ref = str(product.get("ref") or "").strip()
        if not p_ref:
            continue
        threats = fetch_threats(requests, host, p_ref, headers)
        for threat in threats:
            vuln = build_vulnerability(threat, product, host)
            if vuln is not None:
                vulns.append(vuln)

    log(
        f"Processed {len(vulns)} IriusRisk threats "
        f"(products={len(products)}, "
        f"product_ref={product_ref or '(walk all)'})"
    )

    hosts_out = [build_host(vulns, host, len(products), narrow_ref=product_ref)]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "iriusrisk",
            "command": "iriusrisk",
            "params": f"product_ref={product_ref or ''} products={len(products)}",
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
