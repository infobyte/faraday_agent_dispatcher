#!/usr/bin/env python
"""CERT-IST advisory feed importer.

Pulls advisories from the CERT-IST (Computer Emergency
Response Team — Industry, Services and Tertiary)
RSS/Atom feed at ``https://www.cert-ist.com/public/
avis/`` and emits Faraday bulk-create JSON to stdout.
CERT-IST is the French commercial CERT that publishes
vendor-vetted advisories tracked against affected
products + canonical CVE ids; their feed is the
canonical "what just got disclosed that I should know
about" channel for French-speaking enterprises and
the wider francophone defensive-engineering market.

Endpoint used:
  GET {CERTIST_HOST}/public/avis/rss/feed.xml
      ?fromDate=YYYY-MM-DD
      -> Returns either an RSS 2.0 envelope
      (``<rss><channel><item>...</item></channel></rss>``)
      or an Atom 1.0 envelope
      (``<feed xmlns="http://www.w3.org/2005/Atom">
      <entry>...</entry></feed>``).  Each advisory
      carries ``<title>`` (typically of the form
      ``CERT-IST/AV-YYYY.NNN — <vendor> <product>
      <impact>``), ``<link>`` (canonical advisory
      permalink — ``/public/avis/AV-YYYY.NNN``),
      ``<description>`` / ``<summary>`` (free-text
      analyst description listing affected products,
      severity, and remediation), ``<pubDate>`` (RSS,
      RFC-822) or ``<published>`` (Atom, ISO-8601),
      ``<guid>`` (RSS) or ``<id>`` (Atom) — the
      canonical AV-YYYY.NNN advisory id — and
      optional ``<category>`` tags (CERT-IST surfaces
      severity + vendor as category-level analyst
      labels).

  CERT-IST does not publish a structured per-advisory
  JSON endpoint; the feed is the authoritative
  programmatic surface and the same advisory text is
  re-rendered by the web UI under ``/public/avis/
  AV-YYYY.NNN``.

Auth: CERT-IST advisory access is subscription-gated.
The public RSS endpoint exposes title + link +
publication date only; the full advisory body
(affected products + severity + remediation text) is
only returned when ``Authorization: Bearer
<CERTIST_API_KEY>`` is sent on the request — the
subscriber's API key is issued by CERT-IST after
contract sign-off and pasted into ``CERTIST_API_KEY``.
The executor exits cleanly when ``CERTIST_API_KEY``
is missing (we don't try to walk the public preview —
its analytical value is too low to justify the noise).

Args:
  ``CERTIST_FROM_DATE`` (optional) — YYYY-MM-DD lower
  bound on the advisory publication date.  Forwarded
  server-side as the ``fromDate=`` query parameter so
  the CERT-IST feed itself does the date narrowing;
  also applied client-side after the parse as a
  belt-and-braces guard against mirrors / proxies
  that don't honour the query string.  Blank /
  missing / unparseable input walks the whole feed
  (the typical first-run operational mode).
  Whitespace is trimmed.

Env vars:
  ``CERTIST_HOST`` (optional) — defaults to
  ``https://www.cert-ist.com`` (the canonical CERT-IST
  host).  Settable to a customer-mirror / offline
  cache.  Whitespace is trimmed and ``https://`` is
  added when the operator pasted in a bare FQDN.

  ``CERTIST_API_KEY`` (mandatory) — the Bearer token
  CERT-IST issues to subscribers.  Sent as
  ``Authorization: Bearer <key>`` on every request.

Each advisory becomes one Faraday vulnerability per
affected product.  When an advisory lists no products
(rare — typically only happens on cross-cutting
process / methodology advisories) we emit one vuln
for the advisory itself.  All vulns from a given
advisory share the same advisory id, CVE list, pub-
date, link, and severity; only the product-specific
fragment differs.  All vulns sit under a single
synthetic ``0.0.0.0`` host with hostname
``cert-ist`` (CERT-IST advisories are CVE-keyed not
host-keyed — the operator's other agents emit the
host-side findings this feed is correlated against),
tagged exactly ``[cert-ist]`` per the playbook spec.

Vulnerability names carry a ``[CERT-IST]`` engine
prefix so operators can filter the feed independently
in the Faraday UI.  The canonical advisory id (e.g.
``AV-2024.123``) is used as ``external_id`` (with a
``::<product-slug>`` suffix when an advisory spawns
multiple per-product vulns so records don't collide).

Severity ladder (analyst-published CERT-IST label
mapped to Faraday's ladder):
  - ``critique`` / ``critical``        -> critical
  - ``majeure``  / ``major`` / ``high``-> high
  - ``modere``   / ``moyenne`` / ``moderate`` /
    ``medium``                         -> medium
  - ``mineure``  / ``faible`` / ``low``-> low
  - missing / unknown                  -> medium
    (the conservative default — CERT-IST advisories
    are vendor-vetted disclosures so the floor is
    medium, not info; analysts can downgrade in the
    Faraday workspace once triage is complete)

Status is always ``open`` (an advisory cannot be
'fixed' upstream — it can only be remediated on the
affected hosts).  Resolution defaults to the
advisory's analyst-recommended remediation text when
present, falling back to a generic ``"Apply vendor
patches for <product or CVE> per the CERT-IST
advisory <id> remediation guidance."`` when the feed
omits a remediation section.

Refs include the canonical CERT-IST advisory deep-
link (``https://www.cert-ist.com/public/avis/
AV-YYYY.NNN``), the canonical NVD CVE permalink for
every CVE surfaced in the title / description /
category list, and explicit ``Certist-AdvisoryID`` /
``Certist-Title`` / ``Certist-PubDate`` / ``Certist-
Severity`` / ``Certist-Product`` / ``Certist-Vendor``
/ ``Certist-Category`` / ``Certist-CVE`` /
``Certist-FromDate`` pivots so operators can pivot
from a Faraday finding back to the exact advisory
field set.
"""

import json
import os
import re
import socket
import sys
import time
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlencode

TIMEOUT = 60

DEFAULT_HOST = "https://www.cert-ist.com"
FEED_PATH = "/public/avis/rss/feed.xml"
ADVISORY_PATH = "/public/avis"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
ADVISORY_ID_RE = re.compile(r"AV[-/](\d{4})[.-](\d{3,4})", re.IGNORECASE)

ATOM_NS = "{http://www.w3.org/2005/Atom}"

# CERT-IST publishes advisory severity in French + English
# variants ("critique" / "majeure" / "moderee" / "mineure" /
# "faible") under either a ``<category>`` tag or a "Severity:"
# / "Gravite:" line in the description.  The lookup is
# normalized (accent-stripped, whitespace-trimmed, lower-case)
# before the map is consulted so "Modérée" / "Modere" /
# " moderate " all collapse to the same bucket.
SEVERITY_MAP = {
    "critique": "critical",
    "critical": "critical",
    "severe": "critical",
    "majeure": "high",
    "major": "high",
    "high": "high",
    "haute": "high",
    "elevee": "high",
    "moderee": "medium",
    "moderate": "medium",
    "moyenne": "medium",
    "medium": "medium",
    "moyen": "medium",
    "mineure": "low",
    "minor": "low",
    "low": "low",
    "faible": "low",
    "basse": "low",
    "info": "info",
    "informational": "info",
    "informationnelle": "info",
    "informative": "info",
}

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")
DEFAULT_SEVERITY = "medium"

# Regex for the inline "Affected product(s):" / "Produits
# affectes:" section CERT-IST embeds in the advisory body.
# Matches both the French + English labels and captures
# everything up to the next labelled section (Severity /
# Remediation / Reference) or the end of the body.
PRODUCT_SECTION_RE = re.compile(
    r"(?:produits?\s+(?:affect[ée]s?|concern[ée]s?)|affected\s+products?)\s*[:\-]\s*"
    r"(?P<body>.+?)"
    r"(?=\n\s*(?:gravit[ée]|s[ée]v[ée]rit[ée]|severity|remediation|"
    r"correction|solution|reference|r[ée]f[ée]rence|cve|cvss)\s*[:\-]|\Z)",
    re.IGNORECASE | re.DOTALL,
)

# Severity sniff for the inline "Severity: ..." line CERT-IST
# also surfaces in the body when the category vocabulary
# wasn't published on the item itself.
SEVERITY_LINE_RE = re.compile(
    r"(?:gravit[ée]|s[ée]v[ée]rit[ée]|severity|impact)\s*[:\-]\s*(?P<value>[^\n\r]+)",
    re.IGNORECASE,
)

# Remediation sniff for the inline "Remediation:" / "Solution:"
# / "Correction:" line CERT-IST surfaces below the affected-
# product block.
REMEDIATION_LINE_RE = re.compile(
    r"(?:rem[ée]diation|remediation|correction|solution|patch|mitigation)\s*[:\-]\s*"
    r"(?P<body>.+?)"
    r"(?=\n\s*(?:gravit[ée]|s[ée]v[ée]rit[ée]|severity|reference|r[ée]f[ée]rence|cve|cvss)\s*[:\-]|\Z)",
    re.IGNORECASE | re.DOTALL,
)


def log(msg):
    print(f"{datetime.utcnow()} - CertIst: {msg}", file=sys.stderr, flush=True)


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


def normalize_base_url(host):
    """Trim trailing slash + tolerate operator typos on CERTIST_HOST.

    Defaults to ``https://www.cert-ist.com`` (the canonical
    CERT-IST host) when the env override is missing / blank /
    non-string.  Whitespace is trimmed and ``https://`` is
    added automatically when the operator pasted in a bare
    FQDN (mirror / customer-cache stacks typically use raw
    hostnames).
    """
    if not host:
        return DEFAULT_HOST
    if not isinstance(host, str):
        return DEFAULT_HOST
    text = host.strip().rstrip("/")
    if not text:
        return DEFAULT_HOST
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def parse_iso_date(value):
    """Parse a YYYY-MM-DD (or full ISO 8601) string into a ``date``.

    Returns ``None`` for non-string / unparseable / bool
    inputs.  CERT-IST emits ``<published>`` as canonical
    ISO 8601 on the Atom envelope; the RSS envelope uses
    RFC-822 which is handled by ``parse_rfc822_date()``.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    text = str(value).strip()
    if not text:
        return None
    head = text[:10]
    try:
        return datetime.strptime(head, "%Y-%m-%d").date()
    except ValueError:
        return None


def parse_rfc822_date(value):
    """Parse an RFC-822 / RFC-2822 timestamp into a ``date``.

    RSS 2.0 emits ``<pubDate>`` in RFC-822 format
    (``Thu, 30 May 2024 08:00:00 GMT``).  Falls back to
    ``parse_iso_date()`` when the RFC-822 parse fails so
    federated / mirror feeds that re-emit ISO timestamps
    are still readable.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return parse_iso_date(text)
    if dt is None:
        return parse_iso_date(text)
    return dt.date()


def validate_from_date(value):
    """Validate CERTIST_FROM_DATE (YYYY-MM-DD).

    None / blank / unparseable -> ``None`` (no filtering —
    the whole feed is walked).  Whitespace is trimmed.
    The validated date is forwarded server-side via the
    ``fromDate=`` query parameter AND applied client-side
    after the parse as a belt-and-braces guard against
    mirrors that don't honour the query string.
    """
    if value is None or value == "":
        return None
    parsed = parse_iso_date(value)
    if parsed is None:
        log(f"CERTIST_FROM_DATE '{value}' is not a YYYY-MM-DD date; " "ignoring (the whole feed will be walked)")
        return None
    return parsed


def normalize_api_key(value):
    """Coerce CERTIST_API_KEY into a stripped string."""
    if value is None or isinstance(value, bool):
        return ""
    if not isinstance(value, str):
        return ""
    return value.strip()


def build_feed_url(host, from_date=None):
    """Build the canonical CERT-IST RSS/Atom feed URL.

    Forwards ``CERTIST_FROM_DATE`` server-side as the
    ``fromDate=YYYY-MM-DD`` query parameter; CERT-IST
    documents this knob as the only server-side narrowing
    lever on the public feed.  Missing / unparseable dates
    walk the whole feed (no query string).
    """
    base = normalize_base_url(host)
    if from_date is None:
        return f"{base}{FEED_PATH}"
    if isinstance(from_date, datetime):
        from_date = from_date.date()
    if isinstance(from_date, date):
        params = [("fromDate", from_date.isoformat())]
        return f"{base}{FEED_PATH}?{urlencode(params)}"
    text = str(from_date).strip()
    if not text:
        return f"{base}{FEED_PATH}"
    params = [("fromDate", text)]
    return f"{base}{FEED_PATH}?{urlencode(params)}"


def build_advisory_link(host, advisory_id):
    """Build the canonical /public/avis/<advisory-id> permalink."""
    base = normalize_base_url(host)
    aid = advisory_id.strip() if isinstance(advisory_id, str) else ""
    if not aid:
        return f"{base}{ADVISORY_PATH}"
    return f"{base}{ADVISORY_PATH}/{aid}"


def request_headers(api_key):
    """Build the request-header dict for one CERT-IST GET.

    CERT-IST issues subscriber API keys as opaque tokens
    sent via ``Authorization: Bearer <key>``.  Accept is
    always ``application/rss+xml, application/atom+xml,
    application/xml`` so the server picks the variant the
    operator's subscription tier exposes.  Missing / blank
    keys yield an empty Authorization header (the executor
    exits before that path in normal operation; this is
    purely a safety net for the helper-test surface).
    """
    key = normalize_api_key(api_key)
    headers = {
        "Accept": ("application/rss+xml, application/atom+xml, " "application/xml;q=0.9, */*;q=0.5"),
        "User-Agent": "Faraday-CERT-IST-Importer/1.0",
    }
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


def strip_accents(text):
    """Strip common French accents for severity normalisation."""
    if not isinstance(text, str):
        return ""
    table = str.maketrans(
        {
            "é": "e",
            "è": "e",
            "ê": "e",
            "ë": "e",
            "à": "a",
            "â": "a",
            "ä": "a",
            "î": "i",
            "ï": "i",
            "ô": "o",
            "ö": "o",
            "ù": "u",
            "û": "u",
            "ü": "u",
            "ç": "c",
            "É": "E",
            "È": "E",
            "Ê": "E",
            "Ë": "E",
            "À": "A",
            "Â": "A",
            "Ä": "A",
            "Î": "I",
            "Ï": "I",
            "Ô": "O",
            "Ö": "O",
            "Ù": "U",
            "Û": "U",
            "Ü": "U",
            "Ç": "C",
        }
    )
    return text.translate(table)


def normalize_severity_label(value):
    """Lower-case + accent-strip a severity string for the SEVERITY_MAP lookup."""
    if not isinstance(value, str):
        return ""
    return strip_accents(value).strip().lower()


def severity_from_label(label):
    """Map a CERT-IST severity label onto Faraday's ladder.

    Unknown / blank labels yield ``DEFAULT_SEVERITY`` (medium)
    — CERT-IST advisories are vendor-vetted disclosures so
    the floor is medium, not info.
    """
    key = normalize_severity_label(label)
    if not key:
        return DEFAULT_SEVERITY
    return SEVERITY_MAP.get(key, DEFAULT_SEVERITY)


def parse_feed(body):
    """Parse a CERT-IST RSS or Atom XML body into a list of items.

    Both RSS 2.0 (``<rss><channel><item>``) and Atom 1.0
    (``<feed><entry>``) envelopes are tolerated; the
    parser dispatches on the root element tag.  Malformed
    XML yields an empty list (logged) — a CERT-IST outage
    must not crash the dispatcher.
    """
    if body is None:
        return []
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 — surface decode failure
            return []
    if not isinstance(body, str) or not body.strip():
        return []
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        log(f"feed parse error: {exc}")
        return []
    tag = root.tag.lower()
    items = []
    if tag.endswith("rss") or tag == "rss":
        # RSS 2.0: rss/channel/item
        for channel in root.findall("channel"):
            for item in channel.findall("item"):
                items.append(parse_rss_item(item))
    elif tag.endswith("feed"):
        # Atom 1.0: feed/entry
        for entry in root.findall(f"{ATOM_NS}entry"):
            items.append(parse_atom_entry(entry))
        # Some feeds skip the namespace; fall back to bare ``entry``.
        if not items:
            for entry in root.findall("entry"):
                items.append(parse_atom_entry(entry))
    else:
        # Some mirror stacks wrap items directly under the root.
        for item in root.findall("item"):
            items.append(parse_rss_item(item))
        for entry in root.findall(f"{ATOM_NS}entry"):
            items.append(parse_atom_entry(entry))
    return [item for item in items if item]


def _element_text(element, tag, ns=""):
    """Return the stripped text of a child element, or ''."""
    if element is None:
        return ""
    child = element.find(f"{ns}{tag}")
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def _element_text_any(element, *tags):
    """Return the first non-empty child text across the candidate tags."""
    if element is None:
        return ""
    for tag in tags:
        child = element.find(tag)
        if child is not None and child.text and child.text.strip():
            return child.text.strip()
    return ""


def parse_rss_item(element):
    """Parse one ``<item>`` from an RSS 2.0 envelope into a dict."""
    if element is None:
        return None
    title = _element_text(element, "title")
    link = _element_text(element, "link")
    description = _element_text(element, "description")
    pub_date = _element_text(element, "pubDate")
    guid = _element_text(element, "guid")
    categories = []
    for cat in element.findall("category"):
        if cat is not None and cat.text and cat.text.strip():
            categories.append(cat.text.strip())
    if not title and not link and not guid:
        return None
    return {
        "title": title,
        "link": link,
        "description": description,
        "pub_date": pub_date,
        "guid": guid,
        "categories": categories,
        "format": "rss",
    }


def parse_atom_entry(element):
    """Parse one ``<entry>`` from an Atom 1.0 envelope into a dict."""
    if element is None:
        return None
    title = _element_text(element, "title", ns=ATOM_NS) or _element_text(element, "title")
    summary = (
        _element_text(element, "summary", ns=ATOM_NS)
        or _element_text(element, "content", ns=ATOM_NS)
        or _element_text(element, "summary")
        or _element_text(element, "content")
    )
    published = (
        _element_text(element, "published", ns=ATOM_NS)
        or _element_text(element, "updated", ns=ATOM_NS)
        or _element_text(element, "published")
        or _element_text(element, "updated")
    )
    entry_id = _element_text(element, "id", ns=ATOM_NS) or _element_text(element, "id")
    link = ""
    for child in element.findall(f"{ATOM_NS}link"):
        href = child.get("href")
        if href and href.strip():
            link = href.strip()
            break
    if not link:
        for child in element.findall("link"):
            href = child.get("href")
            if href and href.strip():
                link = href.strip()
                break
            if child.text and child.text.strip():
                link = child.text.strip()
                break
    categories = []
    for cat in element.findall(f"{ATOM_NS}category"):
        term = cat.get("term") or cat.get("label")
        if term and term.strip():
            categories.append(term.strip())
    for cat in element.findall("category"):
        term = cat.get("term") or cat.get("label")
        if term and term.strip():
            categories.append(term.strip())
        elif cat.text and cat.text.strip():
            categories.append(cat.text.strip())
    if not title and not link and not entry_id:
        return None
    return {
        "title": title,
        "link": link,
        "description": summary,
        "pub_date": published,
        "guid": entry_id,
        "categories": categories,
        "format": "atom",
    }


def extract_advisory_id(item):
    """Pull the canonical CERT-IST advisory id (e.g. ``AV-2024.123``).

    Search order: the ``guid`` field, the trailing path
    segment of the canonical advisory link, the title.
    Returns an upper-cased ``AV-YYYY.NNN`` token; falls
    back to the ``guid`` / ``link`` / ``title`` raw text
    when no AV-token is found.
    """
    if not isinstance(item, dict):
        return ""
    for key in ("guid", "link", "title"):
        text = item.get(key)
        if not isinstance(text, str) or not text.strip():
            continue
        match = ADVISORY_ID_RE.search(text)
        if match:
            year, num = match.group(1), match.group(2)
            return f"AV-{year}.{num}"
    guid = item.get("guid")
    if isinstance(guid, str) and guid.strip():
        return guid.strip()
    link = item.get("link")
    if isinstance(link, str) and link.strip():
        tail = link.rstrip("/").split("/")[-1]
        return tail.strip()
    title = item.get("title")
    if isinstance(title, str) and title.strip():
        return title.strip()[:64]
    return ""


def extract_publish_date(item):
    """Parse the advisory publication date (RSS or Atom)."""
    if not isinstance(item, dict):
        return None
    raw = item.get("pub_date")
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    # Atom timestamps are ISO 8601; RSS are RFC-822.
    fmt = item.get("format")
    if fmt == "atom":
        d = parse_iso_date(text)
        if d is not None:
            return d
        return parse_rfc822_date(text)
    d = parse_rfc822_date(text)
    if d is not None:
        return d
    return parse_iso_date(text)


def collect_cves(item):
    """Pull CVE ids from title + description + category list.

    CERT-IST surfaces CVEs as free-text mentions in the
    advisory body and (often) in the category list.
    Returns a deduped upper-cased list preserving the
    discovery order.
    """
    out = []
    seen = set()
    if not isinstance(item, dict):
        return out

    def harvest(text):
        if not isinstance(text, str):
            return
        for match in CVE_RE.findall(text):
            cve = match.upper()
            if cve in seen:
                continue
            seen.add(cve)
            out.append(cve)

    harvest(item.get("title"))
    harvest(item.get("description"))
    cats = item.get("categories")
    if isinstance(cats, list):
        for entry in cats:
            harvest(entry)
    return out


def extract_severity_label(item):
    """Pull the analyst-published CERT-IST severity label.

    Search order: the category list (where CERT-IST tags
    the published severity vocabulary), the inline
    "Severity: ..." line in the description body, and the
    title (some advisories surface ``[Critique]`` /
    ``[Major]`` prefixes in the title).  Returns an empty
    string when nothing matches — the caller maps that to
    ``DEFAULT_SEVERITY``.
    """
    if not isinstance(item, dict):
        return ""

    cats = item.get("categories")
    if isinstance(cats, list):
        for entry in cats:
            if not isinstance(entry, str):
                continue
            key = normalize_severity_label(entry)
            if key in SEVERITY_MAP:
                return entry.strip()

    description = item.get("description")
    if isinstance(description, str) and description.strip():
        match = SEVERITY_LINE_RE.search(description)
        if match:
            value = match.group("value").strip()
            if value:
                first_token = value.split()[0] if value.split() else value
                key = normalize_severity_label(first_token)
                if key in SEVERITY_MAP:
                    return first_token
                return value

    title = item.get("title")
    if isinstance(title, str) and title.strip():
        for label in (
            "[critique]",
            "[critical]",
            "[majeure]",
            "[major]",
            "[moderee]",
            "[modérée]",
            "[moderate]",
            "[medium]",
            "[mineure]",
            "[minor]",
            "[low]",
            "[high]",
        ):
            if label in title.lower():
                return label.strip("[]")

    return ""


def severity_for_advisory(item):
    """Final Faraday severity for one CERT-IST advisory."""
    return severity_from_label(extract_severity_label(item))


def _clean_product_token(token):
    """Strip bullet / dash markers + trailing punctuation from one product line."""
    if not isinstance(token, str):
        return ""
    text = token.strip()
    # Strip leading bullet glyphs / dashes / asterisks.
    text = re.sub(r"^[\-\*•●‣⁃∙\s]+", "", text)
    text = text.strip()
    # Strip trailing punctuation.
    text = text.rstrip(".;,:")
    return text.strip()


def extract_affected_products(item):
    """Pull the affected-product list from the advisory body.

    CERT-IST surfaces affected products in a labelled
    "Produits affectés:" / "Affected products:" block;
    products are typically one-per-line with bullet /
    dash glyphs.  When no labelled block is present we
    fall back to splitting the title on the analyst's
    standard ``<vendor> <product> <impact>`` shape.

    Returns a deduped list of cleaned product strings
    preserving discovery order.  Empty list when the
    advisory's body carries no parseable product block —
    the caller then emits one vuln for the advisory itself.
    """
    if not isinstance(item, dict):
        return []

    description = item.get("description")
    products = []
    seen = set()

    def add(product):
        cleaned = _clean_product_token(product)
        if not cleaned:
            return
        key = cleaned.lower()
        if key in seen:
            return
        seen.add(key)
        products.append(cleaned)

    if isinstance(description, str) and description.strip():
        match = PRODUCT_SECTION_RE.search(description)
        if match:
            body = match.group("body")
            if isinstance(body, str):
                for line in body.splitlines():
                    if not isinstance(line, str):
                        continue
                    # Lines carrying inline comma / semicolon separated
                    # product lists are split further so a single-line
                    # "ProductA, ProductB; ProductC" expands into three
                    # vulns rather than collapsing into one.
                    if "," in line or ";" in line:
                        for fragment in re.split(r"[,;]", line):
                            add(fragment)
                    else:
                        add(line)

    return products


def collect_refs(item, host):
    """Build the refs list for one CERT-IST advisory.

    Includes the canonical CERT-IST advisory deep-link,
    the NVD CVE permalink for every CVE surfaced in the
    advisory, and explicit ``Certist-*`` pivots so
    operators can pivot from a Faraday finding back to
    the exact advisory field set.
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

    if not isinstance(item, dict):
        return refs

    aid = extract_advisory_id(item)
    if aid:
        add(f"Certist-AdvisoryID: {aid}")

    link = item.get("link")
    if isinstance(link, str) and link.strip():
        add(link.strip())
    elif aid:
        add(build_advisory_link(host, aid))

    title = item.get("title")
    if isinstance(title, str) and title.strip():
        add(f"Certist-Title: {title.strip()}")

    pub_date = extract_publish_date(item)
    if pub_date is not None:
        add(f"Certist-PubDate: {pub_date.isoformat()}")

    severity_label = extract_severity_label(item)
    if severity_label:
        add(f"Certist-Severity: {severity_label}")

    cats = item.get("categories")
    if isinstance(cats, list):
        for cat in cats:
            if isinstance(cat, str) and cat.strip():
                add(f"Certist-Category: {cat.strip()}")

    for product in extract_affected_products(item):
        add(f"Certist-Product: {product}")

    for cve in collect_cves(item):
        add(f"Certist-CVE: {cve}")
        add(f"https://nvd.nist.gov/vuln/detail/{cve}")

    return refs


def extract_remediation(item):
    """Pull the analyst-recommended remediation text (or '')."""
    if not isinstance(item, dict):
        return ""
    description = item.get("description")
    if not isinstance(description, str) or not description.strip():
        return ""
    match = REMEDIATION_LINE_RE.search(description)
    if not match:
        return ""
    body = match.group("body")
    if not isinstance(body, str):
        return ""
    text = body.strip()
    if not text:
        return ""
    # Collapse runs of whitespace so the remediation fits in
    # the Faraday "resolution" field without a wall of indents.
    return re.sub(r"\s+", " ", text).strip()


def resolution_for_record(item, product=""):
    """Per-advisory analyst recommendation.

    Uses the advisory's "Remediation:" / "Solution:" /
    "Correction:" text when present.  Otherwise falls
    back to a generic vendor-patch reminder keyed off
    the canonical advisory id + the affected product.
    """
    text = extract_remediation(item)
    if text:
        return text
    aid = extract_advisory_id(item) or "the advisory"
    target = product.strip() if isinstance(product, str) and product.strip() else ""
    if not target:
        cves = collect_cves(item)
        target = cves[0] if cves else "the affected product"
    return f"Apply vendor patches for {target} per the CERT-IST " f"advisory {aid} remediation guidance."


def _slugify_product(text):
    """Coerce a product name into a stable, URL-safe slug."""
    if not isinstance(text, str):
        return ""
    cleaned = strip_accents(text).lower()
    cleaned = re.sub(r"[^a-z0-9]+", "-", cleaned)
    return cleaned.strip("-")[:80]


def build_vulnerability(item, host, product=""):
    """Build a Faraday vulnerability dict for one CERT-IST advisory record.

    When ``product`` is supplied (the typical path — one
    vuln per affected product) the product fragment is
    appended to ``name`` and ``external_id`` so multi-
    product advisories don't collide.  When empty (rare —
    cross-cutting / methodology advisories with no
    parseable product list) we emit a single advisory-
    level vuln.
    """
    if not isinstance(item, dict):
        return None

    aid = extract_advisory_id(item)
    title = item.get("title") or ""
    title = title.strip() if isinstance(title, str) else ""

    if not aid and not title:
        return None

    severity = severity_for_advisory(item)
    severity_label = extract_severity_label(item)
    pub_date = extract_publish_date(item)
    description = item.get("description") or ""
    description = description.strip() if isinstance(description, str) else ""

    name_parts = ["[CERT-IST]"]
    if aid:
        name_parts.append(aid)
    if title:
        name_parts.append(title)
    if product:
        name_parts.append(f"({product})")
    name = " ".join(name_parts)

    desc_parts = []
    if aid:
        desc_parts.append(f"advisoryID: {aid}")
    if title:
        desc_parts.append(f"title: {title}")
    if pub_date is not None:
        desc_parts.append(f"pubDate: {pub_date.isoformat()}")
    if severity_label:
        desc_parts.append(f"severity: {severity_label}")
    if product:
        desc_parts.append(f"product: {product}")
    link = item.get("link")
    if isinstance(link, str) and link.strip():
        desc_parts.append(f"link: {link.strip()}")
    cats = item.get("categories")
    if isinstance(cats, list) and cats:
        joined = ", ".join(c.strip() for c in cats if isinstance(c, str) and c.strip())
        if joined:
            desc_parts.append(f"categories: {joined}")
    if description:
        desc_parts.append(f"description: {description}")

    if product:
        slug = _slugify_product(product)
        external_id = f"{aid or title[:80]}::{slug or product[:40]}"
    else:
        external_id = aid or title[:200]

    return {
        "name": str(name).strip()[:200] or "CERT-IST advisory",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": str(external_id)[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": resolution_for_record(item, product=product),
        "data": "",
        "refs": collect_refs(item, host),
        "cve": collect_cves(item),
        "cvss3": {},
        "tags": ["cert-ist"],
    }


def filter_by_from_date(items, from_date):
    """Apply the CERTIST_FROM_DATE filter client-side.

    Belt-and-braces guard against feeds / mirrors that
    don't honour the ``fromDate=`` query parameter.
    Drops advisories whose publication date is strictly
    older than ``from_date``.  Advisories with missing /
    unparseable pubDate are KEPT (conservative default —
    we don't want to silently drop entries the executor
    can't date-stamp).  When ``from_date`` is ``None``
    the whole list passes through.
    """
    if from_date is None:
        return list(items) if isinstance(items, list) else []
    out = []
    if not isinstance(items, list):
        return out
    for entry in items:
        if not isinstance(entry, dict):
            continue
        pub = extract_publish_date(entry)
        if pub is None or pub >= from_date:
            out.append(entry)
    return out


def build_host(vulns, host, from_date, item_count):
    """Build the single synthetic host that carries every CERT-IST vuln."""
    desc_parts = ["source=cert-ist"]
    base = normalize_base_url(host)
    desc_parts.append(f"host={base}")
    if from_date is not None:
        desc_parts.append(f"fromDate={from_date.isoformat()}")
    desc_parts.append(f"advisories={item_count}")
    desc_parts.append(f"vulnerabilities={len(vulns)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": ["cert-ist"],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def fetch_feed(requests_module, url, headers):
    """GET the CERT-IST feed body.

    Returns the raw text body or ``None`` on any failure.
    Network / HTTP errors are logged but never raised
    upstream so a transient CERT-IST outage doesn't crash
    the dispatcher.
    """
    try:
        resp = requests_module.get(url, timeout=TIMEOUT, headers=headers)
    except Exception as exc:  # noqa: BLE001 — surface any network exc
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"CERT-IST feed not found at {url} (404)")
        return None
    if resp.status_code == 401 or resp.status_code == 403:
        log(f"CERT-IST auth failed ({resp.status_code}) for {url}: " "check CERTIST_API_KEY")
        return None
    if resp.status_code >= 400:
        text = getattr(resp, "text", "") or ""
        log(f"CERT-IST request failed ({resp.status_code}) for {url}: " f"{text[:500]}")
        return None
    text = getattr(resp, "text", None)
    if text is None:
        content = getattr(resp, "content", b"")
        if isinstance(content, bytes):
            try:
                text = content.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                return None
        else:
            return None
    return text


def main():
    started = time.time()

    from_date = validate_from_date(env("EXECUTOR_CONFIG_CERTIST_FROM_DATE"))
    host = env("CERTIST_HOST", default=DEFAULT_HOST)
    api_key = env("CERTIST_API_KEY", required=True)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    url = build_feed_url(host, from_date=from_date)
    headers = request_headers(api_key)
    body = fetch_feed(requests, url, headers)

    items = parse_feed(body) if body else []
    items = filter_by_from_date(items, from_date)

    vulns = []
    for item in items:
        products = extract_affected_products(item)
        if products:
            for product in products:
                vuln = build_vulnerability(item, host, product=product)
                if vuln is not None:
                    vulns.append(vuln)
        else:
            vuln = build_vulnerability(item, host)
            if vuln is not None:
                vulns.append(vuln)

    log(
        f"Processed {len(vulns)} CERT-IST vulnerabilities "
        f"from {len(items)} advisories "
        f"(from_date={from_date.isoformat() if from_date else 'none'})"
    )

    hosts_out = [build_host(vulns, host, from_date, len(items))]

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "cert_ist",
            "command": "cert_ist",
            "params": (f"from_date={from_date.isoformat() if from_date else ''}"),
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
