#!/usr/bin/env python
"""endoflife.date public REST API importer.

Pulls per-product release-cycle metadata from the community-maintained
endoflife.date service and flags every currently-deployed product
version whose release cycle is already past its End-Of-Life date. The
PRODUCTS arg controls which product catalogues are queried (one HTTP
GET per product); INSTALLED_VERSIONS pairs each product with the
version actually deployed in the user's environment so the executor
can pick the matching cycle out of the catalogue.

Endpoints used:
  GET /api/{product}.json
      -> JSON list of release cycles. Each cycle carries ``cycle``
      (release line, e.g. ``"20"`` for nodejs / ``"3.11"`` for python),
      ``releaseDate``, ``eol`` (date string OR ``true`` if already
      EOL without a date OR ``false`` if no EOL is planned),
      ``latest`` (latest patch release in the cycle),
      ``latestReleaseDate``, ``lts`` (boolean or LTS-window start),
      ``support`` (end of active / general support — security-only
      updates remain until ``eol``) and optionally
      ``discontinued`` / ``extendedSupport`` / ``link``.

Each product becomes one Faraday host (synthetic ``0.0.0.0`` ip
because EOL findings live in software-version metadata, not on IPs);
per-product EOL findings attach as Faraday vulnerabilities — one per
EOL cycle the installed version maps onto with engine prefix
``[SCA]``. Severity is bucketed by how long ago the cycle EOL'd
(<30d → low, <365d → medium, <730d → high, ≥730d → critical), so
a freshly-EOL-d cycle is reported as low and a multi-year-stale
cycle bubbles up to critical. Past-``support`` cycles whose EOL
hasn't yet passed are surfaced as informational only.

No env vars — the endoflife.date API is unauthenticated and
rate-limited at the gateway level. ENDOFLIFE_HOST may be overridden
via env to point at a mirror or an offline cache; defaults to
``https://endoflife.date``.
"""

import json
import os
import socket
import sys
import time
from datetime import date, datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
DEFAULT_HOST = "https://endoflife.date"

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def log(msg):
    print(f"{datetime.utcnow()} - EndOfLifeDate: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def normalize_base_url(host):
    if not host:
        return DEFAULT_HOST
    base = host if host.startswith(("http://", "https://")) else f"https://{host}"
    return base.rstrip("/")


def parse_csv(value):
    """Parse a CSV string into a deduped, whitespace-tolerant list.

    Accepts None / list / tuple / set inputs verbatim (after the same
    whitespace + dedup pass). Returns ``[]`` for empty input.
    """
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        items = str(value).split(",")
    out = []
    seen = set()
    for item in items:
        if item is None:
            continue
        text = str(item).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def parse_installed_versions(value):
    """Parse a CSV of ``product=version`` pairs into a dict.

    Whitespace-tolerant, case-insensitive on the product key (matches
    how endoflife.date canonicalises product slugs). Later entries for
    the same product win. Returns an empty dict on empty input.
    """
    if value is None or value == "":
        return {}
    if isinstance(value, dict):
        items = [(k, v) for k, v in value.items()]
    else:
        items = []
        for chunk in str(value).split(","):
            if "=" not in chunk:
                continue
            k, _, v = chunk.partition("=")
            items.append((k, v))
    out = {}
    for k, v in items:
        if k is None:
            continue
        key = str(k).strip().lower()
        if not key:
            continue
        out[key] = str(v).strip() if v is not None else ""
    return out


def normalize_product(name):
    """Canonicalise a product slug to the wire form endoflife.date uses.

    endoflife.date URLs are lowercase, hyphen-separated and use
    aliases for a handful of products (``node`` → ``nodejs``,
    ``debian-linux`` → ``debian``). We keep the alias table small and
    fall back to a lowercase / strip pass.
    """
    if not name:
        return ""
    text = str(name).strip().lower().replace("_", "-")
    aliases = {
        "node": "nodejs",
        "node.js": "nodejs",
        "node-js": "nodejs",
        "python3": "python",
        "py": "python",
        "rhel": "rhel",
        "redhat": "rhel",
        "red-hat-enterprise-linux": "rhel",
        "centos-linux": "centos",
        "ubuntu-linux": "ubuntu",
        "debian-linux": "debian",
        "go-lang": "go",
        "golang": "go",
        "openjdk": "java",
    }
    return aliases.get(text, text)


def parse_iso_date(value):
    """Parse a YYYY-MM-DD (or full ISO 8601) string into a ``date``.

    Returns ``None`` for non-string / unparseable / bool inputs.
    endoflife.date sometimes returns dates with trailing time zones
    (``2024-04-30T00:00:00Z``); the leading 10 characters are the
    canonical date portion.
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


def is_eol_passed(eol_value, today):
    """Return ``(passed, parsed_eol_date_or_None)``.

    endoflife.date encodes eol as:
      - a date string  (e.g. ``"2024-04-30"``)  -> compare to today
      - ``True``                                 -> already EOL, no date
      - ``False``                                -> no EOL planned
      - ``None`` / missing                       -> treat as unknown
    """
    if eol_value is True:
        return True, None
    if eol_value is False or eol_value is None:
        return False, None
    parsed = parse_iso_date(eol_value)
    if parsed is None:
        return False, None
    return parsed < today, parsed


def severity_from_eol_age(parsed_eol, today):
    """Bucket severity by how long ago the cycle EOL'd.

    Older EOLs are scarier (no security backports, no vendor patch
    pipeline, drift from current cycle is wider). The ladder picks
    intentionally coarse cut-offs so the executor produces stable
    severity across runs even as ``today`` advances.

    ``parsed_eol`` may be ``None`` (when the cycle is marked
    ``eol: true`` without a date), in which case we assume the cycle
    is multi-year stale and emit ``high`` — Faraday users can still
    adjust via MIN_SEVERITY.
    """
    if parsed_eol is None:
        return "high"
    delta = (today - parsed_eol).days
    if delta < 0:
        return "info"
    if delta < 30:
        return "low"
    if delta < 365:
        return "medium"
    if delta < 730:
        return "high"
    return "critical"


def find_matching_cycle(cycles, installed_version):
    """Pick the cycle that matches the installed version.

    Strategy:
      1. exact match of ``cycle == installed``
      2. progressive prefix match — strip ``.``-separated trailing
         components from the installed version until a cycle matches
         (so ``3.11.4`` matches cycle ``3.11`` and then ``3``)
      3. exact match against the cycle's ``latest`` value (some
         products only ship one cycle at a time and pin ``latest``
         to the canonical patch release; e.g. solo libraries)
      4. lexicographic prefix match against any cycle (handles e.g.
         ``cycle="2024-04"`` for ubuntu LTS where the installed
         version is the same ``"24.04"`` style)

    Returns the matching cycle dict or ``None``.
    """
    if not isinstance(cycles, list) or not installed_version:
        return None
    target = str(installed_version).strip()
    if not target:
        return None
    target_lower = target.lower()

    by_cycle = {}
    for c in cycles:
        if not isinstance(c, dict):
            continue
        cyc = c.get("cycle")
        if cyc is None:
            continue
        by_cycle[str(cyc).strip().lower()] = c

    if target_lower in by_cycle:
        return by_cycle[target_lower]

    parts = target.split(".")
    for i in range(len(parts) - 1, 0, -1):
        candidate = ".".join(parts[:i]).lower()
        if candidate in by_cycle:
            return by_cycle[candidate]

    for c in cycles:
        if not isinstance(c, dict):
            continue
        latest = c.get("latest")
        if isinstance(latest, str) and latest.strip().lower() == target_lower:
            return c

    for c in cycles:
        if not isinstance(c, dict):
            continue
        cyc = c.get("cycle")
        if not isinstance(cyc, str):
            continue
        cyc_lower = cyc.strip().lower()
        if not cyc_lower:
            continue
        if target_lower.startswith(cyc_lower + ".") or target_lower.startswith(cyc_lower + "-"):
            return c

    return None


def fetch_product(base_url, product):
    """GET /api/{product}.json — returns a list of cycle dicts.

    Returns ``None`` if the product slug is unknown to endoflife.date
    (404) or the request fails; an empty list is treated as ``[]``.
    """
    url = f"{base_url}/api/{product}.json"
    try:
        resp = requests.get(url, timeout=TIMEOUT, verify=False, headers={"Accept": "application/json"})
    except requests.RequestException as exc:
        log(f"GET {url} failed: {exc}")
        return None
    if resp.status_code == 404:
        log(f"product '{product}' not found on endoflife.date (404)")
        return None
    if resp.status_code >= 400:
        log(f"GET {url} failed ({resp.status_code}): {resp.text[:500]}")
        return None
    try:
        body = resp.json()
    except ValueError:
        log(f"GET {url} returned non-JSON body")
        return None
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in ("cycles", "results", "data", "items"):
            value = body.get(key)
            if isinstance(value, list):
                return value
    return []


def cycle_label(cycle):
    """Return a printable label for a cycle dict.

    Prefers ``cycle`` but falls back to ``releaseLabel`` / ``name``
    for the rare products (e.g. some Apple OS catalogues) that ship
    a separate human label.
    """
    if not isinstance(cycle, dict):
        return ""
    for key in ("cycle", "releaseLabel", "name"):
        value = cycle.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def build_vulnerability(product, installed_version, cycle, today):
    """Build a Faraday vulnerability dict for one EOL cycle hit."""
    cyc_label = cycle_label(cycle) if isinstance(cycle, dict) else ""
    eol_raw = cycle.get("eol") if isinstance(cycle, dict) else None
    passed, parsed_eol = is_eol_passed(eol_raw, today)

    severity = severity_from_eol_age(parsed_eol, today)
    status = "open"

    title_version = installed_version or cyc_label or "(unknown)"
    raw_name = f"{product} {title_version} is past End-Of-Life"
    if cyc_label and cyc_label != str(installed_version):
        raw_name = f"{product} {title_version} (cycle {cyc_label}) is past End-Of-Life"
    name = f"[SCA] {raw_name}"

    desc_parts = [f"product: {product}"]
    if installed_version:
        desc_parts.append(f"installed_version: {installed_version}")
    if cyc_label:
        desc_parts.append(f"cycle: {cyc_label}")
    if parsed_eol is not None:
        delta = (today - parsed_eol).days
        desc_parts.append(f"eol: {parsed_eol.isoformat()} ({delta} days ago)")
    elif eol_raw is True:
        desc_parts.append("eol: true (date not published)")
    elif eol_raw not in (None, False, ""):
        desc_parts.append(f"eol: {eol_raw}")
    if isinstance(cycle, dict):
        support = cycle.get("support")
        if support not in (None, "", False):
            desc_parts.append(f"support: {support}")
        latest = cycle.get("latest")
        if latest:
            desc_parts.append(f"latest: {latest}")
        latest_release = cycle.get("latestReleaseDate") or cycle.get("latestRelease")
        if latest_release:
            desc_parts.append(f"latestReleaseDate: {latest_release}")
        release_date = cycle.get("releaseDate")
        if release_date:
            desc_parts.append(f"releaseDate: {release_date}")
        lts = cycle.get("lts")
        if lts not in (None, "", False):
            desc_parts.append(f"lts: {lts}")
        discontinued = cycle.get("discontinued")
        if discontinued not in (None, "", False):
            desc_parts.append(f"discontinued: {discontinued}")
        extended = cycle.get("extendedSupport") or cycle.get("extended_support")
        if extended not in (None, "", False):
            desc_parts.append(f"extendedSupport: {extended}")

    refs = []
    seen_refs = set()

    def add_ref(text, ref_type="other"):
        if not text:
            return
        s = str(text).strip()
        if not s or s in seen_refs:
            return
        seen_refs.add(s)
        refs.append({"name": s, "type": ref_type})

    add_ref(f"https://endoflife.date/{product}")
    if isinstance(cycle, dict):
        link = cycle.get("link")
        if isinstance(link, str) and link.strip():
            add_ref(link)

    resolution = ""
    if isinstance(cycle, dict):
        latest = cycle.get("latest")
        if latest:
            resolution = (
                f"Upgrade {product} from {installed_version or cyc_label} "
                f"to a supported release line (latest in this cycle: {latest})."
            )
        else:
            resolution = (
                f"Upgrade {product} {installed_version or cyc_label} to a supported "
                "release line — this cycle no longer receives security backports."
            )

    external_id = f"EOL:{product}:{cyc_label or installed_version or '?'}"

    return {
        "name": str(name).strip()[:200] or f"EOL {product}",
        "desc": "\n".join(desc_parts),
        "severity": severity,
        "external_id": external_id,
        "type": "Vulnerability",
        "status": status,
        "resolution": resolution,
        "data": "",
        "refs": refs,
        "cve": [],
        "cvss3": {},
        "tags": ["endoflife_date", "eol", "sca"],
    }


def build_host(product, installed_version, cycles, vulns):
    canonical = normalize_product(product) or product or ""
    hostname = f"{canonical}@{installed_version}" if installed_version else canonical
    desc_parts = [f"product={canonical}"]
    if installed_version:
        desc_parts.append(f"installed_version={installed_version}")
    if isinstance(cycles, list):
        desc_parts.append(f"cycles={len(cycles)}")
    return {
        "ip": "0.0.0.0",
        "os": "",
        "hostnames": [hostname] if hostname else [],
        "mac": "",
        "description": " | ".join(desc_parts),
        "vulnerabilities": vulns,
    }


def validate_min_severity(value):
    if value is None or value == "":
        return "info"
    text = str(value).strip().lower()
    if text not in VALID_MIN_SEVERITY:
        log(f"EOL_MIN_SEVERITY '{value}' not recognised; defaulting to 'info'")
        return "info"
    return text


def main():
    started = time.time()
    products_raw = env("EXECUTOR_CONFIG_PRODUCTS", required=True)
    installed_raw = env("EXECUTOR_CONFIG_INSTALLED_VERSIONS")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_EOL_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]
    host = env("ENDOFLIFE_HOST", default=DEFAULT_HOST)
    base_url = normalize_base_url(host)
    today = date.today()

    products = parse_csv(products_raw)
    if not products:
        log("PRODUCTS is required (CSV like nodejs,python,debian)")
        sys.exit(1)
    installed = parse_installed_versions(installed_raw)

    hosts = []
    total_vulns = 0
    for raw_product in products:
        product = normalize_product(raw_product)
        if not product:
            continue
        installed_version = installed.get(product) or installed.get(raw_product.lower())
        cycles = fetch_product(base_url, product)
        if cycles is None:
            continue
        if not installed_version:
            log(
                f"product '{product}' has no INSTALLED_VERSIONS entry; "
                "skipping vulnerability emission (host still recorded)"
            )
            hosts.append(build_host(product, "", cycles, []))
            continue
        cycle = find_matching_cycle(cycles, installed_version)
        if cycle is None:
            log(f"installed version '{installed_version}' did not match any " f"cycle for product '{product}'")
            hosts.append(build_host(product, installed_version, cycles, []))
            continue
        eol_raw = cycle.get("eol")
        passed, _ = is_eol_passed(eol_raw, today)
        if not passed:
            hosts.append(build_host(product, installed_version, cycles, []))
            continue
        vuln = build_vulnerability(product, installed_version, cycle, today)
        if SEVERITY_ORDER[vuln["severity"]] < floor:
            hosts.append(build_host(product, installed_version, cycles, []))
            continue
        total_vulns += 1
        hosts.append(build_host(product, installed_version, cycles, [vuln]))

    log(
        f"Processed {len(products)} products against endoflife.date "
        f"({total_vulns} EOL vulnerabilities emitted, min_severity={min_severity})"
    )

    output = {
        "hosts": hosts,
        "command": {
            "tool": "endoflife_date",
            "command": "endoflife_date",
            "params": (
                f"products={','.join(products)},"
                f"installed_versions={len(installed)},"
                f"min_severity={min_severity}"
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
