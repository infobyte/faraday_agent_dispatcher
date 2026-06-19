#!/usr/bin/env python
"""EventSentry — SIEM / log-management import.

PROVISIONAL: EventSentry's REST API is not publicly documented and the
demo at demo.eventsentry.io is auth-walled (HTTP 403 unauthenticated),
so the endpoint paths and JSON field names below are best-guess defaults
based on the Web Reports v6 product overview. Confirm against an actual
EventSentry instance (DevTools → Network) and adjust EVENTSENTRY_*
config + the parse_event() field map as needed.

What we believe today:
  - Web Reports v6 ships a REST API alongside the dashboard UI.
  - Auth is an API key sent as a header (default: ``X-API-Key``).
  - Events are queryable by time window, severity, and source host.

What this executor does:
  1. GETs ``{base}/{events_path}`` with auth + filters.
  2. Iterates the returned ``events`` list (or ``items`` / ``records``
     — we try each).
  3. Builds one Faraday host per distinct ``computer`` / ``hostname``
     field; one vuln per high-severity event.
  4. Severity buckets EventSentry's enum (Critical / Error / Warning /
     Information / Audit Success / Audit Failure) into Faraday's
     five-bucket scheme.

Args:
  EVENTSENTRY_HOST           (mandatory)  base URL, e.g. https://eventsentry.example.com
  EVENTSENTRY_API_KEY        (mandatory)  vendor token (sent as header)
  EVENTSENTRY_EVENTS_PATH    (optional)   default /api/events
  EVENTSENTRY_DAYS_BACK      (optional)   default 1
  EVENTSENTRY_MIN_SEVERITY   (optional)   default 'warning'
  EVENTSENTRY_SOURCE_FILTER  (optional)   host / computer name substring
  EVENTSENTRY_HEADER_NAME    (optional)   default 'X-API-Key'
  EVENTSENTRY_MAX_PAGES      (optional)   default 50
  EVENTSENTRY_PAGE_SIZE      (optional)   default 500
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# EventSentry's classic Windows-event-style severity enum, plus the
# product's "Audit Success / Audit Failure" buckets.
EVENTSENTRY_SEVERITY_TO_FARADAY = {
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "information": "info",
    "info": "info",
    "verbose": "info",
    "debug": "info",
    "audit_success": "info",
    "audit success": "info",
    "audit_failure": "medium",
    "audit failure": "medium",
}

VALID_MIN_SEVERITY = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def log(msg):
    print(msg, file=sys.stderr)


def normalise_severity(value):
    if value is None:
        return "info"
    text = str(value).strip().lower().replace("-", "_")
    return EVENTSENTRY_SEVERITY_TO_FARADAY.get(text, "info")


def validate_min_severity(value):
    if not value:
        return "warning"
    text = str(value).strip().lower()
    # EventSentry users tend to think in their own enum; translate first.
    bucket = EVENTSENTRY_SEVERITY_TO_FARADAY.get(text, text)
    if bucket not in VALID_MIN_SEVERITY:
        log(f"EVENTSENTRY_MIN_SEVERITY '{value}' not recognised; defaulting to 'medium' (warning).")
        return "medium"
    return bucket


def safe_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def event_records(payload):
    """Return the list of event records regardless of the wrapper key.

    EventSentry's exact key name isn't confirmed; we try the obvious
    ones in order and fall back to a flat-list payload.
    """
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("events", "items", "records", "data", "result", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def parse_event(event):
    """Map one EventSentry event record into a Faraday vulnerability dict."""
    if not isinstance(event, dict):
        return None
    severity = normalise_severity(event.get("severity") or event.get("level") or event.get("type"))
    host = (
        event.get("computer")
        or event.get("hostname")
        or event.get("source_host")
        or event.get("host")
        or "unknown-host"
    )
    event_id = event.get("event_id") or event.get("id") or event.get("eventID") or ""
    source = event.get("source") or event.get("provider") or ""
    message = event.get("message") or event.get("description") or event.get("text") or ""
    timestamp = event.get("timestamp") or event.get("time") or event.get("@timestamp") or ""
    category = event.get("category") or event.get("channel") or ""

    refs = []
    for cve in CVE_RE.findall(message):
        ref = cve.upper()
        if ref not in [r["name"] for r in refs]:
            refs.append({"name": ref, "type": "other"})
    if source:
        refs.append({"name": f"EventSentry-Source-{source}", "type": "other"})
    if event_id:
        refs.append({"name": f"EventSentry-EventID-{event_id}", "type": "other"})

    title = f"[SIEM] {source}: EventID {event_id}" if event_id else f"[SIEM] {source or 'EventSentry alert'}"
    desc_lines = []
    if timestamp:
        desc_lines.append(f"Timestamp: {timestamp}")
    if category:
        desc_lines.append(f"Category: {category}")
    if message:
        desc_lines.append("")
        desc_lines.append(message.strip())

    return {
        "host": str(host),
        "vuln": {
            "name": title,
            "desc": "\n".join(desc_lines) or "EventSentry alert (no message body)",
            "severity": severity,
            "type": "Vulnerability",
            "refs": refs,
            "data": f"event_id={event_id}; source={source}; ts={timestamp}",
            "external_id": str(event_id) if event_id else "",
            "tool": "eventsentry",
        },
    }


def fetch_events(base, path, headers, days_back, source_filter, page_size, max_pages):
    """Paginate the EventSentry events endpoint and collect every record.

    Pagination shape is not confirmed; we send ``page`` + ``page_size``
    and stop when the response returns fewer than ``page_size`` items.
    """
    since = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()
    params_base = {"since": since, "page_size": page_size}
    if source_filter:
        params_base["computer"] = source_filter
    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
    out = []
    for page in range(1, max_pages + 1):
        params = dict(params_base, page=page)
        try:
            r = requests.get(url, headers=headers, params=params, timeout=30)
        except requests.RequestException as exc:
            log(f"EventSentry request error on page {page}: {exc}")
            break
        if r.status_code == 429:
            log("EventSentry rate-limited (429); sleeping 30s before retrying.")
            time.sleep(30)
            continue
        if r.status_code != 200:
            log(f"EventSentry returned HTTP {r.status_code} on page {page}: {r.text[:300]}")
            break
        try:
            payload = r.json()
        except ValueError:
            log(f"EventSentry returned non-JSON on page {page}: {r.text[:200]!r}")
            break
        batch = event_records(payload)
        if not batch:
            break
        out.extend(batch)
        if len(batch) < page_size:
            break
    return out


def main():
    base = os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_HOST") or os.environ.get("EVENTSENTRY_HOST")
    api_key = os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_API_KEY") or os.environ.get("EVENTSENTRY_API_KEY")
    if not base or not api_key:
        log("EVENTSENTRY_HOST and EVENTSENTRY_API_KEY are required.")
        sys.exit(1)
    events_path = os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_EVENTS_PATH", "/api/events")
    header_name = os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_HEADER_NAME", "X-API-Key")
    days_back = safe_int(os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_DAYS_BACK"), 1)
    source_filter = os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_SOURCE_FILTER") or ""
    page_size = safe_int(os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_PAGE_SIZE"), 500)
    max_pages = safe_int(os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_MAX_PAGES"), 50)
    min_severity = validate_min_severity(os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_MIN_SEVERITY"))

    headers = {header_name: api_key, "Accept": "application/json"}
    raw_events = fetch_events(base, events_path, headers, days_back, source_filter, page_size, max_pages)

    floor = SEVERITY_ORDER.get(min_severity, 2)
    hosts_by_name = {}
    for event in raw_events:
        parsed = parse_event(event)
        if not parsed:
            continue
        if SEVERITY_ORDER.get(parsed["vuln"]["severity"], 0) < floor:
            continue
        host_name = parsed["host"]
        if host_name not in hosts_by_name:
            hosts_by_name[host_name] = {
                "ip": "0.0.0.0",
                "description": "Discovered via EventSentry SIEM",
                "hostnames": [host_name],
                "vulnerabilities": [],
            }
        hosts_by_name[host_name]["vulnerabilities"].append(parsed["vuln"])

    print(json.dumps({"hosts": list(hosts_by_name.values())}))


if __name__ == "__main__":
    main()
