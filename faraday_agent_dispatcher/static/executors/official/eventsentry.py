#!/usr/bin/env python
"""EventSentry — SIEM / log-management import.

Pulls events from EventSentry Web Reports (v6.x) via its UI-backing JSON
endpoints and emits Faraday bulk-create JSON to stdout.

Confirmed against EventSentry Web Reports 6.0.1.1:

  - Every UI list page exposes a /<page>/json sibling that returns
    {"results": [...rows...]} when called with the same `search.*`
    query params the UI uses.
  - Default events endpoint: /events/json
  - Auth: API token sent as `Authorization: Bearer <token>` (the token is
    a JWT minted in EventSentry's admin UI under user API keys).

Real event row shape (captured live):

  {
    "eventId":     "7036",        # Windows EventID
    "computer":    "HOSTNAME",
    "eventNumber": "4150",        # EventSentry sequence number
    "eventLog":    "System",      # System / Application / Security / ...
    "eventType":   "Information", # Information / Warning / Error / Critical
                                  # / Audit Success / Audit Failure
    "source":      "Service Control Manager",
    "time":        "YYYY-MM-DD HH:MM:SS",
    "category":    "",
    "userName":    "",
    "message":     "..."
  }

What this executor does:
  1. GETs `{base}/{events_path}` with `search.type`, `search.dateRange`,
     `search.order=recorddate`, `search.sort=desc`, `search.limit`,
     `search.page`, and an optional `search.query` (EventSentry's filter
     DSL — e.g. `computer:HOST` or `admin:Yes`).
  2. Pages until the server returns an empty `results` list or
     EVENTSENTRY_MAX_PAGES is hit.
  3. Buckets each row by `computer`, emits one Faraday host per machine
     and one vulnerability per event above the severity floor.

Args (all read from EXECUTOR_CONFIG_* env vars, with raw fallbacks):
  EVENTSENTRY_HOST           (mandatory)  base URL, e.g. https://eventsentry.example.com:8844
  EVENTSENTRY_API_KEY        (mandatory)  vendor JWT (sent as Bearer)
  EVENTSENTRY_EVENTS_PATH    (optional)   default /events/json
  EVENTSENTRY_DATE_RANGE     (optional)   EventSentry date range, e.g.
                                          'Today', 'Last+24+hours' (default),
                                          'Last+7+days', 'Last+30+days'.
                                          Overrides EVENTSENTRY_DAYS_BACK.
  EVENTSENTRY_DAYS_BACK      (optional)   default 1; bucketed into one of the
                                          EventSentry presets above.
  EVENTSENTRY_SEARCH_QUERY   (optional)   raw EventSentry query string, e.g.
                                          'computer:WEB01' or 'admin:Yes'
  EVENTSENTRY_SOURCE_FILTER  (optional)   shortcut → 'computer:<value>'
  EVENTSENTRY_MIN_SEVERITY   (optional)   default 'warning'
  EVENTSENTRY_HEADER_NAME    (optional)   default 'Authorization'
  EVENTSENTRY_HEADER_PREFIX  (optional)   default 'Bearer '
                                          (set to '' if using X-API-Key)
  EVENTSENTRY_MAX_PAGES      (optional)   default 50
  EVENTSENTRY_PAGE_SIZE      (optional)   default 500
"""

import json
import os
import re
import sys
import time

import requests

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

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

# EventSentry's date-range presets accepted by the search.dateRange param.
# Map roughly from a user-supplied "days back" integer to the nearest preset.
DAYS_TO_RANGE = [
    (0, "Today"),
    (1, "Last 24 hours"),
    (7, "Last 7 days"),
    (30, "Last 30 days"),
    (90, "Last 90 days"),
]


def log(msg):
    print(msg, file=sys.stderr)


def normalise_severity(value):
    if value is None:
        return "info"
    text = str(value).strip().lower().replace("-", "_")
    return EVENTSENTRY_SEVERITY_TO_FARADAY.get(text, "info")


def validate_min_severity(value):
    if not value:
        return "medium"
    text = str(value).strip().lower()
    bucket = EVENTSENTRY_SEVERITY_TO_FARADAY.get(text, text)
    if bucket not in VALID_MIN_SEVERITY:
        log(f"EVENTSENTRY_MIN_SEVERITY '{value}' not recognised; defaulting to 'medium'.")
        return "medium"
    return bucket


def safe_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def days_back_to_range(days):
    for threshold, label in DAYS_TO_RANGE:
        if days <= threshold:
            return label
    return DAYS_TO_RANGE[-1][1]


def parse_event(event):
    if not isinstance(event, dict):
        return None
    severity = normalise_severity(event.get("eventType") or event.get("severity") or event.get("level"))
    host = event.get("computer") or event.get("hostname") or event.get("source_host") or "unknown-host"
    event_id = event.get("eventId") or event.get("event_id") or event.get("id") or ""
    event_number = event.get("eventNumber") or event.get("number") or ""
    event_log = event.get("eventLog") or event.get("log") or ""
    source = event.get("source") or event.get("provider") or ""
    user_name = event.get("userName") or event.get("user") or ""
    message = event.get("message") or event.get("description") or event.get("text") or ""
    timestamp = event.get("time") or event.get("timestamp") or event.get("recordDate") or ""
    category = event.get("category") or event.get("channel") or ""

    refs = []
    seen_refs = set()

    def add_ref(name):
        if name and name not in seen_refs:
            refs.append({"name": name, "type": "other"})
            seen_refs.add(name)

    for cve in CVE_RE.findall(message):
        add_ref(cve.upper())
    if source:
        add_ref(f"EventSentry-Source-{source}")
    if event_id:
        add_ref(f"EventSentry-EventID-{event_id}")
    if event_log:
        add_ref(f"EventSentry-Log-{event_log}")

    title = (
        f"[SIEM] {source}: EventID {event_id}"
        if event_id and source
        else (f"[SIEM] EventID {event_id}" if event_id else f"[SIEM] {source or 'EventSentry alert'}")
    )
    desc_lines = []
    if timestamp:
        desc_lines.append(f"Timestamp: {timestamp}")
    if event_log:
        desc_lines.append(f"Log: {event_log}")
    if category:
        desc_lines.append(f"Category: {category}")
    if user_name:
        desc_lines.append(f"User: {user_name}")
    if message:
        desc_lines.append("")
        desc_lines.append(message.strip())

    # external_id needs to be unique per host. EventSentry's eventNumber is the
    # per-event sequence id, eventId is the recurring Windows EventID — combine
    # them so the same Windows EventID firing N times produces N rows.
    parts = [str(p) for p in (event_id, event_number, timestamp) if p]
    external_id = f"eventsentry:{':'.join(parts)}" if parts else ""

    return {
        "host": str(host),
        "vuln": {
            "name": title,
            "desc": "\n".join(desc_lines) or "EventSentry alert (no message body)",
            "severity": severity,
            "type": "Vulnerability",
            "refs": refs,
            "data": f"event_id={event_id}; number={event_number}; source={source}; ts={timestamp}",
            "external_id": external_id,
            "tool": "eventsentry",
        },
    }


def fetch_events(base, path, headers, date_range, search_query, page_size, max_pages):
    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
    out = []
    for page in range(1, max_pages + 1):
        params = {
            "search.type": "detailed",
            "search.dateRange": date_range,
            "search.order": "recorddate",
            "search.sort": "desc",
            "search.page": page,
            "search.limit": page_size,
        }
        if search_query:
            params["search.query"] = search_query
        try:
            r = requests.get(url, headers=headers, params=params, timeout=30, verify=False)
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
        batch = payload.get("results") if isinstance(payload, dict) else None
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
    events_path = os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_EVENTS_PATH", "/events/json")
    header_name = os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_HEADER_NAME", "Authorization")
    header_prefix = os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_HEADER_PREFIX", "Bearer ")
    days_back = safe_int(os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_DAYS_BACK"), 1)
    date_range = os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_DATE_RANGE") or days_back_to_range(days_back)
    source_filter = os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_SOURCE_FILTER") or ""
    search_query = os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_SEARCH_QUERY") or ""
    if source_filter and not search_query:
        search_query = f"computer:{source_filter}"
    page_size = safe_int(os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_PAGE_SIZE"), 500)
    max_pages = safe_int(os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_MAX_PAGES"), 50)
    min_severity = validate_min_severity(os.environ.get("EXECUTOR_CONFIG_EVENTSENTRY_MIN_SEVERITY"))

    headers = {header_name: f"{header_prefix}{api_key}", "Accept": "application/json"}
    raw_events = fetch_events(base, events_path, headers, date_range, search_query, page_size, max_pages)
    log(f"EventSentry: fetched {len(raw_events)} raw rows (range={date_range!r}, query={search_query!r}).")

    floor = SEVERITY_ORDER.get(min_severity, 2)
    hosts_by_name = {}
    kept = 0
    for event in raw_events:
        parsed = parse_event(event)
        if not parsed:
            continue
        if SEVERITY_ORDER.get(parsed["vuln"]["severity"], 0) < floor:
            continue
        kept += 1
        host_name = parsed["host"]
        if host_name not in hosts_by_name:
            hosts_by_name[host_name] = {
                "ip": "0.0.0.0",
                "description": "Discovered via EventSentry SIEM",
                "hostnames": [host_name],
                "vulnerabilities": [],
            }
        hosts_by_name[host_name]["vulnerabilities"].append(parsed["vuln"])

    # Deduplicate vulnerabilities by external_id per host (Faraday c-5.21.x
    # silently drops the whole vulns array on duplicate external_ids).
    for host in hosts_by_name.values():
        deduped = {}
        for v in host["vulnerabilities"]:
            key = v.get("external_id") or f"{v.get('name')}::{v.get('data')}"
            deduped[key] = v
        host["vulnerabilities"] = list(deduped.values())

    log(f"EventSentry: emitting {len(hosts_by_name)} hosts, {kept} vulns kept above floor={min_severity}.")
    print(json.dumps({"hosts": list(hosts_by_name.values())}))


if __name__ == "__main__":
    main()
