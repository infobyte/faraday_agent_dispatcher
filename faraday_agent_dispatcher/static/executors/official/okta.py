#!/usr/bin/env python
"""Okta identity-platform importer.

Pulls Okta user accounts and System Log events from an Okta tenant
and emits Faraday bulk-create JSON to stdout.  Okta is the identity
authority of record for the modern SaaS estate, so this executor is
the IAM-class feed Faraday operators correlate the EDR / EASM /
vuln-scanner agents' findings against to confirm an identity tied
to an exposed host is a known, active principal — and to surface
suspicious authentication activity (impossible-travel sign-ins,
brute-forced MFA, deactivated-user revivals) onto the workspace as
identity-attack-surface vulnerabilities.

Each Okta user becomes one Faraday host — Okta users aren't
IP-keyed (identities can sign in from anywhere) so they synthesise
onto the ``0.0.0.0`` sentinel; the ``profile.login`` /
``profile.email`` / ``profile.firstName`` + ``profile.lastName``
projection lands on ``host.hostnames``, the ``status`` /
``lastLogin`` / ``passwordChanged`` enrichment lands on
``host.description``, and the user record itself becomes one
Faraday vulnerability with the ``[IDENTITY]`` engine prefix so the
finding lands in the workspace alongside the other identity-
attack-surface feeds.  Each Okta System Log event becomes one
Faraday host keyed on ``client.ipAddress`` when present (sign-in
events almost always carry the client IP) or the ``0.0.0.0``
sentinel otherwise; the ``actor.alternateId`` / ``actor.displayName``
/ ``target[].alternateId`` projection lands on ``host.hostnames``
and the event becomes one Faraday vulnerability with severity
mapped from Okta's ``severity`` field.  Each Okta event hook (when
``OKTA_EVENT_HOOKS=true``) becomes one Faraday host on the
``0.0.0.0`` sentinel — hook channels are configuration-class
records and surface as ``info`` so operators can audit which
external systems are wired to the Okta event stream.

Endpoints used:
  GET {OKTA_DOMAIN}/api/v1/users?limit=<OKTA_LIMIT>&filter=<OKTA_FILTER>
      -> paginated user inventory.  Returns ``[{...user...}]`` at
      the envelope root.  Pagination is Link-header based — each
      response carries an ``rfc5988`` ``Link: <url>; rel="next"``
      header that we walk verbatim until either the header is
      absent or ``OKTA_PAGES`` is reached.  ``filter`` is an Okta
      filter expression (e.g. ``status eq "ACTIVE"``) forwarded
      server-side.
  GET {OKTA_DOMAIN}/api/v1/logs?limit=<OKTA_LIMIT>&filter=<OKTA_FILTER>
      -> paginated System Log events.  Same envelope shape and
      pagination strategy as the users surface.  ``filter`` accepts
      Okta filter expressions (e.g.
      ``eventType eq "user.session.start"`` or
      ``severity eq "WARN"``) forwarded server-side.
  GET {OKTA_DOMAIN}/api/v1/eventHooks  (only when OKTA_EVENT_HOOKS=true)
      -> configured event-hook channels.  Returns ``[{...hook...}]``
      with ``status`` / ``channel.uri`` / ``events`` enrichment.
      No pagination — Okta returns the full list in a single call.

Auth: Okta uses long-lived API tokens.  Operators create one in
the Okta admin console under ``Security -> API -> Tokens -> Create
Token``.  The dispatcher carries it on every request as the
non-standard ``Authorization: SSWS <OKTA_API_TOKEN>`` header.
``OKTA_DOMAIN`` is the operator's Okta tenant host (e.g.
``mycorp.okta.com`` or ``mycorp.oktapreview.com``); ``https://``
is added automatically when the operator pasted in a bare FQDN.

Severity for users / event hooks is always ``info`` (they're
identity-inventory entries, not findings).  Severity for log
events is mapped from Okta's ``severity`` field
(``DEBUG``/``INFO`` -> ``info``, ``WARN`` -> ``med``,
``ERROR`` -> ``high``).  Tags: [okta, identity, user|log|event-hook].
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

TIMEOUT = 60
DEFAULT_LIMIT = 200  # Okta's documented default for both /users and /logs.
MAX_LIMIT = 1000  # Okta's documented hard cap.
DEFAULT_PAGES = 5
MAX_PAGES = 50

# Okta System Log severity values -> Faraday severity slots.
SEVERITY_MAP = {
    "DEBUG": "info",
    "INFO": "info",
    "WARN": "med",
    "ERROR": "high",
}

# Sentinel IP used for identity-keyed (non-IP-keyed) records.
SENTINEL_IP = "0.0.0.0"

LINK_NEXT_RE = re.compile(r'<([^>]+)>\s*;\s*rel\s*=\s*"next"', re.IGNORECASE)


def log(msg):
    print(f"{datetime.utcnow()} - Okta: {msg}", file=sys.stderr, flush=True)


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
    """Trim trailing slash + tolerate operator typos on OKTA_DOMAIN.

    No default — the Okta tenant host is operator-specific so we
    ``sys.exit(1)`` upstream in ``main`` when the env var is
    missing.  Here we just whitespace-trim, strip trailing slashes
    and add ``https://`` when the operator pasted in a bare FQDN.
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    text = host.strip().rstrip("/")
    if not text.lower().startswith(("http://", "https://")):
        text = f"https://{text}"
    return text


def validate_filter(value):
    """Validate OKTA_FILTER (the operator-supplied Okta filter expr).

    None / blank -> ``""`` (Okta interprets the absence of ``filter``
    as "all records").  Whitespace is trimmed.  Anything else is
    forwarded verbatim — Okta filter expressions are free-form
    (e.g. ``status eq "ACTIVE"`` for /users or
    ``eventType eq "user.session.start"`` for /logs).
    """
    if value is None:
        return ""
    return str(value).strip()


def validate_limit(value):
    """Validate OKTA_LIMIT (per-page record cap).

    None / blank -> ``DEFAULT_LIMIT``.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_LIMIT] so a stray
    operator input can't ask Okta for a page size it won't honour.
    """
    if value is None or value == "":
        return DEFAULT_LIMIT
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"OKTA_LIMIT '{value}' not numeric; defaulting to {DEFAULT_LIMIT}")
        return DEFAULT_LIMIT
    if n < 1:
        return 1
    if n > MAX_LIMIT:
        log(f"OKTA_LIMIT {n} above MAX_LIMIT={MAX_LIMIT}; clamping")
        return MAX_LIMIT
    return n


def validate_pages(value):
    """Validate OKTA_PAGES (per-surface page-walk cap).

    None / blank -> ``DEFAULT_PAGES``.  Accepts int / numeric-string;
    floats are floored.  Clamped to [1, MAX_PAGES] so a stray
    operator input can't fan out into 100k+ requests against the
    Okta API.  Not exposed as a manifest argument (the playbook
    only lists OKTA_FILTER / OKTA_LIMIT / OKTA_EVENT_HOOKS) but read
    from the env so a tenant-side override can still tune the walk.
    """
    if value is None or value == "":
        return DEFAULT_PAGES
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        log(f"OKTA_PAGES '{value}' not numeric; defaulting to {DEFAULT_PAGES}")
        return DEFAULT_PAGES
    if n < 1:
        return 1
    if n > MAX_PAGES:
        log(f"OKTA_PAGES {n} above MAX_PAGES={MAX_PAGES}; clamping")
        return MAX_PAGES
    return n


def validate_event_hooks(value):
    """Validate OKTA_EVENT_HOOKS (true | false).

    None / blank -> ``False``.  Truthy tokens: ``true`` / ``1`` /
    ``yes`` / ``on`` (case-insensitive).  Anything else is ``False``.
    """
    if value is None:
        return False
    text = str(value).strip().lower()
    return text in ("true", "1", "yes", "on")


def auth_headers(token):
    """Return the Okta auth header set.

    Okta uses a non-standard ``Authorization: SSWS <token>`` scheme
    rather than ``Bearer`` / ``Basic``.  We also force
    ``Accept: application/json`` because Okta's content negotiation
    will default to JSON anyway but being explicit avoids edge cases
    on federated / proxy stacks that strip the default.
    """
    return {
        "Authorization": f"SSWS {token or ''}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_next_link(headers):
    """Pull the ``rel="next"`` URL out of an Okta response's Link header.

    Okta paginates via the RFC 5988 ``Link`` header.  Each response
    carries one or more ``<url>; rel="..."`` entries — we only care
    about ``rel="next"``.  Returns None when no next link is set,
    which signals end-of-walk to ``fetch_all``.
    """
    if not headers:
        return None
    link = headers.get("Link") or headers.get("link")
    if not link:
        return None
    for entry in link.split(","):
        match = LINK_NEXT_RE.search(entry)
        if match:
            return match.group(1).strip()
    return None


def fetch_all(requests_module, url, headers, max_pages, surface_name):
    """Walk an Okta endpoint via Link-header pagination.

    Pages until either the response stops carrying a
    ``rel="next"`` Link header or ``max_pages`` is reached.  401
    short-circuits the whole executor because the operator
    credentials are wrong (the matching surfaces also 401 on the
    same token).  403 / 429 just stop pagination on the surface
    we're walking and return what we have.
    """
    out = []
    walked = 0
    current_url = url
    while current_url and walked < max_pages:
        try:
            resp = requests_module.get(current_url, headers=headers, timeout=TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET {current_url} failed: {exc}")
            break
        if resp.status_code == 401:
            log("Okta request rejected (401). Check OKTA_API_TOKEN.")
            sys.exit(1)
        if resp.status_code == 403:
            log(f"Okta {surface_name} request rejected (403). Check the token's scope.")
            return out
        if resp.status_code == 429:
            log(f"Okta rate-limited (429) on {surface_name}; stopping pagination.")
            return out
        if resp.status_code >= 400:
            log(f"Okta {surface_name} failed ({resp.status_code}): {resp.text[:500]}")
            return out
        try:
            payload = resp.json()
        except ValueError:
            log(f"Okta {surface_name} response was not JSON")
            return out
        if isinstance(payload, list):
            for entry in payload:
                if isinstance(entry, dict):
                    out.append(entry)
        walked += 1
        current_url = extract_next_link(resp.headers)
    if current_url and walked >= max_pages:
        log(f"hit OKTA_PAGES={max_pages} on {surface_name}; stopping pagination")
    return out


def build_users_url(host, limit, filter_expr):
    base = f"{normalize_base_url(host)}/api/v1/users"
    params = [f"limit={int(limit)}"]
    if filter_expr:
        from urllib.parse import quote

        params.append(f"filter={quote(filter_expr, safe='')}")
    return f"{base}?{'&'.join(params)}"


def build_logs_url(host, limit, filter_expr):
    base = f"{normalize_base_url(host)}/api/v1/logs"
    params = [f"limit={int(limit)}"]
    if filter_expr:
        from urllib.parse import quote

        params.append(f"filter={quote(filter_expr, safe='')}")
    return f"{base}?{'&'.join(params)}"


def build_event_hooks_url(host):
    return f"{normalize_base_url(host)}/api/v1/eventHooks"


def _str(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value)


def _serialise(obj):
    if obj is None:
        return ""
    if isinstance(obj, (str, int, float)):
        return str(obj)
    try:
        return json.dumps(obj, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(obj)


def user_hostnames(profile):
    """Pick canonical principal strings for an Okta user."""
    out = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    if isinstance(profile, dict):
        add(profile.get("login"))
        add(profile.get("email"))
        add(profile.get("secondEmail"))
        first = _str(profile.get("firstName"))
        last = _str(profile.get("lastName"))
        if first or last:
            add(f"{first} {last}".strip())
    return out


def map_log_severity(value):
    """Map an Okta System Log severity onto a Faraday severity slot."""
    if not value:
        return "info"
    return SEVERITY_MAP.get(str(value).strip().upper(), "info")


def collect_user_refs(user):
    """Walk an Okta user record for identity pivots."""
    refs = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if isinstance(user, dict):
        uid = _str(user.get("id"))
        if uid:
            add(f"Okta-Id: {uid}")
        status = _str(user.get("status"))
        if status:
            add(f"Okta-Status: {status}")
        last_login = _str(user.get("lastLogin"))
        if last_login:
            add(f"Okta-LastLogin: {last_login}")
        password_changed = _str(user.get("passwordChanged"))
        if password_changed:
            add(f"Okta-PasswordChanged: {password_changed}")
        created = _str(user.get("created"))
        if created:
            add(f"Okta-Created: {created}")
        profile = user.get("profile") or {}
        if isinstance(profile, dict):
            login = _str(profile.get("login"))
            if login:
                add(f"Okta-Login: {login}")
    return refs


def build_user_host(user, filter_expr):
    """Build a Faraday host dict for an Okta user record.

    Users aren't IP-keyed — synthesise on the ``0.0.0.0`` sentinel so
    the workspace still surfaces the finding, and hang the principal
    on ``host.hostnames`` so Faraday's hostname index still pivots
    on it.
    """
    if not isinstance(user, dict):
        return None
    profile = user.get("profile") or {}
    hostnames = user_hostnames(profile)
    primary = hostnames[0] if hostnames else _str(user.get("id")) or "unknown user"

    desc_parts = []
    for key in (
        "id",
        "status",
        "created",
        "activated",
        "lastLogin",
        "lastUpdated",
        "passwordChanged",
        "statusChanged",
    ):
        v = user.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if isinstance(profile, dict) and profile:
        desc_parts.append(f"profile: {_serialise(profile)}")
    if filter_expr:
        desc_parts.append(f"okta_filter: {filter_expr}")

    vuln = {
        "name": f"[IDENTITY] Okta user: {primary}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(user.get("id"))[:200] or f"okta-user-{primary}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Okta user records are identity-inventory entries, not "
            "vulnerabilities.  Cross-check the principal against the "
            "other agents' findings — anything reported against this "
            "login indicates a real exposure on a known managed "
            "identity.  Deactivate the user in Okta if the account "
            "should no longer have tenant access."
        ),
        "data": "",
        "refs": collect_user_refs(user),
        "cve": [],
        "cvss3": {},
        "tags": ["okta", "identity", "user"],
    }
    return {
        "ip": SENTINEL_IP,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": f"Okta user {primary}",
        "vulnerabilities": [vuln],
    }


def collect_log_refs(event):
    """Walk an Okta System Log event for identity / network pivots."""
    refs = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(event, dict):
        return refs
    uuid = _str(event.get("uuid"))
    if uuid:
        add(f"Okta-EventUUID: {uuid}")
    event_type = _str(event.get("eventType"))
    if event_type:
        add(f"Okta-EventType: {event_type}")
    published = _str(event.get("published"))
    if published:
        add(f"Okta-Published: {published}")
    actor = event.get("actor") or {}
    if isinstance(actor, dict):
        alt = _str(actor.get("alternateId")) or _str(actor.get("displayName"))
        if alt:
            add(f"Okta-Actor: {alt}")
    client = event.get("client") or {}
    if isinstance(client, dict):
        ip = _str(client.get("ipAddress"))
        if ip:
            add(f"Okta-ClientIP: {ip}")
        geo = client.get("geographicalContext") or {}
        if isinstance(geo, dict):
            country = _str(geo.get("country"))
            if country:
                add(f"Okta-Country: {country}")
    outcome = event.get("outcome") or {}
    if isinstance(outcome, dict):
        result = _str(outcome.get("result"))
        if result:
            add(f"Okta-Outcome: {result}")
        reason = _str(outcome.get("reason"))
        if reason:
            add(f"Okta-Reason: {reason}")
    targets = event.get("target")
    if isinstance(targets, list):
        for t in targets:
            if isinstance(t, dict):
                tid = _str(t.get("alternateId")) or _str(t.get("displayName"))
                if tid:
                    add(f"Okta-Target: {tid}")
    return refs


def build_log_host(event, filter_expr):
    """Build a Faraday host dict for an Okta System Log event."""
    if not isinstance(event, dict):
        return None
    client = event.get("client") or {}
    ip = _str(client.get("ipAddress")) if isinstance(client, dict) else ""
    if not ip or ip in ("0.0.0.0", "127.0.0.1", "::1"):
        ip = SENTINEL_IP

    hostnames = []
    seen = set()
    actor = event.get("actor") or {}
    if isinstance(actor, dict):
        for key in ("alternateId", "displayName"):
            s = _str(actor.get(key))
            if s and s not in seen:
                seen.add(s)
                hostnames.append(s)
    targets = event.get("target")
    if isinstance(targets, list):
        for t in targets:
            if isinstance(t, dict):
                for key in ("alternateId", "displayName"):
                    s = _str(t.get(key))
                    if s and s not in seen:
                        seen.add(s)
                        hostnames.append(s)

    event_type = _str(event.get("eventType")) or "unknown event"
    actor_label = ""
    if isinstance(actor, dict):
        actor_label = _str(actor.get("alternateId")) or _str(actor.get("displayName"))
    label_subject = actor_label or (hostnames[0] if hostnames else "")
    label = f"[IDENTITY] Okta event: {event_type}"
    if label_subject:
        label = f"{label} ({label_subject})"

    desc_parts = []
    for key in ("uuid", "eventType", "displayMessage", "severity", "published"):
        v = event.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    for key in ("actor", "client", "outcome", "target", "authenticationContext", "securityContext"):
        v = event.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if filter_expr:
        desc_parts.append(f"okta_filter: {filter_expr}")

    vuln = {
        "name": label[:200],
        "desc": "\n".join(desc_parts),
        "severity": map_log_severity(event.get("severity")),
        "external_id": _str(event.get("uuid"))[:200] or f"okta-log-{label_subject}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Okta System Log events are identity-attack-surface "
            "signals.  Review the actor / client / outcome enrichment "
            "and pivot via the Okta-Actor / Okta-ClientIP / "
            "Okta-Target refs.  Confirm the activity against the "
            "operator's baseline; revoke the session or step up MFA "
            "in Okta if the event indicates compromise."
        ),
        "data": "",
        "refs": collect_log_refs(event),
        "cve": [],
        "cvss3": {},
        "tags": ["okta", "identity", "log"],
    }
    return {
        "ip": ip,
        "os": "",
        "hostnames": hostnames,
        "mac": "",
        "description": f"Okta event {event_type}",
        "vulnerabilities": [vuln],
    }


def collect_hook_refs(hook):
    refs = []
    seen = set()

    def add(text):
        s = _str(text)
        if not s or s in seen:
            return
        seen.add(s)
        refs.append({"name": s, "type": "other"})

    if not isinstance(hook, dict):
        return refs
    add(f"Okta-EventHookId: {_str(hook.get('id'))}")
    add(f"Okta-EventHookStatus: {_str(hook.get('status'))}")
    add(f"Okta-EventHookVerification: {_str(hook.get('verificationStatus'))}")
    channel = hook.get("channel") or {}
    if isinstance(channel, dict):
        add(f"Okta-EventHookChannel: {_str(channel.get('type'))}")
        config = channel.get("config") or {}
        if isinstance(config, dict):
            add(f"Okta-EventHookURI: {_str(config.get('uri'))}")
    events = hook.get("events") or {}
    if isinstance(events, dict):
        items = events.get("items")
        if isinstance(items, list) and items:
            add(f"Okta-EventHookEvents: {','.join(_str(i) for i in items if i)}")
    return [r for r in refs if r["name"].split(": ", 1)[-1].strip()]


def build_event_hook_host(hook):
    """Build a Faraday host dict for an Okta event hook configuration."""
    if not isinstance(hook, dict):
        return None
    name = _str(hook.get("name")) or _str(hook.get("id")) or "unknown hook"
    channel = hook.get("channel") or {}
    uri = ""
    if isinstance(channel, dict):
        config = channel.get("config") or {}
        if isinstance(config, dict):
            uri = _str(config.get("uri"))

    desc_parts = []
    for key in ("id", "name", "status", "verificationStatus", "created", "updated"):
        v = hook.get(key)
        if v in (None, "", [], {}):
            continue
        desc_parts.append(f"{key}: {_serialise(v)}")
    if channel:
        desc_parts.append(f"channel: {_serialise(channel)}")
    events = hook.get("events")
    if events:
        desc_parts.append(f"events: {_serialise(events)}")

    vuln = {
        "name": f"[IDENTITY] Okta event hook: {name}"[:200],
        "desc": "\n".join(desc_parts),
        "severity": "info",
        "external_id": _str(hook.get("id"))[:200] or f"okta-eventhook-{name}"[:200],
        "type": "Vulnerability",
        "status": "open",
        "resolution": (
            "Okta event hooks are configuration entries — operators "
            "audit them to confirm which external systems receive "
            "the Okta event stream.  Disable / delete the hook in "
            "Okta if the destination URI is no longer authorised."
        ),
        "data": "",
        "refs": collect_hook_refs(hook),
        "cve": [],
        "cvss3": {},
        "tags": ["okta", "identity", "event-hook"],
    }
    return {
        "ip": SENTINEL_IP,
        "os": "",
        "hostnames": [name] + ([uri] if uri else []),
        "mac": "",
        "description": f"Okta event hook {name}",
        "vulnerabilities": [vuln],
    }


def main():
    started = time.time()

    filter_expr = validate_filter(env("EXECUTOR_CONFIG_OKTA_FILTER"))
    limit = validate_limit(env("EXECUTOR_CONFIG_OKTA_LIMIT"))
    event_hooks_enabled = validate_event_hooks(env("EXECUTOR_CONFIG_OKTA_EVENT_HOOKS"))
    pages = validate_pages(env("OKTA_PAGES"))

    host = env("OKTA_DOMAIN", required=True)
    token = env("OKTA_API_TOKEN", required=True)

    if not normalize_base_url(host):
        log("OKTA_DOMAIN is required")
        sys.exit(1)

    try:
        import requests  # noqa: WPS433 — lazy import keeps unit tests light
    except ImportError:
        log("requests is not installed in the executor environment")
        sys.exit(1)

    headers = auth_headers(token)
    users_url = build_users_url(host, limit, filter_expr)
    logs_url = build_logs_url(host, limit, filter_expr)

    user_hits = fetch_all(requests, users_url, headers, pages, "/api/v1/users")
    log_hits = fetch_all(requests, logs_url, headers, pages, "/api/v1/logs")

    hook_hits = []
    if event_hooks_enabled:
        try:
            resp = requests.get(
                build_event_hooks_url(host),
                headers=headers,
                timeout=TIMEOUT,
            )
        except Exception as exc:  # noqa: BLE001 — surface any network exc
            log(f"GET /api/v1/eventHooks failed: {exc}")
            resp = None
        if resp is not None:
            if resp.status_code == 401:
                log("Okta /api/v1/eventHooks rejected (401). Check OKTA_API_TOKEN.")
                sys.exit(1)
            elif resp.status_code >= 400:
                log(f"Okta /api/v1/eventHooks failed ({resp.status_code}): " f"{resp.text[:500]}")
            else:
                try:
                    body = resp.json()
                except ValueError:
                    log("Okta /api/v1/eventHooks response was not JSON")
                    body = None
                if isinstance(body, list):
                    hook_hits = [h for h in body if isinstance(h, dict)]

    log(
        f"Processing {len(user_hits)} Okta users + {len(log_hits)} log events "
        f"+ {len(hook_hits)} event hooks (filter={filter_expr!r}, "
        f"limit={limit}, pages={pages}, event_hooks={event_hooks_enabled})"
    )

    hosts_out = []
    for u in user_hits:
        built = build_user_host(u, filter_expr)
        if built is not None:
            hosts_out.append(built)
    for ev in log_hits:
        built = build_log_host(ev, filter_expr)
        if built is not None:
            hosts_out.append(built)
    for hk in hook_hits:
        built = build_event_hook_host(hk)
        if built is not None:
            hosts_out.append(built)

    output = {
        "hosts": hosts_out,
        "command": {
            "tool": "okta",
            "command": "okta",
            "params": (
                f"filter={filter_expr}," f"limit={limit}," f"event_hooks={event_hooks_enabled}," f"pages={pages}"
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
