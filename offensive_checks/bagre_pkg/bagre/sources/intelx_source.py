"""Intelligence X (intelx.io) credential source.

Searches IntelX for files mentioning the target domain, downloads the
matching items, parses common stealer-log credential formats, and returns
rows in the canonical credential schema documented in
``bagre/sources/__init__.py``.

API reference: https://2.intelx.io (account-specific). All requests are
authenticated with the ``x-key`` header — the key MUST come from
``INTELX_API_KEY`` (or the [intelx] config block). It is never written to
source.
"""

from __future__ import annotations

import re
import sys
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

import requests

from .base import CredentialSource, CredentialRow
from ..config import IntelXConfig

# Status codes returned by /intelligent/search and /intelligent/search/result
_STATUS_OK = 0
_STATUS_NO_MORE = 1
_STATUS_NO_RESULTS = 2  # historically "search aborted"
_STATUS_DONE = 3


# Heuristic filters applied to IntelX record names BEFORE downloading them.
# Stealer-log archives contain many sibling files per victim — most of them
# (cookies, browsing history, autofill, system info, screenshots) match a
# domain search but have no credentials. Skipping these by name saves the
# /file/read credit and avoids wasting the max_files budget.
_SKIP_NAME_SUBSTRINGS = (
    "cookies",          # */cookies/Chrome [Default].txt
    "browser/cookies",  # */Browser/Cookies/Chrome_Default_[4232].txt
    "/history",         # */History/*.txt
    "_history.",        # url_uniq_history.log
    "/autofill",
    "/bookmarks",
    "/downloads",
    "/screenshot",
    "/web data",
    "/system",          # System.txt / system_info.txt
    "wallets",
    "fdns_",            # MX/DNS records dumps
    "mx records",
    "dns_zones",
    "domains-detailed",
)
# When a record name contains any of these substrings it is treated as a
# high-confidence credential dump and downloaded first. Anything that
# names a known credential-list product (LEAKBASE, ULP, BASE, HUNTER,
# combolist, etc.) goes here.
_PRIORITY_NAME_SUBSTRINGS = (
    "passwords",        # Passwords.txt / All Passwords.txt
    "urlpw",            # LEAKBASE URL+PW files
    "leakbase",
    "credential",
    "combo",
    "_pw.",
    "_pw_",
    "/pw.",
    "/pw/",
    "login",
    "ulp",              # @KURTXT_ULP, HUNTER ULP, ULP @FATETRAFFIC etc.
    "lb.sb",            # 90kk_URLPW_LB.SB / 63m_URLPW_LB.SB / etc.
    " ulp ",
    "uhq",              # 49M BASE CORP UHQ
    " base ",           # "49M BASE CORP" credential collections
    "iggycloud",        # @IGGYCLOUD combolist
    "fatetraffic",      # @FATETRAFFIC combolist
    "skylords",         # @SKYLORDS combolist
)


def _likely_credential_file(name: str) -> int:
    """Score a record name. Higher = more likely to contain credentials.

    Returns:
        2  — name matches a priority pattern (likely a password dump)
        1  — name looks neutral (might be credentials, worth a try)
        0  — name matches a skip pattern (cookies / history / system info)
    """
    n = (name or "").lower()
    for sub in _PRIORITY_NAME_SUBSTRINGS:
        if sub in n:
            return 2
    for sub in _SKIP_NAME_SUBSTRINGS:
        if sub in n:
            return 0
    return 1


# ---------------------------------------------------------------------------
# URL → schema decomposition
# ---------------------------------------------------------------------------

# Lazy tldextract import — the dep is optional; if absent we fall back to a
# best-effort split on the last dot. tldextract handles multi-part TLDs
# (e.g. ".com.ar") correctly which matters for credential URL components.
_tldextract = None


def _decompose_url(url: str) -> Dict[str, Any]:
    """Split a URL into the canonical credential-row URL fields."""
    global _tldextract
    fields = {
        "uri_protocol": "",
        "uri_subdomain": "",
        "uri_domain": "",
        "uri_tld": "",
        "uri_port": 0,
        "uri_path": "",
        "uri_query": "",
    }
    if not url:
        return fields

    if "://" not in url:
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return fields

    fields["uri_protocol"] = (parsed.scheme or "").lower()
    fields["uri_path"] = parsed.path or ""
    fields["uri_query"] = parsed.query or ""
    # parsed.port raises ValueError if the parsed value is out of 0-65535
    # (e.g. when the regex over-matches a colon-separated triple where the
    # middle component is a large numeric id, not a real port).
    try:
        if parsed.port:
            fields["uri_port"] = int(parsed.port)
    except (ValueError, TypeError):
        pass

    host = (parsed.hostname or "").lower()
    if not host:
        return fields

    if _tldextract is None:
        try:
            import tldextract as _tld  # type: ignore
            _tldextract = _tld
        except ImportError:
            _tldextract = False

    if _tldextract:
        ext = _tldextract.extract(host)
        fields["uri_subdomain"] = ext.subdomain or ""
        fields["uri_domain"] = ext.domain or ""
        fields["uri_tld"] = ext.suffix or ""
    else:
        # Fallback: split on dots, treat last token as TLD, second-to-last
        # as domain, rest as subdomain.
        parts = host.split(".")
        if len(parts) == 1:
            fields["uri_domain"] = parts[0]
        elif len(parts) == 2:
            fields["uri_domain"], fields["uri_tld"] = parts
        else:
            fields["uri_subdomain"] = ".".join(parts[:-2])
            fields["uri_domain"] = parts[-2]
            fields["uri_tld"] = parts[-1]

    return fields


def host_in_scope(candidate_host: str, target: str) -> bool:
    """True if candidate_host is the target host or a sub-host of it.

    Scope is determined by how specific the target is:
      * target = "movistar.com.ar"          -> matches movistar.com.ar AND
                                                any *.movistar.com.ar
      * target = "canales.movistar.com.ar"  -> matches ONLY
                                                canales.movistar.com.ar and
                                                *.canales.movistar.com.ar
                                                (NOT www/iris/etc.)

    This lets a subdomain search stay scoped to that subdomain instead of
    leaking the whole registered domain.
    """
    c = (candidate_host or "").strip(".").lower()
    t = (target or "").strip(".").lower()
    if not c or not t:
        return False
    return c == t or c.endswith("." + t)


def reconstruct_host(row: Dict[str, Any]) -> str:
    """Build the full host from a credential row's URL components."""
    parts = [
        (row.get("uri_subdomain") or "").lower(),
        (row.get("uri_domain") or "").lower(),
        (row.get("uri_tld") or "").lower(),
    ]
    return ".".join(p for p in parts if p)


def _decompose_email(email: str) -> Dict[str, Any]:
    """Split an email into the canonical mail_* fields."""
    fields = {
        "mail_username": "",
        "mail_subdomain": "",
        "mail_domain": "",
        "mail_tld": "",
    }
    if not email or "@" not in email:
        return fields
    user, _, host = email.partition("@")
    fields["mail_username"] = user.strip()
    url_fields = _decompose_url("http://" + host.strip())
    fields["mail_subdomain"] = url_fields["uri_subdomain"]
    fields["mail_domain"] = url_fields["uri_domain"]
    fields["mail_tld"] = url_fields["uri_tld"]
    return fields


# ---------------------------------------------------------------------------
# Credential parsing
# ---------------------------------------------------------------------------

# Block-style: URL:/Username:/Password: spread across consecutive lines.
_BLOCK_URL_RE = re.compile(r"^\s*(?:url|host)\s*[:=]\s*(?P<url>\S.*?)\s*$", re.IGNORECASE)
_BLOCK_USER_RE = re.compile(r"^\s*(?:user(?:name)?|login|email)\s*[:=]\s*(?P<user>\S.*?)\s*$", re.IGNORECASE)
_BLOCK_PASS_RE = re.compile(r"^\s*(?:pass(?:word)?|pwd)\s*[:=]\s*(?P<pass>\S.*?)\s*$", re.IGNORECASE)

# LEAKBASE / Redline stealer-log format (most common in IntelX leaks.private
# / leaks.public): "<URL> <user>:<password>" on a single line — URL has
# scheme + host (+ optional path), separator is whitespace, then user/pass
# split by the FIRST colon after the URL.
_INLINE_SPACE_TRIPLE_RE = re.compile(
    r"^(?P<url>https?://\S+)\s+(?P<user>[^:\s]+):(?P<pass>\S.*?)\s*$",
    re.IGNORECASE,
)

# Older/legacy triple: "url:user:pass" — URL anchored on https?:// and
# greedy-trimmed up to the last two colons.
_INLINE_COLON_TRIPLE_RE = re.compile(
    r"^(?P<url>https?://[^\s]+?):(?P<user>[^:\s]+):(?P<pass>[^\s]+)\s*$",
    re.IGNORECASE,
)

# Bare-host triple: "host[:port][/path]:user:pass" — scheme omitted.
# Common in LEAKBASE / 1kkk_URLPW combolists where each line is just
# host + creds, e.g.:
#   portal.faradaysec.com:user@email.com:HATIKO4000
#   slmhkwrd.apps.faradaysec.com:faraday:pxfC1hL3dtm0J
# Anchored on the host having at least one dot and a 2+-letter TLD so we
# don't grab arbitrary three-token colon-separated content (e.g. CSV rows
# starting with a domain-like field). Port is bounded to 1-5 digits AND
# the _decompose_url helper double-checks urlparse(...).port for the
# 0-65535 range so an over-matching line like host.com:99999:user:pass
# can't crash the parser.
_INLINE_HOST_TRIPLE_RE = re.compile(
    r"^(?P<url>(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::[0-9]{1,5})?(?:/[^\s:]*)?):(?P<user>[^:\s]+):(?P<pass>\S+)\s*$",
)

# Combo line: email:password
_COMBO_RE = re.compile(
    r"^(?P<user>[^\s:@]+@[^\s:@]+\.[^\s:@]+):(?P<pass>\S+)\s*$"
)


_JUNK_USER_CHARS = re.compile(r"[=;!]")


def _is_junk_username(user: str) -> bool:
    """Reject obviously-non-username tokens picked up by the regex parser.

    Combolist / paste files frequently embed session-cookie fragments
    (e.g. ``jsessionid=ABCDEF...!1597910706!-18476794!...``), telemetry
    blobs, or query strings between real credential lines. Anything with
    ``=`` / ``;`` / ``!`` or longer than 64 chars is not a real login.
    Real usernames seen in scope (``avelez``, ``mpquin2000@hotmail.com``,
    ``tmoviles\\earenas``) all pass.
    """
    if not user:
        return True
    u = user.strip()
    if len(u) > 64:
        return True
    if _JUNK_USER_CHARS.search(u):
        return True
    return False


def _make_row(url: str, user: str, password: str) -> Optional[CredentialRow]:
    """Build a credential row in the canonical schema.

    Returns ``None`` if the username is junk (cookie / query-string noise);
    callers must filter Nones out of the result list.
    """
    if _is_junk_username(user):
        return None
    row: CredentialRow = {
        "user": user.strip() if user else "",
        "password": password,
        "phone": "",
        "hash": "",
    }
    row.update(_decompose_url(url))
    row.update(_decompose_email(user) if user and "@" in user else _decompose_email(""))
    return row


def parse_credentials_from_text(content: str) -> List[CredentialRow]:
    """Extract credential rows from a stealer-log / paste-style text blob.

    Supports three common patterns:
      1. Block layout (URL:/USER:/PASS: across lines).
      2. Inline triple ``url:user:password``.
      3. Combo line ``email:password`` (URL will be empty).
    """
    rows: List[CredentialRow] = []

    # --- Pass 1: block layout ---
    current = {"url": None, "user": None, "pass": None}

    def flush_block():
        if current["user"] and current["pass"] is not None:
            rows.append(_make_row(current["url"] or "", current["user"], current["pass"]))
        current["url"] = current["user"] = current["pass"] = None

    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        if not line:
            flush_block()
            continue
        m = _BLOCK_URL_RE.match(line)
        if m:
            if current["user"] is not None and current["pass"] is not None:
                flush_block()
            current["url"] = m.group("url")
            continue
        m = _BLOCK_USER_RE.match(line)
        if m:
            current["user"] = m.group("user")
            continue
        m = _BLOCK_PASS_RE.match(line)
        if m:
            current["pass"] = m.group("pass")
            flush_block()
            continue
    flush_block()

    # --- Pass 2: single-line triples / combos. Skip lines already consumed
    # by the block parser by checking for the URL/USER/PASS prefixes. ---
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if _BLOCK_URL_RE.match(line) or _BLOCK_USER_RE.match(line) or _BLOCK_PASS_RE.match(line):
            continue
        # Try the LEAKBASE space-separated format first (most common).
        m = _INLINE_SPACE_TRIPLE_RE.match(line)
        if m:
            rows.append(_make_row(m.group("url"), m.group("user"), m.group("pass")))
            continue
        # Then legacy colon-separated triple (URL has scheme).
        m = _INLINE_COLON_TRIPLE_RE.match(line)
        if m:
            rows.append(_make_row(m.group("url"), m.group("user"), m.group("pass")))
            continue
        # Then bare-host triple (LEAKBASE-style, no scheme).
        m = _INLINE_HOST_TRIPLE_RE.match(line)
        if m:
            rows.append(_make_row(m.group("url"), m.group("user"), m.group("pass")))
            continue
        # Finally bare email:password combolist line.
        m = _COMBO_RE.match(line)
        if m:
            rows.append(_make_row("", m.group("user"), m.group("pass")))

    return rows


# ---------------------------------------------------------------------------
# IntelX HTTP client
# ---------------------------------------------------------------------------


class IntelXSource(CredentialSource):
    """CredentialSource backed by intelx.io."""

    def __init__(self, config: IntelXConfig):
        if not config.is_configured():
            raise ValueError(
                "IntelX source requires INTELX_API_KEY to be set "
                "(env var or [intelx] config block)."
            )
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "x-key": config.api_key,
            "User-Agent": "bagre-agent/1.0 (+https://faradaysec.com)",
        })

    def _log(self, message: str) -> None:
        print(f"[BAGRE-INTELX] {message}", file=sys.stderr, flush=True)

    def _matches_filters(
        self,
        row: CredentialRow,
        target_domain: Optional[str],
        target_subdomain: Optional[str],
        mail_domain: Optional[str],
        uri_path: Optional[str],
    ) -> bool:
        if target_domain:
            # Scope-aware host match: searching a subdomain
            # (canales.movistar.com.ar) returns only that host and its
            # sub-hosts; searching a registered domain (movistar.com.ar)
            # returns the whole domain tree. See host_in_scope().
            target = target_domain.strip(".").lower()
            row_host = reconstruct_host(row)
            uri_matches = host_in_scope(row_host, target)
            if not uri_matches:
                # Fall back to mail-domain scope so email-only leaks for the
                # target still match.
                row_mail_host = ".".join(
                    p for p in [
                        (row.get("mail_subdomain") or "").lower(),
                        (row.get("mail_domain") or "").lower(),
                        (row.get("mail_tld") or "").lower(),
                    ] if p
                )
                mail_ok = host_in_scope(row_mail_host, target) if row_mail_host else False
                if mail_domain and (row.get("mail_domain") or "").lower() == mail_domain.lower():
                    mail_ok = True
                if not mail_ok:
                    return False
        if target_subdomain:
            pat = target_subdomain.replace("%", "").lower()
            if pat and pat not in (row.get("uri_subdomain") or "").lower():
                return False
        if mail_domain and row.get("mail_domain", "").lower() != mail_domain.lower():
            return False
        if uri_path:
            pat = uri_path.replace("%", "").lower()
            if pat and pat not in (row.get("uri_path") or "").lower():
                return False
        return True

    # --- IntelX API plumbing -------------------------------------------------

    def _start_search(self, term: str, maxresults: int) -> Optional[str]:
        payload = {
            "term": term,
            "buckets": self.config.buckets,
            "lookuplevel": 0,
            "maxresults": maxresults,
            "timeout": 0,
            "datefrom": "",
            "dateto": "",
            "sort": 4,
            "media": 0,
            "terminate": [],
        }
        try:
            r = self.session.post(
                f"{self.config.base_url}/intelligent/search",
                json=payload,
                timeout=self.config.timeout_s,
            )
        except requests.RequestException as e:
            self._log(f"search start failed: {e}")
            return None
        if r.status_code != 200:
            self._log(f"search start HTTP {r.status_code}: {r.text[:200]}")
            return None
        data = r.json() if r.content else {}
        if data.get("status", -1) != _STATUS_OK:
            self._log(f"search start status={data.get('status')}: {data}")
            return None
        if data.get("softselectorwarning"):
            self._log(
                f"WARNING: IntelX flagged term='{term}' as a soft selector — "
                "results will likely be empty. Use a FQDN (e.g. example.com.ar) "
                "or an email/IP selector instead."
            )
        return data.get("id")

    def _poll_results(self, search_id: str, limit: int) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        for attempt in range(self.config.poll_max_attempts):
            try:
                r = self.session.get(
                    f"{self.config.base_url}/intelligent/search/result",
                    params={
                        "id": search_id,
                        "limit": limit,
                        "statistics": 0,
                        "previewlines": 0,
                    },
                    timeout=self.config.timeout_s,
                )
            except requests.RequestException as e:
                self._log(f"poll failed: {e}")
                break
            if r.status_code != 200:
                self._log(f"poll HTTP {r.status_code}: {r.text[:200]}")
                break
            data = r.json() if r.content else {}
            batch = data.get("records") or []
            records.extend(batch)
            status = data.get("status", _STATUS_DONE)
            if status in (_STATUS_NO_RESULTS, _STATUS_DONE):
                break
            if len(records) >= limit:
                break
            time.sleep(self.config.poll_interval_s)
        # Terminate the search to free resources
        try:
            self.session.get(
                f"{self.config.base_url}/intelligent/search/terminate",
                params={"id": search_id},
                timeout=self.config.timeout_s,
            )
        except requests.RequestException:
            pass
        return records[:limit]

    def _fetch_file(self, record: Dict[str, Any]) -> Optional[str]:
        size = int(record.get("size", 0) or 0)
        if size and size > self.config.max_file_size:
            return None
        params = {
            "type": 0,
            "systemid": record.get("systemid", ""),
            "bucket": record.get("bucket", ""),
        }
        if record.get("storageid"):
            params["storageid"] = record["storageid"]
        try:
            r = self.session.get(
                f"{self.config.base_url}/file/read",
                params=params,
                timeout=self.config.timeout_s,
            )
        except requests.RequestException as e:
            self._log(f"file fetch failed for {record.get('systemid')}: {e}")
            return None
        if r.status_code != 200:
            return None
        # Try UTF-8 first; fall back to Latin-1 (never fails).
        try:
            return r.content.decode("utf-8")
        except UnicodeDecodeError:
            return r.content.decode("latin-1", errors="replace")

    # --- CredentialSource interface -----------------------------------------

    def query_credentials(
        self,
        target_domain: Optional[str] = None,
        target_subdomain: Optional[str] = None,
        mail_domain: Optional[str] = None,
        uri_path: Optional[str] = None,
        limit: Optional[int] = 100,
    ) -> List[CredentialRow]:
        # limit=None (or <=0) means "no cap" — return every matching row.
        unlimited = limit is None or limit <= 0
        # max_files=0 (or <=0) means "download every credential-looking file".
        max_files = self.config.max_files
        download_all = max_files is None or max_files <= 0

        term = target_domain or mail_domain or ""
        if target_subdomain:
            stripped = target_subdomain.replace("%", "").strip(".")
            if stripped:
                term = stripped if not target_domain else f"{stripped}.{target_domain}"
        if not term:
            return []

        # Search breadth is intentionally MUCH larger than max_files: IntelX
        # returns one record per matching file, and most matches are cookies/
        # history/DNS noise that the name-filter drops. We want a broad
        # candidate pool so that after filtering there are still enough
        # credential-looking files to fill the max_files download budget.
        breadth_base = max_files if not download_all else self.config.search_maxresults
        search_breadth = max(self.config.search_maxresults, breadth_base * 10)

        self._log(
            f"searching IntelX for term='{term}' buckets={self.config.buckets} "
            f"search_breadth={search_breadth} "
            f"max_files={'ALL' if download_all else max_files} "
            f"limit={'ALL' if unlimited else limit}"
        )

        search_id = self._start_search(term, maxresults=search_breadth)
        if not search_id:
            return []

        raw_records = self._poll_results(search_id, limit=search_breadth)

        # Score and re-sort records so high-confidence credential files are
        # downloaded first. Drop records whose name screams "not credentials"
        # (cookies, history, DNS dumps, etc.) before spending a /file/read
        # credit on them.
        scored = []
        for rec in raw_records:
            score = _likely_credential_file(rec.get("name", ""))
            if score > 0:
                scored.append((score, rec))
        scored.sort(key=lambda x: x[0], reverse=True)
        records = [rec for _, rec in scored]

        files_budget = len(records) if download_all else max_files
        self._log(
            f"got {len(raw_records)} raw records, {len(records)} after name-filter "
            f"(dropped {len(raw_records) - len(records)} cookie/history/dns files); "
            f"fetching up to {files_budget} candidate files"
        )

        rows: List[CredentialRow] = []
        fetched = 0
        # Log progress every N files so a slow run doesn't appear stuck in the
        # dispatcher UI during the fetch loop.
        progress_step = max(5, files_budget // 8)
        for record in records:
            if not download_all and fetched >= max_files:
                break
            content = self._fetch_file(record)
            if not content:
                continue
            fetched += 1
            parsed = parse_credentials_from_text(content)
            for row in parsed:
                if self._matches_filters(
                    row,
                    target_domain=target_domain,
                    target_subdomain=target_subdomain,
                    mail_domain=mail_domain,
                    uri_path=uri_path,
                ):
                    rows.append(row)
                    if not unlimited and len(rows) >= limit:
                        break
            if progress_step and fetched % progress_step == 0:
                self._log(
                    f"progress: fetched {fetched}/{files_budget} files, "
                    f"{len(rows)} matching credential rows so far"
                )
            if not unlimited and len(rows) >= limit:
                break

        self._log(f"returning {len(rows)} matching credential rows (fetched {fetched} files)")
        return rows if unlimited else rows[:limit]
