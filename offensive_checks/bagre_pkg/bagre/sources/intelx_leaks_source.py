"""Intelligence X (3.intelx.io) Leaks-API credential source.

Uses the Identity Portal's Leaks API (separate from /intelligent/search on
2.intelx.io) which returns matched LINES directly — no /file/read calls,
so the per-file download quota does not apply.

Flow:
    1. POST /live/search/internal?selector=<target>     -> {id}
    2. Poll /live/search/result?id=<id>&format=1        -> {records: [LineRecord, ...]}
       (status 0 = results, 1 = keep polling, 2 = done, 3 = not found)
    3. Feed each record's `linea` text through the existing line-parser so
       we reuse the URL:user:pass / host:user:pass / email:pass / block
       regexes — no separate parser to maintain.
    4. Filter by host_in_scope so a subdomain search stays scoped.
    5. /live/search/terminate to release server resources.

Auth is the same INTELX_API_KEY (the key just needs the "Identity Portal"
license enabled on the IntelX account).
"""

from __future__ import annotations

import sys
import time
from typing import List, Optional

import requests

from .base import CredentialSource, CredentialRow
from ..config import IntelXConfig
from .intelx_source import (
    parse_credentials_from_text,
    host_in_scope,
    reconstruct_host,
    _decompose_url,
)


# Status codes for /live/search/result
_STATUS_RESULT = 0
_STATUS_POLL_AGAIN = 1
_STATUS_TERMINATED = 2
_STATUS_NOT_FOUND = 3

# The Leaks API is hosted on a different IntelX subdomain from the regular
# Search API. Hardcoded because it's part of the API contract.
_LEAKS_BASE_URL = "https://3.intelx.io"


class IntelXLeaksSource(CredentialSource):
    """CredentialSource backed by the IntelX Identity Portal Leaks API."""

    def __init__(self, config: IntelXConfig):
        if not config.api_key:
            raise ValueError(
                "IntelX Leaks source requires INTELX_API_KEY (env) or "
                "[intelx] api_key (config)."
            )
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "x-key": config.api_key,
            "User-Agent": "bagre-agent/1.0 (+https://faradaysec.com)",
        })

    def _log(self, msg: str) -> None:
        print(f"[BAGRE-INTELX-LEAKS] {msg}", file=sys.stderr, flush=True)

    def _start(self, selector: str, limit: int) -> Optional[str]:
        try:
            r = self.session.get(
                f"{_LEAKS_BASE_URL}/live/search/internal",
                params={
                    "selector": selector,
                    "limit": limit,
                    "bucket": "",
                    "skipinvalid": "true",
                    "analyze": "false",
                },
                timeout=self.config.timeout_s,
            )
        except requests.RequestException as e:
            self._log(f"search start failed: {e}")
            return None
        if r.status_code != 200:
            self._log(f"search start HTTP {r.status_code}: {r.text[:200]}")
            return None
        data = r.json() if r.content else {}
        if data.get("status") != 0:
            self._log(f"selector rejected (status={data.get('status')}): {data}")
            return None
        return data.get("id")

    def _terminate(self, job_id: str) -> None:
        try:
            self.session.get(
                f"{_LEAKS_BASE_URL}/live/search/terminate",
                params={"id": job_id},
                timeout=self.config.timeout_s,
            )
        except requests.RequestException:
            pass

    def query_credentials(
        self,
        target_domain: Optional[str] = None,
        target_subdomain: Optional[str] = None,
        mail_domain: Optional[str] = None,
        uri_path: Optional[str] = None,
        limit: Optional[int] = 100,
    ) -> List[CredentialRow]:
        unlimited = limit is None or limit <= 0
        selector = target_domain or mail_domain or ""
        if target_subdomain:
            stripped = target_subdomain.replace("%", "").strip(".")
            if stripped:
                selector = stripped if not target_domain else f"{stripped}.{target_domain}"
        if not selector:
            return []

        target_scope = (target_domain or "").strip(".").lower()
        # The Leaks API's `limit` is per-bucket, so set generously and let our
        # row-limit / scope-filter do the real capping.
        api_limit = 1000 if unlimited else max(limit * 3, 100)

        self._log(
            f"selector='{selector}' api_limit={api_limit} "
            f"row_limit={'ALL' if unlimited else limit}"
        )
        job_id = self._start(selector, api_limit)
        if not job_id:
            return []
        self._log(f"job_id={job_id}")

        rows: List[CredentialRow] = []
        seen = set()
        total_lines = 0
        try:
            for attempt in range(self.config.poll_max_attempts):
                try:
                    r = self.session.get(
                        f"{_LEAKS_BASE_URL}/live/search/result",
                        params={"id": job_id, "format": 1},
                        timeout=self.config.timeout_s,
                    )
                except requests.RequestException as e:
                    self._log(f"poll failed: {e}")
                    break
                if r.status_code != 200:
                    self._log(f"poll HTTP {r.status_code}: {r.text[:200]}")
                    break
                data = r.json() if r.content else {}
                status = data.get("status", _STATUS_NOT_FOUND)
                records = data.get("records") or []
                total_lines += len(records)

                for rec in records:
                    linea = rec.get("linea") or ""
                    if not linea:
                        continue
                    # Reuse the inline-triple / combo / block parser from the
                    # file-based source so we keep one canonical implementation.
                    for parsed in parse_credentials_from_text(linea):
                        # Scope-filter on full host.
                        if target_scope:
                            row_host = reconstruct_host(parsed)
                            row_mail_host = ".".join(
                                p for p in [
                                    (parsed.get("mail_subdomain") or "").lower(),
                                    (parsed.get("mail_domain") or "").lower(),
                                    (parsed.get("mail_tld") or "").lower(),
                                ] if p
                            )
                            if not host_in_scope(row_host, target_scope) and not host_in_scope(row_mail_host, target_scope):
                                continue
                        key = (
                            (parsed.get("user") or "").lower(),
                            parsed.get("password") or "",
                            reconstruct_host(parsed),
                        )
                        if key in seen:
                            continue
                        seen.add(key)
                        rows.append(parsed)
                        if not unlimited and len(rows) >= limit:
                            break
                    if not unlimited and len(rows) >= limit:
                        break

                if not unlimited and len(rows) >= limit:
                    break
                if status in (_STATUS_TERMINATED, _STATUS_NOT_FOUND):
                    break
                if status == _STATUS_POLL_AGAIN:
                    time.sleep(self.config.poll_interval_s)
                elif status == _STATUS_RESULT:
                    # More results may be on the way — keep polling, but
                    # with the standard interval so we don't hammer.
                    time.sleep(self.config.poll_interval_s)
        finally:
            self._terminate(job_id)

        self._log(
            f"returning {len(rows)} unique scoped credential rows "
            f"(parsed from {total_lines} lines)"
        )
        return rows if unlimited else rows[:limit]
