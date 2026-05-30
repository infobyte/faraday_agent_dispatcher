"""ClickHouse-backed credential source.

Thin adapter over BagreClickHouseClient. The actual ClickHouse import is
performed lazily inside __init__ so that an IntelX-only deployment does
not need the clickhouse-driver package installed.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import List, Optional

from .base import CredentialSource, CredentialRow
from ..config import ClickHouseConfig


class ClickHouseSource(CredentialSource):
    def __init__(self, config: ClickHouseConfig):
        try:
            from ..clickhouse_client import BagreClickHouseClient
        except ImportError as e:
            raise RuntimeError(
                "ClickHouse source selected but clickhouse-driver is not installed. "
                "Install it or set BAGRE_SOURCE=intelx."
            ) from e
        self._client = BagreClickHouseClient(config)
        self._connected = False

    @contextmanager
    def connection(self):
        with self._client.connection():
            self._connected = True
            try:
                yield self
            finally:
                self._connected = False

    def query_credentials(
        self,
        target_domain: Optional[str] = None,
        target_subdomain: Optional[str] = None,
        mail_domain: Optional[str] = None,
        uri_path: Optional[str] = None,
        limit: int = 100,
    ) -> List[CredentialRow]:
        if not self._connected:
            with self.connection():
                return self._client.query_credentials(
                    target_domain=target_domain,
                    target_subdomain=target_subdomain,
                    mail_domain=mail_domain,
                    uri_path=uri_path,
                    limit=limit,
                )
        return self._client.query_credentials(
            target_domain=target_domain,
            target_subdomain=target_subdomain,
            mail_domain=mail_domain,
            uri_path=uri_path,
            limit=limit,
        )
