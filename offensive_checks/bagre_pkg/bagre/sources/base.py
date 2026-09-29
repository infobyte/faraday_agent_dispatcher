"""Abstract base class for credential sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import List, Dict, Any, Optional


CredentialRow = Dict[str, Any]


class CredentialSource(ABC):
    """A source that produces credential rows for a target domain."""

    @abstractmethod
    def query_credentials(
        self,
        target_domain: Optional[str] = None,
        target_subdomain: Optional[str] = None,
        mail_domain: Optional[str] = None,
        uri_path: Optional[str] = None,
        limit: int = 100,
    ) -> List[CredentialRow]:
        """Return credential rows matching the filters.

        Implementations must respect `limit` and return at most that many
        rows. Returned dicts MUST follow the schema documented in
        ``bagre/sources/__init__.py``.
        """

    @contextmanager
    def connection(self):
        """Context manager hook. Default is a no-op; subclasses may override
        (e.g., ClickHouse needs explicit connect/disconnect)."""
        yield self

    @property
    def name(self) -> str:
        return self.__class__.__name__
