"""Credential source plug-in layer.

Every source returns rows in the **same dict shape** that the existing
ClickHouse query layer produces, so the formatter and spray engine remain
source-agnostic:

    {
      "user":           str,   # bare username (preferred)
      "password":       str,
      "uri_protocol":   str,   # "http" / "https" / ""
      "uri_subdomain":  str,
      "uri_domain":     str,
      "uri_tld":        str,
      "uri_port":       int,
      "uri_path":       str,
      "uri_query":      str,
      "mail_username":  str,
      "mail_subdomain": str,
      "mail_domain":    str,
      "mail_tld":       str,
      "phone":          str,
      "hash":           str,
    }

Missing fields default to "" / 0; the formatter already tolerates blanks.

Selection is driven by `BAGRE_SOURCE` (default: `intelx`). Use
`get_source(config)` to obtain the configured source.
"""

from __future__ import annotations

import os
from typing import Optional

from .base import CredentialSource
from .clickhouse_source import ClickHouseSource
from .intelx_source import IntelXSource
from .intelx_leaks_source import IntelXLeaksSource

DEFAULT_SOURCE = "intelx"


def get_source(config, source_name: Optional[str] = None) -> CredentialSource:
    """Resolve which credential source to use.

    Order of precedence: explicit argument > env var BAGRE_SOURCE >
    ``config.bagre.source`` (already populated by load_from_env) > default.

    Supported sources:
        intelx        — file-based search via 2.intelx.io/intelligent/search +
                        /file/read (uses the file-download quota)
        intelx-leaks  — Identity Portal Leaks API via 3.intelx.io
                        /live/search/internal (returns lines directly, NO
                        /file/read quota burn — requires the "Identity
                        Portal" license on the IntelX key)
        clickhouse    — legacy local credentials database
    """
    name = (
        source_name
        or os.environ.get("BAGRE_SOURCE")
        or getattr(getattr(config, "bagre", None), "source", None)
        or DEFAULT_SOURCE
    ).strip().lower()
    if name == "intelx":
        return IntelXSource(config.intelx)
    if name in ("intelx-leaks", "intelx_leaks", "leaks"):
        return IntelXLeaksSource(config.intelx)
    if name == "clickhouse":
        return ClickHouseSource(config.clickhouse)
    raise ValueError(
        f"Unknown BAGRE_SOURCE='{name}'. "
        "Supported values: intelx, intelx-leaks, clickhouse"
    )


__all__ = [
    "CredentialSource", "ClickHouseSource", "IntelXSource", "IntelXLeaksSource",
    "get_source", "DEFAULT_SOURCE",
]
