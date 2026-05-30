"""Configuration loader for Bagre agent.

Supports loading configuration from:
1. Configuration file (INI format)
2. Environment variables

Environment variables take precedence over config file values.
"""

import os
import configparser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List


# Default configuration file locations
DEFAULT_CONFIG_PATHS = [
    Path.home() / ".faraday" / "config" / "bagre.ini",
    Path("/etc/faraday/bagre.ini"),
    Path("bagre.ini"),
]


@dataclass
class ClickHouseConfig:
    """ClickHouse connection configuration."""
    host: str = "localhost"
    port: int = 9000
    database: str = "credentials_db"
    user: str = ""
    password: str = ""


@dataclass
class BagreConfig:
    """Bagre executor configuration."""
    query_limit: int = 100
    # Default credential source. "intelx" (default) or "clickhouse".
    source: str = "intelx"


# Defaults are duplicated here (not imported from sources.intelx_source) to
# avoid a circular import between config and the sources package.
_DEFAULT_INTELX_BUCKETS: List[str] = [
    "leaks.logs",
    "leaks.private",
    "leaks.public",
    "pastes",
    "dumpster",
]
_DEFAULT_INTELX_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


@dataclass
class IntelXConfig:
    """Intelligence X (intelx.io) source configuration."""
    api_key: str = ""
    base_url: str = "https://2.intelx.io"
    buckets: List[str] = field(default_factory=lambda: list(_DEFAULT_INTELX_BUCKETS))
    timeout_s: float = 15.0
    max_file_size: int = _DEFAULT_INTELX_MAX_FILE_SIZE
    # Each LEAKBASE / combolist chunk typically contains only 1-2 lines for
    # any given target domain (the files are 4 MB slices of billion-row
    # databases). To find the bulk of leaked credentials we have to fetch
    # many chunks. 50 is a balance between coverage and runtime — bump
    # higher via INTELX_MAX_FILES when investigating noisy targets.
    max_files: int = 50
    # How many candidate records the IntelX search itself should return.
    # This is the breadth of the search (one record per matching file);
    # most are noise that gets name-filtered before download. Kept well
    # above max_files so filtering doesn't starve the download budget.
    search_maxresults: int = 1000
    poll_interval_s: float = 1.0
    poll_max_attempts: int = 20

    def __post_init__(self):
        self.base_url = (self.base_url or "").rstrip("/")

    def is_configured(self) -> bool:
        return bool(self.api_key)


@dataclass
class Config:
    """Complete configuration for Bagre agent."""
    clickhouse: ClickHouseConfig
    bagre: BagreConfig
    intelx: IntelXConfig

    def validate(self) -> None:
        """Validate the configured source has the credentials it needs."""
        source = (self.bagre.source or "").lower()
        if source in ("intelx", "intelx-leaks", "intelx_leaks", "leaks"):
            if not self.intelx.api_key:
                raise ValueError(
                    f"Source '{source}' requires INTELX_API_KEY (env) or "
                    "[intelx] api_key (config)."
                )
        elif source == "clickhouse":
            if not self.clickhouse.user:
                raise ValueError("ClickHouse user is required")
            if not self.clickhouse.password:
                raise ValueError("ClickHouse password is required")
        else:
            raise ValueError(
                f"Unknown bagre source '{self.bagre.source}'. "
                "Supported: intelx, intelx-leaks, clickhouse"
            )


def find_config_file() -> Optional[Path]:
    """Find the first existing configuration file."""
    for path in DEFAULT_CONFIG_PATHS:
        if path.exists():
            return path
    return None


def load_from_file(config_path: Optional[Path] = None) -> Config:
    """Load configuration from INI file."""
    clickhouse = ClickHouseConfig()
    bagre = BagreConfig()
    intelx = IntelXConfig()

    if config_path is None:
        config_path = find_config_file()

    if config_path and config_path.exists():
        parser = configparser.ConfigParser()
        parser.read(config_path)

        if "clickhouse" in parser:
            ch_section = parser["clickhouse"]
            clickhouse.host = ch_section.get("host", clickhouse.host)
            clickhouse.port = int(ch_section.get("port", clickhouse.port))
            clickhouse.database = ch_section.get("database", clickhouse.database)
            clickhouse.user = ch_section.get("user", clickhouse.user)
            clickhouse.password = ch_section.get("password", clickhouse.password)

        if "bagre" in parser:
            bagre_section = parser["bagre"]
            bagre.query_limit = int(bagre_section.get("query_limit", bagre.query_limit))
            bagre.source = bagre_section.get("source", bagre.source)

        if "intelx" in parser:
            ix_section = parser["intelx"]
            intelx.api_key = ix_section.get("api_key", intelx.api_key)
            intelx.base_url = ix_section.get("base_url", intelx.base_url)
            buckets_raw = ix_section.get("buckets", "")
            if buckets_raw.strip():
                intelx.buckets = [b.strip() for b in buckets_raw.split(",") if b.strip()]
            intelx.timeout_s = float(ix_section.get("timeout_s", intelx.timeout_s))
            intelx.max_file_size = int(ix_section.get("max_file_size", intelx.max_file_size))
            intelx.max_files = int(ix_section.get("max_files", intelx.max_files))
            intelx.poll_interval_s = float(ix_section.get("poll_interval_s", intelx.poll_interval_s))
            intelx.poll_max_attempts = int(ix_section.get("poll_max_attempts", intelx.poll_max_attempts))

    return Config(clickhouse=clickhouse, bagre=bagre, intelx=intelx)


def load_from_env(config: Config) -> Config:
    """Override configuration with environment variables."""
    # ClickHouse settings
    if os.environ.get("CLICKHOUSE_HOST"):
        config.clickhouse.host = os.environ["CLICKHOUSE_HOST"]
    if os.environ.get("CLICKHOUSE_PORT"):
        config.clickhouse.port = int(os.environ["CLICKHOUSE_PORT"])
    if os.environ.get("CLICKHOUSE_DATABASE"):
        config.clickhouse.database = os.environ["CLICKHOUSE_DATABASE"]
    if os.environ.get("CLICKHOUSE_USER"):
        config.clickhouse.user = os.environ["CLICKHOUSE_USER"]
    if os.environ.get("CLICKHOUSE_PASSWORD"):
        config.clickhouse.password = os.environ["CLICKHOUSE_PASSWORD"]

    # Bagre settings
    if os.environ.get("BAGRE_QUERY_LIMIT"):
        config.bagre.query_limit = int(os.environ["BAGRE_QUERY_LIMIT"])
    if os.environ.get("BAGRE_SOURCE"):
        config.bagre.source = os.environ["BAGRE_SOURCE"].strip().lower()

    # IntelX settings
    if os.environ.get("INTELX_API_KEY"):
        config.intelx.api_key = os.environ["INTELX_API_KEY"]
    if os.environ.get("INTELX_BASE_URL"):
        config.intelx.base_url = os.environ["INTELX_BASE_URL"].rstrip("/")
    if os.environ.get("INTELX_BUCKETS"):
        config.intelx.buckets = [
            b.strip() for b in os.environ["INTELX_BUCKETS"].split(",") if b.strip()
        ]
    if os.environ.get("INTELX_TIMEOUT_S"):
        config.intelx.timeout_s = float(os.environ["INTELX_TIMEOUT_S"])
    if os.environ.get("INTELX_MAX_FILE_SIZE"):
        config.intelx.max_file_size = int(os.environ["INTELX_MAX_FILE_SIZE"])
    if os.environ.get("INTELX_MAX_FILES"):
        config.intelx.max_files = int(os.environ["INTELX_MAX_FILES"])
    if os.environ.get("INTELX_SEARCH_MAXRESULTS"):
        config.intelx.search_maxresults = int(os.environ["INTELX_SEARCH_MAXRESULTS"])

    return config


def load_config(config_path: Optional[Path] = None) -> Config:
    """Load configuration from file and environment variables.
    
    Environment variables take precedence over config file values.
    
    Args:
        config_path: Optional path to configuration file.
        
    Returns:
        Complete configuration object.
        
    Raises:
        ValueError: If required configuration is missing.
    """
    # Load from file first
    config = load_from_file(config_path)
    
    # Override with environment variables
    config = load_from_env(config)
    
    # Validate
    config.validate()
    
    return config



