#!/usr/bin/env python3
"""
Utility module for centralized agent configuration handling.
This module provides a standard way to read and parse common AGENT_CONFIG_*
environment variables that are set by the dispatcher.
"""

import os
from typing import List, Optional


class CommonExecutorParameters:
    """
    Centralized handler for common AGENT_CONFIG_* environment variables.
    This class provides a clean interface for accessing agent configuration
    without requiring manual environment variable parsing in each executor.
    """

    def __init__(self):
        """Initialize the agent configuration by reading environment variables."""
        self._ignore_info = self._parse_bool("AGENT_CONFIG_IGNORE_INFO", False)
        self._resolve_hostname = self._parse_bool("AGENT_CONFIG_RESOLVE_HOSTNAME", True)
        self._min_severity = os.getenv("AGENT_CONFIG_MIN_SEVERITY", None)
        self._max_severity = os.getenv("AGENT_CONFIG_MAX_SEVERITY", None)
        self._vuln_tag = self._parse_list("AGENT_CONFIG_VULN_TAG")
        self._service_tag = self._parse_list("AGENT_CONFIG_SERVICE_TAG")
        self._hostname_tag = self._parse_list("AGENT_CONFIG_HOSTNAME_TAG")

    @staticmethod
    def _parse_bool(env_var: str, default: bool = False) -> bool:
        """Parse a boolean environment variable."""
        value = os.getenv(env_var, str(default)).lower()
        return value == "true"

    @staticmethod
    def _parse_list(env_var: str) -> Optional[List[str]]:
        """Parse a comma-separated list environment variable."""
        value = os.getenv(env_var, None)
        if value:
            return value.split(",")
        return None

    @property
    def ignore_info(self) -> bool:
        """Whether to ignore info level vulnerabilities."""
        return self._ignore_info

    @property
    def resolve_hostname(self) -> bool:
        """Whether to resolve hostnames when possible."""
        return self._resolve_hostname

    @property
    def min_severity(self) -> Optional[str]:
        """Minimum severity level for vulnerabilities."""
        return self._min_severity

    @property
    def max_severity(self) -> Optional[str]:
        """Maximum severity level for vulnerabilities."""
        return self._max_severity

    @property
    def vuln_tag(self) -> Optional[List[str]]:
        """Tags to add to vulnerabilities."""
        return self._vuln_tag

    @property
    def service_tag(self) -> Optional[List[str]]:
        """Tags to add to services."""
        return self._service_tag

    @property
    def hostname_tag(self) -> Optional[List[str]]:
        """Tags to add to hosts."""
        return self._hostname_tag

    def to_plugin_kwargs(self) -> dict:
        """
        Return a dictionary suitable for passing to Faraday plugins.
        Only includes non-None values to avoid overriding plugin defaults.
        """
        kwargs = {
            "ignore_info": self.ignore_info,
            "hostname_resolution": self.resolve_hostname,
        }

        if self.min_severity is not None:
            kwargs["min_severity"] = self.min_severity

        if self.max_severity is not None:
            kwargs["max_severity"] = self.max_severity

        if self.vuln_tag is not None:
            kwargs["vuln_tag"] = self.vuln_tag

        if self.service_tag is not None:
            kwargs["service_tag"] = self.service_tag

        if self.hostname_tag is not None:
            kwargs["host_tag"] = self.hostname_tag

        return kwargs


def get_common_parameters() -> CommonExecutorParameters:
    """
    Convenience function to get agent configuration.
    This is the recommended way to access agent configuration in executors.
    """
    return CommonExecutorParameters()
