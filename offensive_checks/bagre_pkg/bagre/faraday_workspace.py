"""Faraday workspace asset and service discovery.

Fetches hosts and services from a Faraday workspace via the REST API.
Used by the spray executor to discover targets to validate credentials against.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from .faraday_credentials import FaradayConfig, FaradayAPIClient


PROTOCOL_NAME_MAP = {
    "ssh": "ssh",
    "openssh": "ssh",
    "http": "http",
    "https": "https",
    "http-proxy": "http",
    "ssl/http": "https",
    "ftp": "ftp",
    "ftps": "ftp",
    "smb": "smb",
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "smtp": "smtp",
    "smtps": "smtp",
    "submission": "smtp",
    "imap": "imap",
    "imaps": "imap",
    "pop3": "pop3",
    "pop3s": "pop3",
    "rdp": "rdp",
    "ms-wbt-server": "rdp",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "mssql": "mssql",
    "ms-sql-s": "mssql",
}


PROTOCOL_PORT_MAP = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtp",
    587: "smtp",
    993: "imap",
    995: "pop3",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    8080: "http",
    8443: "https",
}


@dataclass
class WorkspaceTarget:
    """A target discovered in the Faraday workspace."""
    host_id: int
    ip: str
    hostnames: List[str] = field(default_factory=list)
    service_id: Optional[int] = None
    port: int = 0
    protocol: str = "tcp"
    service_name: str = ""
    normalized_protocol: str = ""
    # Full endpoint URL — set when the target is derived from a credential's
    # leaked endpoint (used by the http-form / https-form validators which
    # need the exact login page, not just host:port).
    url: str = ""

    @property
    def display_host(self) -> str:
        return self.hostnames[0] if self.hostnames else self.ip


def normalize_service(service_name: str, port: int) -> str:
    """Map a Faraday service name/port to a known validator protocol.

    Returns an empty string if no validator handles this service.
    """
    name = (service_name or "").strip().lower()
    if name in PROTOCOL_NAME_MAP:
        return PROTOCOL_NAME_MAP[name]
    return PROTOCOL_PORT_MAP.get(port, "")


class FaradayWorkspaceClient(FaradayAPIClient):
    """Extends FaradayAPIClient with host/service discovery."""

    def get_workspace_credentials(self) -> List[Dict[str, Any]]:
        """Fetch all credentials already stored in the workspace.

        Returns a list of {username, password, endpoint} dicts. Used by the
        password-spray so it can validate the credentials the scan already
        imported — instead of re-querying the upstream source (which burns
        IntelX file-read quota and may differ from what's triaged).
        """
        try:
            response = self.session.get(
                f"{self.base_url}/_api/v3/ws/{self.config.workspace}/credential",
                params={"page_size": 5000},
            )
            if response.status_code != 200:
                return []
            data = response.json()
            rows = data.get("rows") or data.get("data") or []
            creds = []
            for row in rows:
                val = row.get("value", row) if isinstance(row, dict) else row
                creds.append({
                    "username": val.get("username", ""),
                    "password": val.get("password", ""),
                    "endpoint": val.get("endpoint", ""),
                })
            return creds
        except Exception:
            return []

    def get_hosts(self) -> List[Dict[str, Any]]:
        """Fetch all hosts in the configured workspace."""
        try:
            response = self.session.get(
                f"{self.base_url}/_api/v3/ws/{self.config.workspace}/hosts",
                params={"page_size": 1000},
            )
            if response.status_code != 200:
                return []
            data = response.json()
            rows = data.get("rows") or data.get("data") or []
            hosts = []
            for row in rows:
                if isinstance(row, dict) and "value" in row:
                    actual = row["value"]
                    if "id" in row and "id" not in actual:
                        actual["id"] = row["id"]
                    hosts.append(actual)
                else:
                    hosts.append(row)
            return hosts
        except Exception:
            return []

    def get_services_for_host(self, host_id: int) -> List[Dict[str, Any]]:
        """Fetch all services attached to a host."""
        try:
            response = self.session.get(
                f"{self.base_url}/_api/v3/ws/{self.config.workspace}/hosts/{host_id}/services",
                params={"page_size": 1000},
            )
            if response.status_code != 200:
                return []
            data = response.json()
            if isinstance(data, list):
                rows = data
            else:
                rows = data.get("rows") or data.get("data") or data.get("services") or []
            services = []
            for row in rows:
                if isinstance(row, dict) and "value" in row:
                    actual = row["value"]
                    if "id" in row and "id" not in actual:
                        actual["id"] = row["id"]
                    services.append(actual)
                else:
                    services.append(row)
            return services
        except Exception:
            return []

    def discover_targets(
        self,
        protocols_filter: Optional[List[str]] = None,
    ) -> List[WorkspaceTarget]:
        """Walk hosts -> services and produce a flat list of WorkspaceTargets.

        Only returns services whose protocol normalizes to a value handled
        by the validator layer. If protocols_filter is provided, only those
        normalized protocols are included.
        """
        targets: List[WorkspaceTarget] = []
        hosts = self.get_hosts()
        for host in hosts:
            host_id = host.get("id") or host.get("_id")
            if not host_id:
                continue
            ip = host.get("ip") or ""
            hostnames = host.get("hostnames") or host.get("names") or []
            if isinstance(hostnames, str):
                hostnames = [hostnames]

            services = self.get_services_for_host(int(host_id))
            for svc in services:
                if (svc.get("status") or "open").lower() not in ("open", "filtered", "unknown", ""):
                    continue
                ports = svc.get("ports") or []
                if isinstance(ports, list) and ports:
                    port = int(ports[0])
                else:
                    port = int(svc.get("port") or 0)

                svc_name = svc.get("name") or ""
                svc_protocol = (svc.get("protocol") or "tcp").lower()
                normalized = normalize_service(svc_name, port)

                if not normalized:
                    continue
                if protocols_filter and normalized not in protocols_filter:
                    continue

                targets.append(
                    WorkspaceTarget(
                        host_id=int(host_id),
                        ip=ip,
                        hostnames=list(hostnames),
                        service_id=svc.get("id") or svc.get("_id"),
                        port=port,
                        protocol=svc_protocol,
                        service_name=svc_name,
                        normalized_protocol=normalized,
                    )
                )
        return targets
