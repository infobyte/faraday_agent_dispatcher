"""ClickHouse client for querying the credentials database."""

from typing import List, Dict, Any, Optional
from contextlib import contextmanager

from clickhouse_driver import Client

from .config import ClickHouseConfig


class BagreClickHouseClient:
    """Client for querying Bagre credentials database."""

    def __init__(self, config: ClickHouseConfig):
        """Initialize the ClickHouse client.
        
        Args:
            config: ClickHouse connection configuration.
        """
        self.config = config
        self._client: Optional[Client] = None

    def connect(self) -> None:
        """Establish connection to ClickHouse."""
        self._client = Client(
            host=self.config.host,
            port=self.config.port,
            database=self.config.database,
            user=self.config.user,
            password=self.config.password,
        )
        # Test connection
        self._client.execute("SELECT 1")

    def disconnect(self) -> None:
        """Close the ClickHouse connection."""
        if self._client:
            self._client.disconnect()
            self._client = None

    @contextmanager
    def connection(self):
        """Context manager for database connection."""
        try:
            self.connect()
            yield self
        finally:
            self.disconnect()

    def query_credentials(
        self,
        target_domain: Optional[str] = None,
        target_subdomain: Optional[str] = None,
        mail_domain: Optional[str] = None,
        uri_path: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query credentials for a target domain.
        
        Args:
            target_domain: The domain to search for (exact match on uri_domain).
            target_subdomain: Optional subdomain pattern (supports LIKE wildcards).
            mail_domain: Optional mail domain to filter by (exact match on mail_domain).
            uri_path: Optional URI path pattern to filter by (supports LIKE wildcards).
            limit: Maximum number of results to return.
            
        Returns:
            List of credential dictionaries.
        """
        if not self._client:
            raise RuntimeError("Not connected to ClickHouse. Call connect() first.")

        # Build query with parameters to prevent SQL injection
        conditions = []
        params = {"limit": limit}

        if target_domain:
            conditions.append("uri_domain = %(domain)s")
            params["domain"] = target_domain

        if target_subdomain:
            conditions.append("uri_subdomain LIKE %(subdomain)s")
            params["subdomain"] = target_subdomain

        if mail_domain:
            conditions.append("mail_domain = %(mail_domain)s")
            params["mail_domain"] = mail_domain

        if uri_path:
            conditions.append("uri_path LIKE %(uri_path)s")
            params["uri_path"] = uri_path

        # Build the WHERE clause
        if conditions:
            query = "SELECT * FROM credentials WHERE " + " AND ".join(conditions)
        else:
            query = "SELECT * FROM credentials"

        # limit=None / <=0 means "no limit" — omit the LIMIT clause entirely.
        if limit is not None and limit > 0:
            query += " LIMIT %(limit)s"

        # First get column names from table schema
        column_names = self.get_column_names()
        
        # Execute query
        rows = self._client.execute(query, params)
        
        # Convert to list of dictionaries
        credentials = []
        for row in rows:
            cred = dict(zip(column_names, row))
            credentials.append(cred)

        return credentials

    def get_column_names(self) -> List[str]:
        """Get the column names from the credentials table."""
        if not self._client:
            raise RuntimeError("Not connected to ClickHouse. Call connect() first.")
        
        result = self._client.execute("DESCRIBE TABLE credentials")
        return [row[0] for row in result]
