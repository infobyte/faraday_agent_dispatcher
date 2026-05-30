"""Faraday credentials integration via API.

This module handles:
1. Creating credentials via Faraday API
2. Linking credentials to vulnerabilities

Note: faraday-cli does NOT support credential import, so we use the API directly.

Faraday Credential Model:
- Credentials belong to a workspace
- Credentials have a many-to-many relationship with vulnerabilities
- Required fields: username, password, endpoint
- Optional: leak_date, owned, vulnerabilities (list of vuln IDs)
"""

import os
import json
import re
import sys
import time
import requests
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class FaradayConfig:
    """Faraday server configuration."""
    url: str
    username: str
    password: str
    workspace: str
    ssl_verify: bool = True
    
    @classmethod
    def from_env(cls) -> "FaradayConfig":
        """Load Faraday configuration from environment variables."""
        return cls(
            url=os.environ.get("FARADAY_URL", ""),
            username=os.environ.get("FARADAY_USER", ""),
            password=os.environ.get("FARADAY_PASSWORD", ""),
            workspace=os.environ.get("FARADAY_WORKSPACE", ""),
            ssl_verify=os.environ.get("FARADAY_SSL_VERIFY", "true").lower() in ("true", "1", "yes")
        )
    
    def is_configured(self) -> bool:
        """Check if all required Faraday settings are configured."""
        return all([self.url, self.username, self.password, self.workspace])


class FaradayAPIClient:
    """Client for Faraday REST API operations."""
    
    def __init__(self, config: FaradayConfig):
        self.config = config
        self.base_url = config.url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = config.ssl_verify
        self._token: Optional[str] = None
    
    def authenticate(self) -> bool:
        """Authenticate and get API token."""
        try:
            # Try session-based auth first
            response = self.session.post(
                f"{self.base_url}/_api/login",
                json={
                    "email": self.config.username,
                    "password": self.config.password
                }
            )
            if response.status_code == 200:
                return True
            
            # Try token-based auth
            response = self.session.post(
                f"{self.base_url}/_api/v3/token",
                auth=(self.config.username, self.config.password)
            )
            if response.status_code == 200:
                data = response.json()
                self._token = data.get("token")
                self.session.headers["Authorization"] = f"Token {self._token}"
                return True
            
            return False
        except Exception:
            return False
    
    def get_vulnerabilities_by_external_id(
        self,
        external_id_pattern: str
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities matching an external_id.
        
        If external_id_pattern contains a date (like "BAGRE-galicia-20251212"), 
        it does exact matching. Otherwise, it does pattern matching.
        
        Args:
            external_id_pattern: External ID to match (e.g., "BAGRE-galicia-20251212" or "BAGRE-").
            
        Returns:
            List of vulnerability objects.
        """
        try:
            # Check if it looks like a full external_id (contains date pattern YYYYMMDD)
            has_date = re.search(r'\d{8}', external_id_pattern) is not None
            
            if has_date:
                # Exact match for full external_id
                filter_op = "eq"
                filter_val = external_id_pattern
            else:
                # Pattern match for partial external_id
                filter_op = "ilike"
                filter_val = f"%{external_id_pattern}%"
            
            # Use filter endpoint with external_id search
            response = self.session.get(
                f"{self.base_url}/_api/v3/ws/{self.config.workspace}/vulns",
                params={"q": json.dumps({"filters": [{"name": "external_id", "op": filter_op, "val": filter_val}]})}
            )
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulnerabilities", data.get("data", []))
                # Handle API response format where vulnerability data is nested in 'value' field
                # Format: [{"id": ..., "key": ..., "value": {actual_vuln_data}}]
                processed_vulns = []
                for vuln in vulns:
                    if isinstance(vuln, dict) and "value" in vuln:
                        # Extract the actual vulnerability data from 'value' field
                        actual_vuln = vuln["value"]
                        # Preserve the top-level 'id' if it exists (might be the real ID)
                        if "id" in vuln and "id" not in actual_vuln:
                            actual_vuln["id"] = vuln["id"]
                        processed_vulns.append(actual_vuln)
                    else:
                        processed_vulns.append(vuln)
                return processed_vulns
            return []
        except Exception:
            return []
    
    def get_credentials(self) -> List[Dict[str, Any]]:
        """Get all credentials in the workspace.
        
        Returns:
            List of credential objects.
        """
        try:
            response = self.session.get(
                f"{self.base_url}/_api/v3/ws/{self.config.workspace}/credential"
            )
            if response.status_code == 200:
                data = response.json()
                # Handle both possible response formats
                if "rows" in data:
                    return [row.get("value", row) for row in data.get("rows", [])]
                return data.get("data", [])
            return []
        except Exception:
            return []
    
    def find_credential(
        self,
        username: str,
        password: str,
        endpoint: str
    ) -> Optional[Dict[str, Any]]:
        """Find an existing credential by username, password, and endpoint.
        
        Args:
            username: Credential username.
            password: Credential password.
            endpoint: Credential endpoint.
            
        Returns:
            Credential object if found, None otherwise.
        """
        try:
            # Get all credentials and filter
            credentials = self.get_credentials()
            for cred in credentials:
                if (cred.get("username", "").strip() == username.strip() and
                    cred.get("password", "").strip() == password.strip() and
                    cred.get("endpoint", "").strip() == endpoint.strip()):
                    return cred
            return None
        except Exception:
            return None
    
    def create_credential(
        self,
        username: str,
        password: str,
        endpoint: str,
        vulnerability_ids: Optional[List[int]] = None,
        leak_date: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Create a credential linked to vulnerabilities.
        
        Args:
            username: Credential username.
            password: Credential password.
            endpoint: The URL/endpoint for the credential.
            vulnerability_ids: List of vulnerability IDs to link to.
            leak_date: Optional leak date (ISO format).
            
        Returns:
            Created credential object or None.
        """
        try:
            payload = {
                "username": username,
                "password": password,
                "endpoint": endpoint,
            }
            
            # Add vulnerability IDs if provided
            if vulnerability_ids:
                payload["vulnerabilities"] = vulnerability_ids
            
            if leak_date:
                payload["leak_date"] = leak_date
            
            response = self.session.post(
                f"{self.base_url}/_api/v3/ws/{self.config.workspace}/credential",
                json=payload
            )
            if response.status_code in (200, 201):
                return response.json()
            # Return error details
            try:
                error_data = response.json()
                return {"error": True, "message": error_data.get("message", f"HTTP {response.status_code}"), "status_code": response.status_code}
            except:
                return {"error": True, "message": f"HTTP {response.status_code}", "status_code": response.status_code}
        except Exception as e:
            return {"error": True, "message": str(e), "status_code": None}
    
    def update_credential_vulnerabilities(
        self,
        credential_id: int,
        vulnerability_ids: List[int]
    ) -> bool:
        """Update a credential to link it to vulnerabilities.
        
        Args:
            credential_id: Credential ID.
            vulnerability_ids: List of vulnerability IDs to link.
            
        Returns:
            True if successful.
        """
        try:
            response = self.session.patch(
                f"{self.base_url}/_api/v3/ws/{self.config.workspace}/credential/{credential_id}",
                json={"vulnerabilities": vulnerability_ids}
            )
            return response.status_code == 200
        except Exception:
            return False
    
    def bulk_update_credentials(
        self,
        credential_ids: List[int],
        vulnerability_ids: List[int]
    ) -> bool:
        """Bulk update credentials to link them to vulnerabilities.
        
        Args:
            credential_ids: List of credential IDs to update.
            vulnerability_ids: List of vulnerability IDs to link.
            
        Returns:
            True if successful.
        """
        try:
            response = self.session.patch(
                f"{self.base_url}/_api/v3/ws/{self.config.workspace}/credential",
                json={
                    "ids": credential_ids,
                    "vulnerabilities": vulnerability_ids
                }
            )
            return response.status_code == 200
        except Exception:
            return False


def import_credentials_and_link_to_vulns(
    credentials: List[Dict[str, Any]],
    faraday_config: FaradayConfig,
    vulnerability_ids: Optional[List[int]] = None,
    external_id_pattern: Optional[str] = None
) -> Tuple[bool, str, List[int]]:
    # Debug: log the external_id_pattern we received
    print(f"[BAGRE DEBUG] import_credentials_and_link_to_vulns called with external_id_pattern='{external_id_pattern}' (type: {type(external_id_pattern)}, length: {len(external_id_pattern) if external_id_pattern else 0})", file=sys.stderr, flush=True)
    """Import credentials to Faraday and link them to vulnerabilities.
    
    This function uses the Faraday API directly (faraday-cli doesn't support
    credential import_csv).
    
    Steps:
    1. Authenticates with Faraday API
    2. If vulnerability_ids not provided, finds vulns by external_id pattern
    3. Creates credentials linked to the vulnerabilities
    
    Args:
        credentials: List of credential dictionaries from ClickHouse.
        faraday_config: Faraday configuration.
        vulnerability_ids: Optional list of vuln IDs to link to.
        external_id_pattern: Pattern to find vulns by external_id (e.g., "BAGRE-").
        
    Returns:
        Tuple of (success, message, list of credential IDs).
    """
    if not faraday_config.is_configured():
        return False, "Faraday configuration incomplete", []
    
    if not credentials:
        return True, "No credentials to import", []
    
    created_credential_ids = []
    updated_credential_ids = []
    processed_cred_ids = set()  # Track which credential IDs we've already processed
    
    # Use API directly (faraday-cli doesn't have credential import)
    api = FaradayAPIClient(faraday_config)
    
    if not api.authenticate():
        return False, "API authentication failed", []
    
    # Find vulnerability IDs if not provided
    vuln_ids = vulnerability_ids or []
    
    if not vuln_ids and external_id_pattern:
        # Debug: show what pattern we're searching for
        print(f"[BAGRE DEBUG] Searching for vulnerabilities with external_id_pattern: '{external_id_pattern}' (length: {len(external_id_pattern)})", file=sys.stderr, flush=True)
        
        # Wait a bit for bulk_create to finish creating vulnerabilities
        # bulk_create is asynchronous, so we need to wait longer
        time.sleep(5)  # Wait 5 seconds for bulk_create to process
        
        # Try to find vulnerabilities, with retries
        for attempt in range(3):
            print(f"[BAGRE DEBUG] Attempt {attempt+1}: Searching with pattern '{external_id_pattern}'", file=sys.stderr, flush=True)
            vulns = api.get_vulnerabilities_by_external_id(external_id_pattern)
            # Debug: show what external_ids we got and what fields are available
            if vulns:
                ext_ids_found = []
                for v in vulns:
                    # Try different possible field names
                    ext_id = v.get("external_id") or v.get("externalId") or v.get("externalID") or v.get("_external_id")
                    ext_ids_found.append(str(ext_id) if ext_id else "NO_EXTERNAL_ID")
                    # On first attempt, show full structure of first vuln for debugging
                    if attempt == 0 and v == vulns[0]:
                        print(f"[BAGRE DEBUG] Sample vulnerability fields: {list(v.keys())[:10]}...", file=sys.stderr, flush=True)
                        print(f"[BAGRE DEBUG] Sample vulnerability external_id values: external_id={v.get('external_id')}, externalId={v.get('externalId')}, _external_id={v.get('_external_id')}", file=sys.stderr, flush=True)
                print(f"[BAGRE DEBUG] Attempt {attempt+1}: Found {len(vulns)} vulnerabilities. External IDs: {ext_ids_found}", file=sys.stderr, flush=True)
            
            # Filter to only exact matches (try different field names)
            exact_matches = []
            for v in vulns:
                ext_id = v.get("external_id") or v.get("externalId") or v.get("externalID") or v.get("_external_id")
                ext_id_str = str(ext_id).strip() if ext_id else ""
                pattern_str = str(external_id_pattern).strip()
                # Debug: show comparison
                if attempt == 0 and len(exact_matches) == 0:
                    print(f"[BAGRE DEBUG] Comparing: '{ext_id_str}' == '{pattern_str}'? {ext_id_str == pattern_str}", file=sys.stderr, flush=True)
                if ext_id_str == pattern_str:
                    exact_matches.append(v)
            if exact_matches:
                vuln_ids = [v.get("id") or v.get("_id") for v in exact_matches if v.get("id") or v.get("_id")]
                print(f"[BAGRE DEBUG] Found {len(exact_matches)} exact matching vulnerabilities (out of {len(vulns)} total) for external_id: {external_id_pattern}", file=sys.stderr, flush=True)
                break
            else:
                # Don't use fallback - wait and retry if no exact match
                if attempt < 2:  # Don't sleep on last attempt
                    print(f"[BAGRE DEBUG] No exact match found on attempt {attempt+1}, waiting and retrying...", file=sys.stderr, flush=True)
                    time.sleep(3)  # Wait longer for bulk_create to finish
                else:
                    # Last attempt failed - try fallback: find by name pattern
                    print(f"[BAGRE DEBUG] No exact match found after {attempt+1} attempts. Trying fallback: find by name...", file=sys.stderr, flush=True)
                    # Try to find by name "Bagre - Compromised Credentials Found" created today
                    try:
                        from datetime import datetime
                        today = datetime.now().strftime("%Y-%m-%d")
                        # Query by name and creation date
                        response = api.session.get(
                            f"{api.base_url}/_api/v3/ws/{api.config.workspace}/vulns",
                            params={"q": json.dumps({
                                "filters": [
                                    {"name": "name", "op": "ilike", "val": "%Compromised Credentials Found%"},
                                    {"name": "create_date", "op": "ge", "val": today}
                                ]
                            })}
                        )
                        if response.status_code == 200:
                            data = response.json()
                            fallback_vulns_raw = data.get("vulnerabilities", data.get("data", []))
                            # Handle nested structure (value field)
                            fallback_vulns = []
                            for vuln in fallback_vulns_raw:
                                if isinstance(vuln, dict) and "value" in vuln:
                                    actual_vuln = vuln["value"]
                                    if "id" in vuln and "id" not in actual_vuln:
                                        actual_vuln["id"] = vuln["id"]
                                    fallback_vulns.append(actual_vuln)
                                else:
                                    fallback_vulns.append(vuln)
                            
                            if fallback_vulns:
                                # Get the most recent one (should be the one we just created)
                                fallback_vulns.sort(key=lambda x: x.get("create_date", ""), reverse=True)
                                fallback_vuln = fallback_vulns[0]
                                fallback_id = fallback_vuln.get("id") or fallback_vuln.get("_id")
                                if fallback_id:
                                    vuln_ids = [fallback_id]
                                    print(f"[BAGRE DEBUG] Found vulnerability by name fallback: ID={fallback_id}, external_id={fallback_vuln.get('external_id', 'N/A')}", file=sys.stderr, flush=True)
                                    break
                    except Exception as e:
                        print(f"[BAGRE DEBUG] Fallback query failed: {e}", file=sys.stderr, flush=True)
                    
                    if not vuln_ids:
                        print(f"[BAGRE WARNING] No exact match found after {attempt+1} attempts. Will create credentials without vulnerability linking.", file=sys.stderr, flush=True)
                        vuln_ids = []
    
    # If no vulnerabilities found, we'll still create credentials but without linking
    # This is better than failing completely
    
    # Deduplicate credentials by (username, password, endpoint) before processing
    # This avoids trying to create the same credential multiple times
    seen_cred_keys = set()
    unique_credentials = []
    for cred in credentials:
        # Build username
        username = cred.get("user", "")
        if not username:
            mail_user = cred.get("mail_username", "")
            mail_domain = cred.get("mail_domain", "")
            mail_tld = cred.get("mail_tld", "")
            if mail_user and mail_domain:
                username = f"{mail_user}@{mail_domain}.{mail_tld}"
        
        password = cred.get("password", "")
        
        # Skip if no username or password
        if not username or not password:
            continue
        
        # Build endpoint (URL)
        subdomain = cred.get("uri_subdomain", "")
        domain = cred.get("uri_domain", "")
        tld = cred.get("uri_tld", "")
        if subdomain:
            hostname = f"{subdomain}.{domain}.{tld}"
        else:
            hostname = f"{domain}.{tld}"
        
        protocol = cred.get("uri_protocol", "https") or "https"
        port = cred.get("uri_port", 0)
        path = cred.get("uri_path", "")
        
        endpoint = f"{protocol}://{hostname}"
        if port and port not in (0, 80, 443):
            endpoint += f":{port}"
        if path:
            endpoint += path
        
        # Create unique key for this credential
        cred_key = (username.strip().lower(), password, endpoint.strip())
        if cred_key not in seen_cred_keys:
            seen_cred_keys.add(cred_key)
            unique_credentials.append(cred)
    
    print(f"[BAGRE DEBUG] Deduplicated {len(credentials)} credentials to {len(unique_credentials)} unique credentials", file=sys.stderr, flush=True)
    
    # Create credentials (with or without vulnerability linking)
    errors = []
    for cred in unique_credentials:
        # Build username
        username = cred.get("user", "")
        if not username:
            mail_user = cred.get("mail_username", "")
            mail_domain = cred.get("mail_domain", "")
            mail_tld = cred.get("mail_tld", "")
            if mail_user and mail_domain:
                username = f"{mail_user}@{mail_domain}.{mail_tld}"
        
        password = cred.get("password", "")
        
        # Skip if no username or password
        if not username or not password:
            errors.append(f"Skipped credential: missing username or password")
            continue
        
        # Build endpoint (URL)
        subdomain = cred.get("uri_subdomain", "")
        domain = cred.get("uri_domain", "")
        tld = cred.get("uri_tld", "")
        if subdomain:
            hostname = f"{subdomain}.{domain}.{tld}"
        else:
            hostname = f"{domain}.{tld}"
        
        protocol = cred.get("uri_protocol", "https") or "https"
        port = cred.get("uri_port", 0)
        path = cred.get("uri_path", "")
        
        endpoint = f"{protocol}://{hostname}"
        if port and port not in (0, 80, 443):
            endpoint += f":{port}"
        if path:
            endpoint += path
        
        # Try to create credential linked to vulnerabilities (if any found)
        result = api.create_credential(
            username=username,
            password=password,
            endpoint=endpoint,
            vulnerability_ids=vuln_ids if vuln_ids else None
        )
        
        if result and not result.get("error") and "id" in result:
            # Successfully created
            cred_id = result["id"]
            if cred_id not in processed_cred_ids:
                created_credential_ids.append(cred_id)
                processed_cred_ids.add(cred_id)
                print(f"[BAGRE] Created new credential {cred_id} for {username}@{endpoint}", file=sys.stderr, flush=True)
        elif result and result.get("error") and "Existing value" in str(result.get("message", "")):
            # Credential already exists - find it and update it
            existing_cred = api.find_credential(username, password, endpoint)
            if existing_cred:
                cred_id = existing_cred.get("id") or existing_cred.get("_id")
                if cred_id:
                    # Skip if we've already processed this credential in this run
                    if cred_id in processed_cred_ids:
                        print(f"[BAGRE DEBUG] Skipping duplicate credential {cred_id} for {username}@{endpoint} (already processed)", file=sys.stderr, flush=True)
                        continue
                    
                    # Get existing vulnerability IDs and merge with new ones
                    existing_vuln_ids = existing_cred.get("vulnerabilities", [])
                    if isinstance(existing_vuln_ids, list):
                        existing_vuln_ids = [v.get("id") if isinstance(v, dict) else v for v in existing_vuln_ids]
                    else:
                        existing_vuln_ids = []
                    
                    # Merge vulnerability IDs (avoid duplicates)
                    all_vuln_ids = list(set(existing_vuln_ids + (vuln_ids or [])))
                    
                    # Update the credential to link to all vulnerabilities
                    if api.update_credential_vulnerabilities(cred_id, all_vuln_ids):
                        updated_credential_ids.append(cred_id)
                        processed_cred_ids.add(cred_id)
                        print(f"[BAGRE] Updated existing credential {cred_id} to link to {len(all_vuln_ids)} vulnerabilities", file=sys.stderr, flush=True)
                    else:
                        errors.append(f"Failed to update existing credential {cred_id} for {username}@{endpoint}")
                else:
                    errors.append(f"Found existing credential but no ID for {username}@{endpoint}")
            else:
                errors.append(f"Credential exists but could not find it for {username}@{endpoint}")
        else:
            # Get more details about the failure
            error_detail = "Unknown error"
            if result and result.get("error"):
                error_detail = result.get("message", "Unknown API error")
            elif result:
                error_detail = f"Unexpected response: {result}"
            errors.append(f"Failed to create credential for {username}@{endpoint}: {error_detail}")
            print(f"[BAGRE ERROR] Failed to create credential for {username}@{endpoint}: {error_detail}", file=sys.stderr, flush=True)
    
    # Build final message
    msg_parts = []
    if created_credential_ids:
        msg_parts.append(f"Created {len(created_credential_ids)} new credentials")
    if updated_credential_ids:
        msg_parts.append(f"Updated {len(updated_credential_ids)} existing credentials")
    
    if vuln_ids:
        msg_parts.append(f"linked to {len(vuln_ids)} vulnerabilities")
    elif not created_credential_ids and not updated_credential_ids:
        msg_parts.append("(no vulnerabilities found to link)")
    
    if errors:
        msg_parts.append(f"({len(errors)} errors: {'; '.join(errors[:3])}{'...' if len(errors) > 3 else ''})")
        # Print first few errors for debugging
        for error in errors[:3]:
            print(f"[BAGRE ERROR] {error}", file=sys.stderr, flush=True)
    
    final_message = ", ".join(msg_parts) if msg_parts else "No credentials processed"
    all_cred_ids = created_credential_ids + updated_credential_ids
    
    if created_credential_ids or updated_credential_ids:
        return True, final_message, all_cred_ids
    else:
        if errors:
            error_msg = f"Failed to process credentials: {'; '.join(errors[:3])}"
            return False, error_msg, []
        else:
            return True, "No credentials to process", []


# Keep old function name for backwards compatibility
def import_credentials_and_link(
    credentials: List[Dict[str, Any]],
    faraday_config: FaradayConfig,
    external_id_pattern: Optional[str] = None,
    use_cli: bool = True  # Ignored - always uses API now
) -> Tuple[bool, str, List[int]]:
    """Import credentials to Faraday (backwards compatible wrapper).
    
    Note: use_cli parameter is ignored - faraday-cli doesn't support
    credential import, so we always use the API directly.
    
    This function tries to find Bagre vulnerabilities by external_id pattern
    and links the credentials to them.
    """
    return import_credentials_and_link_to_vulns(
        credentials=credentials,
        faraday_config=faraday_config,
        external_id_pattern=external_id_pattern or "BAGRE-"  # Use provided pattern or default to "BAGRE-"
    )
