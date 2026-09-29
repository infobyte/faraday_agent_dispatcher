"""Format ClickHouse results into Faraday Bulk Create JSON format."""

from typing import List, Dict, Any, Optional
from datetime import datetime
import socket
import hashlib
import sys


def reconstruct_url(credential: Dict[str, Any]) -> str:
    """Reconstruct the full URL from credential components.
    
    Args:
        credential: Credential dictionary from ClickHouse.
        
    Returns:
        Reconstructed URL string.
    """
    protocol = credential.get("uri_protocol", "https") or "https"
    subdomain = credential.get("uri_subdomain", "")
    domain = credential.get("uri_domain", "")
    tld = credential.get("uri_tld", "")
    port = credential.get("uri_port", 0)
    path = credential.get("uri_path", "")
    query = credential.get("uri_query", "")

    # Build hostname
    if subdomain:
        hostname = f"{subdomain}.{domain}.{tld}"
    else:
        hostname = f"{domain}.{tld}"

    # Build URL
    url = f"{protocol}://{hostname}"
    
    if port and port not in (0, 80, 443):
        url += f":{port}"
    
    if path:
        url += path
    
    if query:
        url += f"?{query}"

    return url


def reconstruct_email(credential: Dict[str, Any]) -> Optional[str]:
    """Reconstruct email address from credential components.
    
    Args:
        credential: Credential dictionary from ClickHouse.
        
    Returns:
        Email string or None if not available.
    """
    username = credential.get("mail_username", "")
    domain = credential.get("mail_domain", "")
    tld = credential.get("mail_tld", "")

    if not username or not domain:
        return None

    if credential.get("mail_subdomain"):
        return f"{username}@{credential['mail_subdomain']}.{domain}.{tld}"
    
    return f"{username}@{domain}.{tld}"


def format_credential_entry(credential: Dict[str, Any], index: int) -> str:
    """Format a single credential entry for the vulnerability data field.
    
    Args:
        credential: Credential dictionary from ClickHouse.
        index: The credential number (1-based).
        
    Returns:
        Formatted credential string.
    """
    lines = [f"=== Credential #{index} ==="]
    
    # URL
    url = reconstruct_url(credential)
    lines.append(f"URL: {url}")
    
    # Subdomain (if present)
    if credential.get("uri_subdomain"):
        lines.append(f"Subdomain: {credential['uri_subdomain']}")
    
    # Path (if present)
    if credential.get("uri_path"):
        lines.append(f"Path: {credential['uri_path']}")
    
    # Username
    if credential.get("user"):
        lines.append(f"Username: {credential['user']}")
    
    # Password
    if credential.get("password"):
        lines.append(f"Password: {credential['password']}")
    
    # Email (if present)
    email = reconstruct_email(credential)
    if email:
        lines.append(f"Email: {email}")
    
    # Phone (if present)
    if credential.get("phone"):
        lines.append(f"Phone: {credential['phone']}")
    
    # Hash
    if credential.get("hash"):
        lines.append(f"Hash: {credential['hash']}")
    
    lines.append("")  # Empty line separator
    
    return "\n".join(lines)


def get_unique_urls(credentials: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Extract unique URLs from credentials for references.
    
    Args:
        credentials: List of credential dictionaries.
        
    Returns:
        List of reference objects with 'name' field (Faraday format).
    """
    urls = set()
    for cred in credentials:
        url = reconstruct_url(cred)
        if url:
            urls.add(url)
    # Faraday expects refs as list of objects with 'name' field
    return [{"name": url} for url in sorted(urls)]


def resolve_hostname_to_ip(hostname: str) -> str:
    """Try to resolve hostname to IP address.
    
    Args:
        hostname: The hostname to resolve.
        
    Returns:
        IP address string, or the hostname itself if resolution fails.
    """
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except (socket.gaierror, socket.herror):
        # If resolution fails, return the hostname as-is
        # Faraday can accept hostnames in the ip field
        return hostname


def build_full_hostname(credential: Dict[str, Any]) -> str:
    """Build the full hostname from credential components.
    
    Args:
        credential: Credential dictionary from ClickHouse.
        
    Returns:
        Full hostname string.
    """
    subdomain = credential.get("uri_subdomain", "")
    domain = credential.get("uri_domain", "")
    tld = credential.get("uri_tld", "")
    
    if subdomain:
        return f"{subdomain}.{domain}.{tld}"
    return f"{domain}.{tld}"


def create_faraday_credential(credential: Dict[str, Any]) -> Dict[str, Any]:
    """Create a Faraday credential object from a ClickHouse credential.
    
    Format matches Faraday's BulkCredentialSchema:
    - username (required)
    - password (required)  
    - endpoint (URL, required for bulk_create)
    - leak_date (optional)
    - owned (optional, default False)
    
    Args:
        credential: Credential dictionary from ClickHouse.
        
    Returns:
        Faraday credential format dictionary for bulk_create.
    """
    url = reconstruct_url(credential)
    email = reconstruct_email(credential)
    
    # Build username - prefer user field, fall back to email
    username = credential.get("user", "") or email or ""
    
    # Get password
    password = credential.get("password", "") or ""
    
    # Create credential object matching BulkCredentialSchema
    # Required fields: username, password, endpoint
    faraday_cred = {
        "username": username,
        "password": password,
        "endpoint": url or "",  # endpoint is required by bulk_create
    }
    
    return faraday_cred


def format_faraday_output(
    credentials: List[Dict[str, Any]],
    target_domain: Optional[str],
    target_subdomain: Optional[str],
    mail_domain: Optional[str],
    uri_path: Optional[str],
    command: str,
    duration: float,
    include_credentials: bool = False
) -> Dict[str, Any]:
    """Format credentials into Faraday Bulk Create JSON format.
    
    Creates hosts with vulnerabilities and optionally credentials at the top level.
    Faraday's bulk_create API supports credentials at the top level of the JSON.
    
    Args:
        credentials: List of credential dictionaries from ClickHouse.
        target_domain: The domain that was searched (if any).
        target_subdomain: The subdomain pattern that was searched (if any).
        mail_domain: The mail domain that was searched (if any).
        uri_path: The URI path pattern that was searched (if any).
        command: The command that was executed.
        duration: Execution duration in seconds.
        include_credentials: If True, include credentials in bulk_create output (for BAGRE_IMPORT_CREDS=true).
        
    Returns:
        Faraday Bulk Create format dictionary.
    """
    if not credentials:
        # No credentials found, returning empty result
        return {
            "hosts": [],
            "credentials": [],
            "command": {
                "tool": "bagre",
                "command": command,
                "duration": duration
            }
        }

    # Group credentials by hostname for host/vuln creation
    hosts_by_hostname: Dict[str, Dict[str, Any]] = {}
    
    for i, cred in enumerate(credentials, 1):
        # Build hostname for this credential
        hostname = build_full_hostname(cred)
        
        if hostname not in hosts_by_hostname:
            # Try to resolve hostname to IP, or use hostname as IP
            ip_or_hostname = resolve_hostname_to_ip(hostname)
            
            hosts_by_hostname[hostname] = {
                "ip": ip_or_hostname,
                "description": f"Host with compromised credentials found by Bagre",
                "hostnames": [hostname],
                "vulnerabilities": [],
                "credential_entries": []  # Temporary storage for credential data
            }
        
        # Store credential entry for later formatting
        hosts_by_hostname[hostname]["credential_entries"].append(cred)

    # Calculate total credentials for description
    total_credentials = len(credentials)
    
    # Now create one vulnerability with all credentials data
    # Group all credentials into a single vulnerability per search
    all_cred_entries = []
    for hostname, host_data in hosts_by_hostname.items():
        all_cred_entries.extend(host_data["credential_entries"])
    
    # Format all credentials into the data field
    credential_texts = []
    for i, cred in enumerate(all_cred_entries, 1):
        entry = format_credential_entry(cred, i)
        credential_texts.append(entry)
    data_content = "\n".join(credential_texts)
    
    # Build description for vulnerability
    desc_parts = [
        "Infostealer credentials detected by Bagre threat intelligence.",
        "",
    ]
    if target_domain:
        desc_parts.append(f"**Target Domain:** {target_domain}")
    if target_subdomain:
        desc_parts.append(f"**Subdomain Filter:** {target_subdomain}")
    if mail_domain:
        desc_parts.append(f"**Mail Domain:** {mail_domain}")
    if uri_path:
        desc_parts.append(f"**URI Path Filter:** {uri_path}")
    desc_parts.append(f"**Total Credentials Found:** {total_credentials}")
    description = "\n".join(desc_parts)
    
    # Get unique URLs for references from all credentials
    refs = get_unique_urls(all_cred_entries)
    
    # Build external ID
    date_str = datetime.now().strftime("%Y%m%d")
    search_id = target_domain or mail_domain or "search"
    external_id = f"BAGRE-{search_id}-{date_str}"
    
    # Create a single vulnerability with all credential data
    # Include search term in vulnerability name
    vuln_name = f"Compromised Credentials Found - {search_id}"
    vulnerability = {
        "name": vuln_name,
        "desc": description,
        "severity": "critical",
        "type": "Vulnerability",
        "data": data_content,
        "refs": refs,
        "external_id": external_id
    }
    
    # Create hosts - first host gets the vulnerability
    hosts_list = []
    first_host = True
    for hostname, host_data in hosts_by_hostname.items():
        # Remove temporary credential_entries
        host_data.pop("credential_entries", None)
        
        # Only the first host gets the vulnerability (to avoid duplicates)
        if first_host:
            host_data["vulnerabilities"] = [vulnerability]
            first_host = False
        else:
            host_data["vulnerabilities"] = []
        
        hosts_list.append(host_data)
    
    # Create Faraday credentials for bulk_create if requested
    all_faraday_credentials = []
    if include_credentials:
        print(f"[BAGRE DEBUG] Processing {len(credentials)} credentials for bulk_create", file=sys.stderr, flush=True)
        for cred in credentials:
            faraday_cred = create_faraday_credential(cred)
            # Only include credentials with valid username (matching BulkCredentialSchema validation)
            # Password is required by schema, so use placeholder if missing
            username = faraday_cred.get("username", "").strip()
            password = faraday_cred.get("password", "").strip()
            
            if not username:
                print(f"[BAGRE DEBUG] Skipped credential: no username", file=sys.stderr, flush=True)
                continue
            
            # If password is empty, use placeholder (BulkCredentialSchema requires non-empty password)
            if not password:
                password = "(no password)"
                faraday_cred["password"] = password
                print(f"[BAGRE DEBUG] Using placeholder password for credential: {username}", file=sys.stderr, flush=True)
            
            all_faraday_credentials.append(faraday_cred)
        print(f"[BAGRE DEBUG] Created {len(all_faraday_credentials)} valid credentials for bulk_create", file=sys.stderr, flush=True)
    
    output = {
        "hosts": hosts_list,
        "credentials": all_faraday_credentials if include_credentials else [],
        "command": {
            "tool": "bagre",
            "command": command,
            "duration": duration
        },
        # Store external_id for credential linking (not part of bulk_create schema, but useful for post-processing)
        "_external_id": external_id
    }

    return output



