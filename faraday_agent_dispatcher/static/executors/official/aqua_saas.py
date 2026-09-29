#!/usr/bin/env python
"""Aqua SaaS (CNAPP / CSPM) REST importer.

Thin wrapper around :mod:`aqua_enterprise` that hardcodes the tenant
URL to Aqua's hosted Cloud-Native Application Protection Platform
(CNAPP / CSPM) SaaS edition (`cloudsploit.com` family). Every helper
function — auth flow, pagination, severity / status normalisation,
CVE / CWE harvesting, host bucketing, Faraday vulnerability shape —
is reused verbatim from :mod:`aqua_enterprise`, guaranteeing the two
executors stay in lockstep.

Differences vs. ``aqua_enterprise``:

* ``AQUA_HOST`` is **not** an environment variable. The host is
  hardcoded to ``https://cloudsploit.com`` (the canonical SaaS URL)
  with an optional ``AQUA_REGION`` arg that selects a per-region
  endpoint:

      us / default / empty -> https://cloudsploit.com
      eu                   -> https://eu.cloudsploit.com
      apac / ap            -> https://apac.cloudsploit.com
      singapore / sg       -> https://singapore.cloudsploit.com

  Unrecognised tokens log a warning and fall back to ``us``.

* ``tool`` / ``command`` / tag namespace = ``aqua_saas`` (so Faraday
  workspaces can distinguish ingest provenance from the on-prem
  ``aqua_enterprise`` executor).

* Required env vars: ``AQUA_USER``, ``AQUA_PASSWORD``.
"""

import importlib.util
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Load the sibling aqua_enterprise module so every helper stays
# single-sourced. Executors are invoked as standalone scripts (no
# package init), so importlib + spec_from_file_location is the
# canonical way to pull a sibling in.
_HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("aqua_enterprise_base", _HERE / "aqua_enterprise.py")
_base = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_base)

# Re-export commonly tested helpers so test suites + downstream
# callers don't need to know about the shim.
log = _base.log
env = _base.env
normalize_base_url = _base.normalize_base_url
validate_min_severity = _base.validate_min_severity
severities_at_or_above = _base.severities_at_or_above
severity_from_aqua = _base.severity_from_aqua
status_from_aqua = _base.status_from_aqua
extract_token = _base.extract_token
extract_items = _base.extract_items
fetch_access_token = _base.fetch_access_token
fetch_findings = _base.fetch_findings
fetch_image = _base.fetch_image
cvss_score = _base.cvss_score
cvss_vector = _base.cvss_vector
collect_cves = _base.collect_cves
collect_refs = _base.collect_refs
image_label = _base.image_label
package_label = _base.package_label
vuln_label = _base.vuln_label
build_vulnerability = _base.build_vulnerability
host_bucket_key = _base.host_bucket_key
build_host = _base.build_host
SEVERITY_ORDER = _base.SEVERITY_ORDER
AQUA_API_SEVERITY = _base.AQUA_API_SEVERITY

DEFAULT_AQUA_SAAS_HOST = "https://cloudsploit.com"

# Per-region SaaS endpoints. ``default`` and an empty token both map
# to the canonical US tenant URL.
AQUA_SAAS_REGIONS = {
    "": "https://cloudsploit.com",
    "default": "https://cloudsploit.com",
    "us": "https://cloudsploit.com",
    "eu": "https://eu.cloudsploit.com",
    "apac": "https://apac.cloudsploit.com",
    "ap": "https://apac.cloudsploit.com",
    "singapore": "https://singapore.cloudsploit.com",
    "sg": "https://singapore.cloudsploit.com",
}


def resolve_region(value):
    """Resolve a region token to a canonical SaaS endpoint URL.

    Unrecognised tokens log a warning and fall back to the US default
    so a typo doesn't surface as an opaque 404. None / empty defaults
    silently to ``cloudsploit.com``.
    """
    if value is None:
        return DEFAULT_AQUA_SAAS_HOST
    text = str(value).strip().lower()
    if not text:
        return DEFAULT_AQUA_SAAS_HOST
    if text in AQUA_SAAS_REGIONS:
        return AQUA_SAAS_REGIONS[text]
    log(f"AQUA_REGION '{value}' not recognised; defaulting to US ({DEFAULT_AQUA_SAAS_HOST})")
    return DEFAULT_AQUA_SAAS_HOST


def main():
    started = time.time()
    username = env("AQUA_USER", required=True)
    password = env("AQUA_PASSWORD", required=True)
    region_raw = env("EXECUTOR_CONFIG_AQUA_REGION")
    registry = env("EXECUTOR_CONFIG_AQUA_REGISTRY")
    repo = env("EXECUTOR_CONFIG_AQUA_REPO")
    min_severity = validate_min_severity(env("EXECUTOR_CONFIG_AQUA_MIN_SEVERITY"))
    floor = SEVERITY_ORDER[min_severity]
    severities = severities_at_or_above(min_severity)
    if severities and len(severities) == len(AQUA_API_SEVERITY):
        severities = None

    base_url = normalize_base_url(resolve_region(region_raw))
    if not base_url:
        log("Failed to resolve Aqua SaaS base URL; aborting.")
        sys.exit(1)

    token = fetch_access_token(base_url, username, password)
    if not token:
        log("Failed to obtain Aqua SaaS access token; aborting.")
        sys.exit(1)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    findings = fetch_findings(base_url, headers, registry, repo, severities)
    log(
        f"Processing {len(findings)} Aqua SaaS findings "
        f"(host={base_url}, registry={registry or 'ALL'}, repo={repo or 'ALL'}, "
        f"min_severity={min_severity})"
    )

    buckets = {}
    for finding in findings:
        key = host_bucket_key(finding)
        buckets.setdefault(key, []).append(finding)

    image_meta = {}
    for key in list(buckets.keys()):
        if key == "__unknown__":
            continue
        first = buckets[key][0] if buckets[key] else {}
        f_registry = first.get("registry") or first.get("registry_name") or registry or ""
        f_repo = first.get("repository") or first.get("image_name") or first.get("image_repository_name") or repo or ""
        f_image_id = first.get("image_id") or first.get("imageId") or first.get("digest") or ""
        image = fetch_image(base_url, headers, f_registry, f_repo, f_image_id)
        if image:
            image_meta[key] = image

    hosts = []
    for key, bucket in buckets.items():
        image = image_meta.get(key)
        vulns = []
        for finding in bucket:
            built = build_vulnerability(finding, image)
            if built is None:
                continue
            if SEVERITY_ORDER[built["severity"]] < floor:
                continue
            built["tags"] = ["aqua_saas", "cnapp", "cloud-security"]
            vulns.append(built)
        if not vulns:
            continue
        bucket_id = "" if key == "__unknown__" else key
        hosts.append(build_host(bucket_id, image, bucket, vulns))

    params = f"min_severity={min_severity}"
    if region_raw:
        params = f"{params},region={region_raw}"
    if registry:
        params = f"{params},registry={registry}"
    if repo:
        params = f"{params},repo={repo}"

    output = {
        "hosts": hosts,
        "command": {
            "tool": "aqua_saas",
            "command": "aqua_saas",
            "params": params,
            "user": os.environ.get("USER", ""),
            "hostname": socket.gethostname(),
            "start_date": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
            "duration": int((time.time() - started) * 1000),
            "import_source": "report",
        },
    }
    print(json.dumps(output))


if __name__ == "__main__":
    main()
