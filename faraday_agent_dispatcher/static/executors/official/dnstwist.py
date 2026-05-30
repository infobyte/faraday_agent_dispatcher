#!/usr/bin/env python3
"""dnstwist typo-squat / lookalike-domain detection executor.

Generates permutations of the target domain (homoglyphs, bitsquatting,
character transpositions, etc.) and resolves them. Each resolved
permutation becomes a Faraday host with a 'Lookalike domain detected'
vulnerability so brand-protection workflows can act on it.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def main():
    domain = os.environ.get("EXECUTOR_CONFIG_DNSTWIST_DOMAIN")
    if not domain:
        print("DNSTWIST_DOMAIN is required", file=sys.stderr)
        sys.exit(1)
    cmd = ["dnstwist", "--format", "json"]
    if os.environ.get("EXECUTOR_CONFIG_DNSTWIST_REGISTERED_ONLY", "true").lower() == "true":
        cmd.append("--registered")
    if os.environ.get("EXECUTOR_CONFIG_DNSTWIST_MX_CHECK", "").lower() == "true":
        cmd.append("--mxcheck")
    cmd.append(domain)
    start = datetime.now(timezone.utc)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)
    try:
        items = json.loads(proc.stdout) if proc.stdout.strip() else []
    except json.JSONDecodeError as e:
        print(f"dnstwist output not JSON: {e}", file=sys.stderr)
        sys.exit(1)
    hosts = []
    for it in items:
        d = it.get("domain", "")
        fuzzer = it.get("fuzzer", "unknown")
        ips = it.get("dns_a", []) or []
        ip = ips[0] if ips else "0.0.0.0"
        mx = it.get("dns_mx", []) or []
        whois = it.get("whois_registrar", "") or ""
        sev = "high" if mx else "med"
        hosts.append(
            {
                "ip": ip,
                "os": "unknown",
                "hostnames": [d] if d else [],
                "description": f"Lookalike domain detected by dnstwist (fuzzer={fuzzer})",
                "mac": None,
                "credentials": [],
                "services": [],
                "vulnerabilities": [
                    {
                        "name": f"Lookalike / typo-squat domain: {d}",
                        "desc": (
                            f"dnstwist detected the permutation '{d}' of '{domain}' "
                            f"via the '{fuzzer}' fuzzer. "
                            f"dns_a={ips} dns_mx={mx} whois_registrar={whois!r}"
                        ),
                        "severity": sev,
                        "refs": [],
                        "external_id": fuzzer,
                        "type": "Vulnerability",
                        "resolution": "Investigate ownership; consider defensive registration or takedown.",
                        "data": "",
                        "custom_fields": {},
                        "status": "open",
                        "impact": {},
                        "policyviolations": [],
                        "cve": [],
                        "cvss3": {},
                        "cvss2": {},
                        "easeofresolution": None,
                        "confirmed": False,
                        "tags": ["typo-squat", fuzzer],
                        "cwe": [],
                    }
                ],
                "tags": [],
            }
        )
    duration_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    print(
        json.dumps(
            {
                "hosts": hosts,
                "command": {
                    "tool": "dnstwist",
                    "command": "dnstwist",
                    "params": "",
                    "user": "",
                    "hostname": "",
                    "start_date": start.isoformat(),
                    "duration": duration_ms,
                    "import_source": "report",
                },
            }
        )
    )


if __name__ == "__main__":
    main()
