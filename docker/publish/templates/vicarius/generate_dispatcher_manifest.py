#!/usr/bin/env python3
"""Generate a Kubernetes manifest for a dispatcher with all official executors.

The generated Secret contains the dispatcher token, so do not commit generated
output with a real --agent-token value.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml
from faraday_agent_dispatcher import __version__
from faraday_agent_dispatcher.utils.metadata_utils import all_manifests

DEFAULT_EXECUTOR_ENVS = {
    "arachni": {"ARACHNI_PATH": "/usr/local/src/arachni/bin"},
    "nuclei": {"NUCLEI_TEMPLATES": "/root/nuclei-templates"},
    "report_processor": {"REPORTS_PATH": "/root/reports"},
}


# Offensive Checks capability groups. Each becomes its own agent/Deployment
# when --group is passed. Names not listed here are part of the default
# "all official tools" agent only.
AGENT_GROUPS = {
    "code-sast": {
        "agent_name": "code-sast-agent",
        "executors": [
            "bandit", "semgrep", "shellcheck", "snyk",
            "codeql", "dependabot", "github_secrets", "sonarqube", "appscan",
        ],
        "description": (
            "Static Application Security Testing (SAST) and supply-chain signal import for "
            "source code. Runs bandit (Python), semgrep (multi-language with community rule "
            "packs), shellcheck (shell scripts), snyk (SCA + SAST + IaC), sonarqube "
            "(commercial SAST import) and HCL AppScan (commercial SAST/DAST report import). "
            "Also pulls GitHub-native signals via codeql, dependabot and github_secrets — "
            "one GitHub PAT in the agent config covers all three GitHub-side imports. "
            "Private-repo clones authenticate with GIT_USERNAME / GIT_TOKEN; snyk additionally "
            "needs SNYK_TOKEN."
        ),
    },
    "secrets": {
        "agent_name": "secrets-agent",
        "executors": ["gitleaks", "trufflehog"],
        "description": (
            "Secret detection across source trees and full git history. Runs gitleaks "
            "(pattern-based, history-aware) and trufflehog (with credential verification — "
            "only reports a secret as confirmed once it successfully authenticates). Surfaces "
            "hard-coded API keys, tokens, AWS keys, private keys, and database creds. Clones "
            "private repositories at scan time with the GIT_USERNAME / GIT_TOKEN env vars."
        ),
    },
    "iac-cloud": {
        "agent_name": "iac-cloud-agent",
        "executors": ["checkov", "prowler", "tfsec", "kics"],
        "description": (
            "Infrastructure-as-Code static analysis and Cloud Security Posture Management. "
            "Runs checkov, tfsec and kics against IaC files (Terraform, Kubernetes, "
            "CloudFormation, Dockerfile, Ansible, Helm, ARM) — cloned at scan time via "
            "GIT_USERNAME / GIT_TOKEN. Also runs prowler live against AWS, Azure or GCP — "
            "set the corresponding cloud credentials as agent env vars before launching "
            "(AWS_ACCESS_KEY_ID, AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET, "
            "GOOGLE_APPLICATION_CREDENTIALS)."
        ),
    },
    "container-k8s": {
        "agent_name": "container-k8s-agent",
        "executors": ["trivy", "grype", "kubescape", "kube_bench"],
        "description": (
            "Container and Kubernetes security scanning. Runs trivy (multi-target — images, "
            "filesystems, repos, IaC, clusters) and grype (image / filesystem / SBOM vuln "
            "scanner) for CVEs; kubescape for cluster posture against NSA / MITRE / CIS / "
            "ArmoBest frameworks; and kube-bench for the CIS Kubernetes Benchmark on the host "
            "where the executor runs. Cluster scans need a kubeconfig inside the container."
        ),
    },
    "discovery-osint": {
        "agent_name": "discovery-osint-agent",
        "executors": [
            "subfinder", "naabu", "nmap", "shodan2", "sublist3r",
            "amass", "masscan", "dnstwist", "theharvester",
        ],
        "description": (
            "Passive reconnaissance, active host discovery and brand-protection signals. "
            "Subdomain / DNS enum: subfinder, amass (heavier-duty, more sources), sublist3r "
            "and theharvester (also pulls emails / employees / breaches). Active port "
            "scanning: naabu (fast SYN/CONNECT), nmap (with NSE scripting) and masscan "
            "(internet-scale, >1M pps). Passive Internet-wide intel: shodan2 (needs "
            "SHODAN_API_KEY). Brand-protection: dnstwist (typo-squat / lookalike domain "
            "detection, with optional MX-record probing to flag phishing-ready domains). "
            "Active scanning (naabu, nmap, masscan) is the reason the agents live on "
            "DigitalOcean — outbound port scanning is prohibited from the AWS network."
        ),
    },
    "web-dast": {
        "agent_name": "web-dast-agent",
        "executors": ["ffuf", "nuclei", "zap", "nikto2", "wpscan", "burp"],
        "description": (
            "Web fuzzing and dynamic application testing. Runs ffuf (HTTP fuzzer — wordlist "
            "substitution into the FUZZ token), nuclei (ProjectDiscovery's templated vuln "
            "scanner with a huge community ruleset), nikto2 (web server fingerprinting and "
            "known-issue checks), zap (OWASP ZAP DAST), wpscan (WordPress vulnerability "
            "scanner) and burp (Burp Suite Pro report import). The ffuf wordlist must be "
            "staged inside the container; burp needs a Burp Pro license + pre-exported XML "
            "to import."
        ),
    },
    "endpoint-edr": {
        "agent_name": "endpoint-edr-agent",
        "executors": ["crowdstrike", "sentinelone", "wazuh", "microsoft_defender"],
        "description": (
            "Endpoint Detection and Response data import. Pulls findings from CrowdStrike "
            "Falcon (Spotlight JSON export pre-staged inside the container), SentinelOne "
            "(live management API at /web/api/v2.1/threats), Wazuh (live REST API) and "
            "Microsoft Defender for Endpoint (live Graph API). Configure each vendor's URL "
            "and API credentials as agent env vars (SENTINELONE_URL/_TOKEN, "
            "WAZUH_URL/_USERNAME/_PASSWORD, MS_DEFENDER_TENANT_ID/_CLIENT_ID/_CLIENT_SECRET) "
            "before scanning."
        ),
    },
    "vulnscan": {
        "agent_name": "vulnscan",
        "executors": [
            "nessus", "tenableio", "tenablesc", "insightvm", "qualys",
            "gvm_openvas", "cisco_cybervision", "report_processor",
        ],
        "description": (
            "Enterprise vulnerability management and report ingest. Pulls findings from "
            "Nessus, Tenable.io and Tenable.sc (Tenable family), Rapid7 InsightVM, Qualys "
            "VMDR, OpenVAS/GVM and Cisco Cyber Vision (OT/ICS); plus report_processor as a "
            "generic SARIF/JSON/XML import path for scan exports produced outside the agents. "
            "Each vendor needs its API URL + token as agent env vars (TENABLE_IO_ACCESS_KEY/"
            "SECRET_KEY, NESSUS_URL/USERNAME/PASSWORD, QUALYS_URL/USERNAME/PASSWORD, "
            "INSIGHTVM_URL/USERNAME/PASSWORD, OPENVAS_URL/USERNAME/PASSWORD, etc.) before "
            "scanning."
        ),
    },
    "redteam": {
        "agent_name": "redteam",
        "executors": ["crackmapexec"],
        "description": (
            "Red-team / post-exploitation tooling. Runs CrackMapExec (CME) for Active "
            "Directory enumeration, SMB / WinRM / MSSQL / SSH authentication checks, "
            "credential validation, share / session listing, and protocol-level attacks "
            "across a target range. CrackMapExec needs reachable target hosts and a set of "
            "credentials passed at scan time (username + password or hash); use this agent "
            "only against environments where you have explicit testing authorization."
        ),
    },
    "remediate": {
        "agent_name": "remediate",
        "executors": ["vicarius"],
        "description": (
            "Endpoint remediation status import via the Vicarius vRx External Data API. "
            "Pulls asset inventory, active CVEs grouped by vulnerabilityId, and missing "
            "patches per endpoint. Configure VICARIUS_API_URL and VICARIUS_TOKEN as agent "
            "env vars (the token is sent as the 'Vicarius-Token' header). Read-only today — "
            "patch execution and external-findings ingest are not exposed by the vRx PAT "
            "scope; new modes (apply-patch, run-script) will be added if Vicarius opens "
            "those endpoints."
        ),
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a Vicarius dispatcher manifest with all official Faraday executors."
    )
    parser.add_argument("--agent-token", required=True, help="64-character token returned by POST /_api/v3/agents")
    parser.add_argument("--namespace", default="client-vicarius")
    parser.add_argument("--deployment", default="vicarius-agent-dispatcher")
    parser.add_argument("--agent-name", default="vicariusAllToolsDispatcher")
    parser.add_argument("--host", default="vicarius.apps.faradaysec.com")
    parser.add_argument("--image", default="faradaysec/faraday_agent_dispatcher:3.9.1")
    parser.add_argument("--node-group", default="corporate")
    parser.add_argument(
        "--image-pull-secret",
        help="Name of a docker-registry secret to attach as imagePullSecrets "
        "(needed when --image lives in a private registry).",
    )
    parser.add_argument(
        "--group",
        choices=sorted(AGENT_GROUPS),
        help="Restrict to a single capability group (its executors, agent name and deployment name). "
        "Omit for the default all-official-tools agent.",
    )
    parser.add_argument("--output", help="Write generated YAML to this path instead of stdout")
    parser.add_argument("--config-only", action="store_true", help="Only output dispatcher.yaml content")
    return parser.parse_args()


def build_executors(only: list[str] | None = None) -> dict[str, dict[str, Any]]:
    executors = {}
    manifests = all_manifests()

    if only is not None:
        missing = [name for name in only if name not in manifests]
        if missing:
            raise ValueError(
                f"group references executors with no installed manifest: {missing}. "
                "Ensure the offensive-check manifests are vendored into "
                "faraday_agent_parameters_types/static/manifests/."
            )
        wanted = [name for name in sorted(manifests) if name in only]
    else:
        wanted = sorted(manifests)

    for name in wanted:
        manifest = manifests[name]
        varenvs = {env_name: "" for env_name in manifest.get("environment_variables", [])}
        varenvs.update(DEFAULT_EXECUTOR_ENVS.get(name, {}))

        executors[name] = {
            "max_size": 314572800,
            "repo_executor": manifest["repo_executor"],
            "repo_name": name,
            "params": manifest.get("arguments", {}),
            "varenvs": varenvs,
        }

    return executors


def resolve_group(args: argparse.Namespace):
    """Return (agent_name, deployment_name, executor_filter, description)."""
    if args.group:
        group = AGENT_GROUPS[args.group]
        agent_name = group["agent_name"]
        deployment = f"vicarius-{args.group}-dispatcher"
        description = group.get("description") or f"Offensive Checks {args.group} agent for Vicarius"
        return agent_name, deployment, group["executors"], description
    return (
        args.agent_name,
        args.deployment,
        None,
        "Demo dispatcher with all Faraday executors for Vicarius partnership evaluation",
    )


def build_dispatcher_config(args: argparse.Namespace) -> dict[str, Any]:
    agent_name, _deployment, executor_filter, description = resolve_group(args)
    return {
        "agent": {
            "agent_name": agent_name,
            "description": description,
            "executors": build_executors(executor_filter),
        },
        "server": {
            "host": args.host,
            "ssl": True,
            "ssl_ignore": False,
            "ssl_cert": "",
            "api_port": 443,
            "websocket_port": 443,
        },
        "tokens": {"agent": args.agent_token},
    }


def labels(group: str | None = None) -> dict[str, str]:
    base = {
        "app.kubernetes.io/name": "faraday-agent-dispatcher",
        "app.kubernetes.io/instance": "vicarius",
        "app.kubernetes.io/component": "agent-dispatcher",
    }
    if group:
        base["faradaysec.com/group"] = group
    return base


def build_k8s_manifest(args: argparse.Namespace) -> list[dict[str, Any]]:
    dispatcher_config = build_dispatcher_config(args)
    executor_count = len(dispatcher_config["agent"]["executors"])
    _agent_name, deployment_name, _filter, _desc = resolve_group(args)
    object_labels = labels(args.group)

    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": f"{deployment_name}-config",
            "namespace": args.namespace,
            "labels": object_labels,
            "annotations": {
                "faradaysec.com/executor-count": str(executor_count),
                "faradaysec.com/dispatcher-version": __version__,
            },
        },
        "type": "Opaque",
        "stringData": {
            "dispatcher.yaml": yaml.safe_dump(dispatcher_config, sort_keys=False),
        },
    }

    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": deployment_name,
            "namespace": args.namespace,
            "labels": object_labels,
        },
        "spec": {
            "replicas": 1,
            "revisionHistoryLimit": 3,
            "selector": {"matchLabels": object_labels},
            "strategy": {"type": "RollingUpdate"},
            "template": {
                "metadata": {
                    "labels": object_labels,
                    "annotations": {
                        "faradaysec.com/executor-count": str(executor_count),
                        "faradaysec.com/config-source": "generated-from-faraday_agent_dispatcher-manifests",
                    },
                },
                "spec": {
                    "nodeSelector": {"node-group": args.node_group},
                    "terminationGracePeriodSeconds": 30,
                    **({"imagePullSecrets": [{"name": args.image_pull_secret}]} if args.image_pull_secret else {}),
                    "containers": [
                        {
                            "name": "dispatcher",
                            "image": args.image,
                            "imagePullPolicy": "Always",
                            "args": [
                                "--config-file",
                                "/root/.faraday/config/dispatcher.yaml",
                                "--logdir",
                                "/root/.faraday/logs",
                                "--log-level",
                                "info",
                            ],
                            "env": [
                                {"name": "PYTHONUNBUFFERED", "value": "1"},
                                {"name": "HOME", "value": "/root"},
                            ],
                            "resources": {
                                "requests": {"cpu": "500m", "memory": "1Gi"},
                                "limits": {"cpu": "2", "memory": "4Gi"},
                            },
                            "volumeMounts": [
                                {
                                    "name": "dispatcher-config",
                                    "mountPath": "/root/.faraday/config/dispatcher.yaml",
                                    "subPath": "dispatcher.yaml",
                                    "readOnly": True,
                                },
                                {"name": "dispatcher-logs", "mountPath": "/root/.faraday/logs"},
                                {"name": "dispatcher-reports", "mountPath": "/root/reports"},
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "name": "dispatcher-config",
                            "secret": {"secretName": f"{deployment_name}-config"},
                        },
                        {"name": "dispatcher-logs", "emptyDir": {}},
                        {"name": "dispatcher-reports", "emptyDir": {}},
                    ],
                },
            },
        },
    }

    return [secret, deployment]


def render(args: argparse.Namespace) -> str:
    if not (len(args.agent_token) == 64 and args.agent_token.isalnum()):
        raise ValueError("--agent-token must be a 64-character alphanumeric Faraday agent token")

    if args.config_only:
        return yaml.safe_dump(build_dispatcher_config(args), sort_keys=False)

    return yaml.safe_dump_all(build_k8s_manifest(args), sort_keys=False)


def main() -> int:
    args = parse_args()
    try:
        output = render(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
