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
        "executors": ["bandit", "semgrep", "shellcheck", "snyk"],
    },
    "secrets": {
        "agent_name": "secrets-agent",
        "executors": ["gitleaks", "trufflehog"],
    },
    "iac-cloud": {
        "agent_name": "iac-cloud-agent",
        "executors": ["checkov", "prowler", "tfsec", "kics"],
    },
    "container-k8s": {
        "agent_name": "container-k8s-agent",
        "executors": ["trivy", "grype", "kubescape", "kube_bench"],
    },
    "discovery-osint": {
        "agent_name": "discovery-osint-agent",
        "executors": ["subfinder", "naabu"],
    },
    "web-dast": {
        "agent_name": "web-dast-agent",
        "executors": ["ffuf"],
    },
    "endpoint-edr": {
        "agent_name": "endpoint-edr-agent",
        "executors": ["crowdstrike", "sentinelone", "wazuh"],
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
        description = f"Offensive Checks {args.group} agent for Vicarius"
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
                            "imagePullPolicy": "IfNotPresent",
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
