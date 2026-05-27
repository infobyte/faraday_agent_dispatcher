# Vicarius Dispatcher Deployment

This documents the production deployment made for `vicarius.apps.faradaysec.com` and keeps a reusable, secret-free template in the repository.

## What Was Deployed

- Namespace: `client-vicarius`
- Deployment: `vicarius-agent-dispatcher`
- Config Secret: `vicarius-agent-dispatcher-config`
- Image: `faradaysec/faraday_agent_dispatcher:3.9.1`
- Faraday agent name: `vicariusAllToolsDispatcher`
- AWS profile/context used: `AWS_PROFILE=faraday_prod`, `kubectl --context faraday-prod`
- Registered executor count: `27`

The actual deployment config contains a Faraday agent token in the Kubernetes Secret. That token is intentionally not stored here.

## How The Tools Were Added

The tools were not typed by hand. The deployment config is generated from the dispatcher package manifests:

```python
from faraday_agent_dispatcher import __version__
from faraday_agent_parameters_types.utils import get_manifests

manifests = get_manifests(__version__)
```

For each manifest, the generator adds an executor with:

- `repo_executor` from the manifest, for example `nmap.py`
- `repo_name` set to the manifest name, for example `nmap`
- `params` copied from the manifest `arguments`
- `varenvs` created from manifest `environment_variables`
- blank credential values by default, except tool path defaults for `arachni`, `nuclei`, and `report_processor`

## Reproduce

Create/register a Faraday agent token from inside the Faraday pod. This uses the pod's existing `ADMIN_USER` and `ADMIN_PASS` env vars and only prints the new 64-character dispatcher token.

```bash
NAMESPACE="client-vicarius"
AGENT_NAME="vicariusAllToolsDispatcher"
AGENT_TOKEN=$(AWS_PROFILE=faraday_prod kubectl --context faraday-prod -n "$NAMESPACE" exec -i deploy/vicarius-faraday -- env AGENT_NAME="$AGENT_NAME" python - <<'PY'
import base64
import json
import os
import urllib.request

base_url = "http://127.0.0.1:5985/_api/v3"
credentials = f"{os.environ['ADMIN_USER']}:{os.environ['ADMIN_PASS']}".encode()
auth_header = "Basic " + base64.b64encode(credentials).decode()

token_request = urllib.request.Request(f"{base_url}/agent_token")
token_request.add_header("Authorization", auth_header)
with urllib.request.urlopen(token_request, timeout=15) as response:
    registration_token = json.load(response)["token"]

payload = json.dumps({
    "token": registration_token,
    "name": os.environ["AGENT_NAME"],
    "description": "Demo dispatcher with all official Faraday executors for Vicarius partnership evaluation",
}).encode()
agent_request = urllib.request.Request(
    f"{base_url}/agents",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(agent_request, timeout=15) as response:
    print(json.load(response)["token"])
PY
)
```

Generate and apply the Kubernetes Secret plus Deployment:

```bash
./.venv/bin/python docker/publish/templates/vicarius/generate_dispatcher_manifest.py \
  --agent-token "$AGENT_TOKEN" \
  | AWS_PROFILE=faraday_prod kubectl --context faraday-prod apply -f -

AWS_PROFILE=faraday_prod kubectl --context faraday-prod -n client-vicarius \
  rollout status deployment/vicarius-agent-dispatcher --timeout=240s
```

If only the Secret changes, restart the deployment so the mounted config is reloaded:

```bash
AWS_PROFILE=faraday_prod kubectl --context faraday-prod -n client-vicarius \
  rollout restart deployment/vicarius-agent-dispatcher
```

## Verify

```bash
AWS_PROFILE=faraday_prod kubectl --context faraday-prod -n client-vicarius \
  get deployment vicarius-agent-dispatcher -o wide

AWS_PROFILE=faraday_prod kubectl --context faraday-prod -n client-vicarius \
  logs deployment/vicarius-agent-dispatcher --since=10m
```

Expected log lines include:

```text
Registered successfully
Trying to connect to: https://vicarius.apps.faradaysec.com:443
```

## Registered Executors

`appscan`, `arachni`, `burp`, `cisco_cybervision`, `codeql`, `crackmapexec`, `dependabot`, `github_secrets`, `gvm_openvas`, `insightvm`, `microsoft_defender`, `nessus`, `nikto2`, `nmap`, `nuclei`, `openvas_legacy`, `qualys`, `report_processor`, `shodan2`, `sonarqube`, `sublist3r`, `tenableio`, `tenablesc`, `w3af`, `wpscan`, `wpscan_legacy`, `zap`.

## Credential And Runtime Gaps

- `appscan`: `HCL_KEY_ID`, `HCL_KEY_SECRET`, `HCL_APP_ID`
- `burp`: `BURP_HOST`, `BURP_API_KEY`, `BURP_API_PULL_INTERVAL`
- `cisco_cybervision`: `CYBERVISION_TOKEN`, `CYBERVISION_HTTPS_URL`
- `codeql`, `dependabot`, `github_secrets`: `GITHUB_TOKEN`, `GITHUB_OWNER`
- `gvm_openvas`: `GVM_USER`, `GVM_PASSW`, `HOST`, `PORT`
- `insightvm`: `INSIGHTVM_HOST`, `INSIGHTVM_USR`, `INSIGHTVM_PASSWD`
- `microsoft_defender`: `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`
- `nessus`: `NESSUS_USERNAME`, `NESSUS_PASSWORD`, `NESSUS_URL`
- `qualys`: `QUALYS_USERNAME`, `QUALYS_PASSWORD`
- `sonarqube`: `SONAR_URL`, plus `TOKEN` as run parameter
- `tenableio`: `TENABLE_ACCESS_KEY`, `TENABLE_SECRET_KEY`, `TENABLE_PULL_INTERVAL`
- `tenablesc`: `TENABLE_HOST`, `TENABLE_ACCESS_KEY`, `TENABLE_SECRET_KEY`
- `zap`: `ZAP_API_KEY`, plus a running ZAP process reachable from the dispatcher container
- `w3af`: `W3AF_PATH`
- `shodan2`: Shodan CLI auth is required in the container runtime
- `report_processor`: reports must be mounted under `/root/reports`

Executors with mostly target/input-only operation: `arachni`, `crackmapexec`, `nikto2`, `nmap`, `nuclei`, `openvas_legacy`, `sublist3r`, `wpscan`, `wpscan_legacy`.
