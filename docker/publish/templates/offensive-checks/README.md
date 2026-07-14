# Offensive Checks Dispatcher Deployment

Reusable, secret-free template that ships a Faraday dispatcher pre-loaded with
every official executor plus the vendored offensive-check tools. Use it as a
starting point for any Kubernetes deployment — replace the placeholders in the
snippets below with your own namespace, agent name, and image tag.

## What Gets Deployed

- Namespace: `<your-namespace>`
- Deployment: `offensive-checks-agent-dispatcher`
- Config Secret: `offensive-checks-agent-dispatcher-config`
- Image: `faradaysec/faraday_agent_dispatcher:<tag>`
- Faraday agent name: `<your-agent-name>` (e.g. `offensive-checks-dispatcher`)
- Registered executor count depends on the manifests bundled with the image

The generated Secret contains the Faraday agent token. **Do not commit the
generated output** — regenerate it at deploy time.

## How The Tools Are Registered

The dispatcher config is generated from the packaged executor manifests — nothing is typed by hand:

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

Register a Faraday agent token from inside the Faraday pod. This uses the pod's `ADMIN_USER` / `ADMIN_PASS` env vars and only prints the new 64-character dispatcher token.

```bash
NAMESPACE="<your-namespace>"
AGENT_NAME="offensive-checks-dispatcher"
AGENT_TOKEN=$(kubectl -n "$NAMESPACE" exec -i deploy/faraday -- env AGENT_NAME="$AGENT_NAME" python - <<'PY'
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
    "description": "Offensive Checks dispatcher with all official Faraday executors",
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
./.venv/bin/python docker/publish/templates/offensive-checks/generate_dispatcher_manifest.py \
  --agent-token "$AGENT_TOKEN" \
  | kubectl -n "$NAMESPACE" apply -f -

kubectl -n "$NAMESPACE" \
  rollout status deployment/offensive-checks-agent-dispatcher --timeout=240s
```

If only the Secret changes, restart the deployment so the mounted config is reloaded:

```bash
kubectl -n "$NAMESPACE" \
  rollout restart deployment/offensive-checks-agent-dispatcher
```

## Verify

```bash
kubectl -n "$NAMESPACE" \
  get deployment offensive-checks-agent-dispatcher -o wide

kubectl -n "$NAMESPACE" \
  logs deployment/offensive-checks-agent-dispatcher --since=10m
```

Expected log lines include:

```text
Registered successfully
Trying to connect to: https://<your-faraday-host>:443
```

## Registered Executors

**Official (27):** `appscan`, `arachni`, `burp`, `cisco_cybervision`, `codeql`, `crackmapexec`, `dependabot`, `github_secrets`, `gvm_openvas`, `insightvm`, `microsoft_defender`, `nessus`, `nikto2`, `nmap`, `nuclei`, `openvas_legacy`, `qualys`, `report_processor`, `shodan2`, `sonarqube`, `sublist3r`, `tenableio`, `tenablesc`, `w3af`, `wpscan`, `wpscan_legacy`, `zap`.

**Offensive Checks (20):** `bandit`, `semgrep`, `shellcheck`, `snyk`, `gitleaks`, `trufflehog`, `checkov`, `prowler`, `tfsec`, `kics`, `trivy`, `grype`, `kubescape`, `kube-bench`, `subfinder`, `naabu`, `ffuf`, `crowdstrike`, `sentinelone`, `wazuh`.

The offensive-check manifests are vendored into the image (`offensive_checks/manifests/`, copied into `faraday_agent_parameters_types/static/manifests/` at build time), their tool binaries are installed in the final image, and the temporary `faraday_plugins` parser fixes are applied inline during the image build. No package release is required.

## Capability-Grouped Agents

Instead of one all-tools agent, the offensive-check executors can be deployed as separate agents per capability group. Pass `--group` to the generator; each group produces its own Secret + Deployment (`offensive-checks-<group>-dispatcher`) and agent name:

| `--group` | agent name | executors |
|-----------|-----------|-----------|
| `code-sast` | `code-sast-agent` | bandit, semgrep, shellcheck, snyk |
| `secrets` | `secrets-agent` | gitleaks, trufflehog |
| `iac-cloud` | `iac-cloud-agent` | checkov, prowler, tfsec, kics |
| `container-k8s` | `container-k8s-agent` | trivy, grype, kubescape, kube-bench |
| `discovery-osint` | `discovery-osint-agent` | subfinder, naabu |
| `web-dast` | `web-dast-agent` | ffuf |
| `endpoint-edr` | `endpoint-edr-agent` | crowdstrike, sentinelone, wazuh |

Each group needs its own agent token (one `POST /_api/v3/agents` per group). Example:

```bash
for group in code-sast secrets iac-cloud container-k8s discovery-osint web-dast endpoint-edr; do
  TOKEN=$(...mint a token as above, with AGENT_NAME=${group}-agent...)
  ./.venv/bin/python docker/publish/templates/offensive-checks/generate_dispatcher_manifest.py \
    --group "$group" --agent-token "$TOKEN" \
    | kubectl -n "$NAMESPACE" apply -f -
done
```

Omitting `--group` keeps the original behavior: a single `offensive-checks-dispatcher` with all 47 executors.

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
