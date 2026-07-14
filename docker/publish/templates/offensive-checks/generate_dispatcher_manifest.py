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
            "bandit",
            "semgrep",
            "shellcheck",
            "snyk",
            "codeql",
            "dependabot",
            "github_secrets",
            "github_security",
            "sonarqube",
            "sonarcloud",
            "appscan",
            "checkmarx_one",
            "checkmarx_sast",
            "checkmarx_sca",
            "fortify_ssc",
            "fortify_fod",
            "veracode",
            "contrast_security",
            "coverity",
            "pradeo_mobile",
            "gitlab_security",
            "bitbucket_security",
            "azure_devops_security",
            "owasp_dep_check",
        ],
        "description": (
            "Static Application Security Testing (SAST) and supply-chain signal import for "
            "source code. Runs bandit (Python), semgrep (multi-language with community rule "
            "packs), shellcheck (shell scripts), snyk (SCA + SAST + IaC), sonarqube "
            "(commercial SAST import) and HCL AppScan (commercial SAST/DAST report import). "
            "Also pulls GitHub-native signals via codeql, dependabot and github_secrets — "
            "one GitHub PAT in the agent config covers all three GitHub-side imports. "
            "github_security is a fan-out superset of those three that calls every GHAS "
            "alert API (code-scanning + secret-scanning + dependabot) under a single "
            "GH_TOKEN, gated by GH_SCAN_TYPES (CSV of code|secrets|dependabot). "
            "Includes contrast_security (Contrast Assess IAST REST API import — pulls "
            "per-application traces from a Contrast TeamServer tenant; needs CONTRAST_HOST + "
            "CONTRAST_ORG_ID + CONTRAST_AUTH + CONTRAST_API_KEY + CONTRAST_SERVICE_KEY), "
            "coverity (Coverity Connect / Synopsys / Black Duck REST + SOAP importer — pulls "
            "per-project defects from a Coverity Connect manager with SOAP v9 fallback for "
            "9.x and earlier; needs COVERITY_HOST + COVERITY_USER + COVERITY_PASSWORD), "
            "pradeo_mobile (Pradeo Mobile Security MAST REST API import — pulls per-application "
            "mobile threats from a Pradeo Security Center tenant; needs PRADEO_HOST + "
            "PRADEO_TOKEN), gitlab_security (GitLab Vulnerability Report REST API import — "
            "pulls SAST / dependency_scanning / container_scanning / secret_detection / DAST "
            "findings from a GitLab instance's Security Dashboard; needs GITLAB_HOST + "
            "GITLAB_TOKEN), and bitbucket_security (Bitbucket Cloud Code Insights REST API "
            "import — pulls SECURITY-type reports and their VULNERABILITY annotations from a "
            "Bitbucket Cloud repository at a specific commit; needs BB_USER + BB_APP_PASSWORD, "
            "with BB_HOST defaulting to https://api.bitbucket.org for Bitbucket Cloud and "
            "settable to the on-prem Bitbucket Data Center API host), "
            "azure_devops_security (Azure DevOps Advanced Security REST API fan-out import — "
            "pulls code-scanning + secret-scanning + dependency-scanning alerts from a single "
            "ADO repository under one PAT; needs ADO_ORG + ADO_PAT env vars and ADO_PROJECT + "
            "ADO_REPO scan args, with ADO_ALERT_TYPE (CSV of code|secret|dependency) scoping "
            "the fan-out and ADO_HOST defaulting to https://advsec.dev.azure.com; PAT needs "
            "Advanced Security: Read + Code: Read scopes), and "
            "owasp_dep_check (OWASP Dependency-Check CLI wrapper — runs "
            "`dependency-check.sh --scan <target> --format JSON --out <out>` against a "
            "checked-out source tree, parses the JSON report and ingests one Faraday "
            "host with per-dependency vulnerabilities; needs the dependency-check CLI on "
            "PATH and optionally a DEPCHECK_SUPPRESSION_FILE). "
            "Private-repo clones authenticate with GIT_USERNAME / GIT_TOKEN; snyk additionally "
            "needs SNYK_TOKEN."
        ),
    },
    "sca-supply-chain": {
        "agent_name": "sca-supply-chain-agent",
        "executors": [
            "blackduck_sca",
            "blackduck_coverity",
            "mend",
            "sonatype_nexus_iq",
            "jfrog_xray",
            "jfrog_artifactory",
            "endoflife_date",
            "owasp_dep_check",
            "whitehat_sentinel",
            "npm_audit",
        ],
        "description": (
            "Software Composition Analysis and supply-chain risk scanners — pulls open-source "
            "component vulns, licence issues, and dependency-graph findings from commercial SCA "
            "platforms and registry security products. Complements the SAST-side coverage in "
            "`code-sast`. Runs blackduck_sca (Black Duck Hub REST API — per-version vulnerable-BOM "
            "components; needs BD_HOST + BD_TOKEN), blackduck_coverity (Coverity Connect REST API, "
            "stream-scoped — distinct from the legacy `coverity` executor in `code-sast` which "
            "handles multi-project enumeration and the SOAP fallback; needs COVERITY_HOST + "
            "COVERITY_USER + COVERITY_PASSWORD), mend (Mend / WhiteSource REST API — per-project "
            "security alerts; needs MEND_HOST + MEND_USER_KEY + MEND_API_KEY), sonatype_nexus_iq "
            "(Sonatype Nexus IQ REST API — per-application policy report security issues; needs "
            "NEXUS_IQ_HOST + NEXUS_IQ_USER + NEXUS_IQ_PASSWORD), jfrog_xray (JFrog Xray REST API "
            "— per-artifact / per-build component vulnerabilities; needs XRAY_HOST + XRAY_USER + "
            "XRAY_API_KEY), jfrog_artifactory (JFrog Artifactory REST API, Xray-enabled — "
            "per-artifact component vulnerabilities surfaced through the Artifactory security "
            "endpoint; needs ARTIFACTORY_HOST + ARTIFACTORY_USER + ARTIFACTORY_API_KEY), "
            "endoflife_date (public endoflife.date REST API — flags currently-deployed runtime / "
            "OS / package versions whose release line is past End-Of-Life; unauthenticated, takes "
            "PRODUCTS + INSTALLED_VERSIONS CSVs), owasp_dep_check (OWASP Dependency-Check CLI "
            "wrapper — same executor as in `code-sast`; runs `dependency-check.sh --scan <target> "
            "--format JSON --out <out>` against a checked-out source tree; needs the "
            "dependency-check CLI on PATH and optionally a DEPCHECK_SUPPRESSION_FILE), and "
            "whitehat_sentinel (legacy WhiteHat Sentinel REST API — per-site DAST vulnerabilities "
            "from orgs still on the legacy product; WhiteHat is now Black Duck Continuous "
            "Dynamic; needs WH_API_KEY)."
        ),
    },
    "cloud-security": {
        "agent_name": "cloud-security-agent",
        "executors": [
            "wiz",
            "orca",
            "lacework",
            "prisma_cloud",
            "aqua_enterprise",
            "aqua_saas",
            "checkpoint_cloudguard",
            "trendmicro_conformity",
            "crowdstrike_cloud",
            "rapid7_insightcloudsec",
        ],
        "description": (
            "Cloud-Native Application Protection (CNAPP) and Cloud Security Posture Management "
            "(CSPM) — ingests findings from cross-cloud security platforms covering "
            "misconfigurations, runtime threats, identity risks, and workload vulnerabilities "
            "across AWS / Azure / GCP / Kubernetes. Runs wiz (Wiz GraphQL API — paginated "
            "`issuesV2` IssuesTable query against a project, OAuth2 client_credentials via "
            "`{WIZ_AUTH_HOST}/oauth/token`; needs WIZ_HOST + WIZ_AUTH_HOST + WIZ_CLIENT_ID + "
            "WIZ_CLIENT_SECRET), orca (Orca Security REST API — paginated `/api/alerts` with "
            "per-asset enrichment via `/api/assets`, native `Authorization: Token` header; "
            "needs ORCA_HOST + ORCA_API_TOKEN), lacework (Lacework REST API — paginated "
            "`/api/v2/Vulnerabilities/Hosts|Containers/search`, API-key / API-secret pair "
            "exchanged for a bearer at `/api/v2/access/tokens`; takes LACEWORK_SCOPE "
            "(hosts | containers | both); needs LACEWORK_ACCOUNT + LACEWORK_API_KEY + "
            "LACEWORK_API_SECRET), prisma_cloud (Palo Alto Prisma Cloud REST API — paginated "
            "`/alert` with `/v2/alert/policy` + `/cloud` enrichment, access-key / secret-key "
            "exchanged for an `x-redlock-auth` token at `/login`; needs PRISMA_HOST + "
            "PRISMA_USERNAME + PRISMA_PASSWORD), aqua_enterprise (Aqua Enterprise REST API — "
            "paginated `/api/v2/risks/vulnerabilities` with per-image enrichment via "
            "`/api/v2/images`, local-account login at `/api/v1/login`; needs AQUA_HOST + "
            "AQUA_USER + AQUA_PASSWORD), aqua_saas (Aqua SaaS variant of aqua_enterprise — "
            "same code path, AQUA_HOST hardcoded to https://cloudsploit.com with per-region "
            "endpoint resolution via AQUA_REGION (us | eu | apac | singapore); needs "
            "AQUA_USER + AQUA_PASSWORD), checkpoint_cloudguard (Check Point CloudGuard REST "
            "API — paginated `/v1/findings` with per-account enrichment via "
            "`/v1/cloud-accounts/{id}`, HTTP Basic with API key / secret pair; needs CG_HOST "
            "+ CG_API_KEY + CG_API_SECRET), trendmicro_conformity (Trend Micro Cloud One "
            "Conformity JSON:API — paginated `/api/checks` with per-account enrichment via "
            "`/api/accounts/{id}`, region-pinned base URL "
            "`https://{region}-api.cloudconformity.com` resolved from CONFORMITY_REGION "
            "(us-west-2 | eu-west-1 | ap-southeast-2 | ap-southeast-1 | ca-central-1), "
            "ApiKey-scheme auth; needs CONFORMITY_API_KEY), crowdstrike_cloud (CrowdStrike "
            "Falcon Cloud Security REST API — paginated `/cloud-security/queries/iom/v1` + "
            "batch `/cloud-security/entities/iom/v1?ids=` with FQL `cloud_provider:` + "
            "`severity:[...]` filters, OAuth2 client_credentials at `/oauth2/token` "
            "identical to Falcon Spotlight / Detect / Hosts; needs FALCON_HOST + "
            "FALCON_CLIENT_ID + FALCON_CLIENT_SECRET), and rapid7_insightcloudsec (Rapid7 "
            "InsightCloudSec REST API, formerly DivvyCloud — `/v2/public/insights/list` "
            "catalogue + `/v2/public/insight/{id}/evaluation/run` per-insight matching "
            "resources, single long-lived `Api-Key` header; needs ICS_HOST + ICS_API_KEY)."
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
        "executors": ["checkov", "prowler", "tfsec", "kics", "tripwire_enterprise"],
        "description": (
            "Infrastructure-as-Code static analysis and Cloud Security Posture Management. "
            "Runs checkov, tfsec and kics against IaC files (Terraform, Kubernetes, "
            "CloudFormation, Dockerfile, Ansible, Helm, ARM) — cloned at scan time via "
            "GIT_USERNAME / GIT_TOKEN. Also runs prowler live against AWS, Azure or GCP — "
            "set the corresponding cloud credentials as agent env vars before launching "
            "(AWS_ACCESS_KEY_ID, AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET, "
            "GOOGLE_APPLICATION_CREDENTIALS). Extends to runtime compliance / "
            "file-integrity-monitoring posture via tripwire_enterprise (Tripwire Enterprise "
            "REST API — pulls compliance / FIM findings against managed-node baselines)."
        ),
    },
    "container-k8s": {
        "agent_name": "container-k8s-agent",
        "executors": [
            "trivy",
            "grype",
            "kubescape",
            "kube_bench",
            "prisma_cloud_compute",
            "rhacs",
            "qualys_container_security",
        ],
        "description": (
            "Container and Kubernetes security scanning. Runs trivy (multi-target — images, "
            "filesystems, repos, IaC, clusters) and grype (image / filesystem / SBOM vuln "
            "scanner) for CVEs; kubescape for cluster posture against NSA / MITRE / CIS / "
            "ArmoBest frameworks; and kube-bench for the CIS Kubernetes Benchmark on the host "
            "where the executor runs. Cluster scans need a kubeconfig inside the container. "
            "Also runs prisma_cloud_compute (Prisma Cloud Compute Edition / formerly Twistlock "
            "REST API import — paginated GET /api/v22.01/images (image scan results with "
            "embedded vulnerabilities) + GET /api/v22.01/hosts (host scan results with "
            "embedded vulnerabilities) + optional GET /api/v22.01/vulnerabilities CVE catalogue "
            "enrichment, scope-gated via TWISTLOCK_SCOPE (images | hosts | both), short-lived "
            "JWT exchanged at POST /api/v22.01/authenticate; needs TWISTLOCK_HOST + "
            "TWISTLOCK_USER + TWISTLOCK_PASSWORD), rhacs (Red Hat Advanced Cluster "
            "Security for Kubernetes / formerly StackRox REST API import — paginated GET "
            "/v1/alerts (policy violations) + GET /v1/alerts/{id} (per-alert detail with "
            "full policy / deployment / violations payload) + GET /v1/images (image listing) "
            "+ GET /v1/images/{id} (per-image scan.components[].vulns[] tree), search-filtered "
            "via Cluster:<name>+Namespace:<ns>+Severity:<csv>, long-lived API token sent as "
            "Authorization: Bearer <RHACS_TOKEN> on every call; takes RHACS_CLUSTER + "
            "RHACS_NAMESPACE + RHACS_MIN_SEVERITY (LOW_SEVERITY | MEDIUM_SEVERITY | "
            "HIGH_SEVERITY | CRITICAL_SEVERITY); needs RHACS_HOST + RHACS_TOKEN), and "
            "qualys_container_security (Qualys Container Security / QCS REST API import — "
            "paginated GET /csapi/v1.3/images (image inventory with embedded vulnerabilities) "
            "+ GET /csapi/v1.3/containers (running container inventory with embedded "
            "vulnerabilities), pageNo + pageSize pagination, Qualys QQL filter "
            "registry:<value> and repo:<value> for QCS_REGISTRY + QCS_REPO scoping, "
            "short-lived JWT exchanged at POST /auth (form-encoded "
            "username=<user>&password=<pass>&token=true), shares QUALYS_USER / "
            "QUALYS_PASSWORD with the classic qualys executor; takes QCS_REGISTRY + QCS_REPO "
            "+ QCS_MIN_SEVERITY (info | low | medium | high | critical); needs QUALYS_HOST + "
            "QUALYS_USER + QUALYS_PASSWORD)."
        ),
    },
    "discovery-osint": {
        "agent_name": "discovery-osint-agent",
        "executors": [
            "subfinder",
            "naabu",
            "nmap",
            "shodan2",
            "amass",
            "masscan",
            "dnstwist",
            "theharvester",
            "bagre",
            "bagre_spray",
        ],
        "description": (
            "Passive reconnaissance, active host discovery and brand-protection signals. "
            "Subdomain / DNS enum: subfinder, amass (heavier-duty, more sources), "
            "and theharvester (also pulls emails / employees / breaches). Active port "
            "scanning: naabu (fast SYN/CONNECT), nmap (with NSE scripting) and masscan "
            "(internet-scale, >1M pps). Passive Internet-wide intel: shodan2 (needs "
            "SHODAN_API_KEY). Brand-protection: dnstwist (typo-squat / lookalike domain "
            "detection, with optional MX-record probing to flag phishing-ready domains). "
            "Credential threat-intel: bagre queries Intelligence X (or ClickHouse) for "
            "leaked credentials tied to the target domain; bagre_spray validates them by "
            "spraying ssh/http(s)/ftp/smb/smtp/imap/pop3 against assets already in the "
            "workspace (lockout-guarded — 3 attempts/user, excludes admin/root, supports "
            "BAGRE_PASSWORD_SPRAY_DRY_RUN). Both need INTELX_API_KEY as an agent env var. "
            "Active scanning (naabu, nmap, masscan, bagre_spray) is the reason the agents "
            "live on DigitalOcean — outbound port scanning is prohibited from the AWS network."
        ),
    },
    "web-dast": {
        "agent_name": "web-dast-agent",
        "executors": [
            "ffuf",
            "nuclei",
            "zap",
            "nikto2",
            "wpscan",
            "burp",
            "fortify_webinspect",
            "invicti",
            "rapid7_insightappsec",
            "appspider",
        ],
        "description": (
            "Web fuzzing and dynamic application testing. Runs ffuf (HTTP fuzzer — wordlist "
            "substitution into the FUZZ token), nuclei (ProjectDiscovery's templated vuln "
            "scanner with a huge community ruleset), nikto2 (web server fingerprinting and "
            "known-issue checks), zap (OWASP ZAP DAST), wpscan (WordPress vulnerability "
            "scanner), burp (Burp Suite Pro report import), fortify_webinspect (Fortify "
            "WebInspect Enterprise REST API import — pulls per-scan DAST findings from a WIE "
            "manager), invicti (Invicti / Acunetix 360 / Netsparker REST API import — pulls "
            "per-scan DAST findings from an Invicti cloud or on-prem server), "
            "rapid7_insightappsec (Rapid7 InsightAppSec REST API import — pulls per-scan "
            "DAST findings from the Rapid7 Insight Platform, region-aware via "
            "INSIGHTAPPSEC_REGION) and appspider (Rapid7 AppSpider Enterprise / NTOSpider "
            "REST API import — pulls per-scan DAST findings from an AppSpider Enterprise "
            "manager). The ffuf wordlist must be staged inside the container; burp needs a "
            "Burp Pro license + pre-exported XML to import; fortify_webinspect needs "
            "WEBINSPECT_HOST + WEBINSPECT_TOKEN; invicti needs INVICTI_HOST + "
            "INVICTI_USER_ID + INVICTI_API_TOKEN; rapid7_insightappsec needs "
            "INSIGHTAPPSEC_API_KEY; appspider needs APPSPIDER_HOST + APPSPIDER_TOKEN."
        ),
    },
    "endpoint-edr": {
        "agent_name": "endpoint-edr-agent",
        "executors": [
            "crowdstrike",
            "sentinelone",
            "wazuh",
            "microsoft_defender",
            "ms_intune",
            "carbon_black",
            "cybereason",
            "cylance",
            "trendmicro_deep_security",
            "cortex_xdr",
            "netrise",
        ],
        "description": (
            "Endpoint Detection and Response data import. Pulls findings from CrowdStrike "
            "Falcon (Spotlight JSON export pre-staged inside the container), SentinelOne "
            "(live management API at /web/api/v2.1/threats), Wazuh (live REST API) and "
            "Microsoft Defender for Endpoint (live Graph API). Also runs ms_intune "
            "(Microsoft Intune via Microsoft Graph `/deviceManagement/managedDevices` + "
            "`/deviceManagement/deviceCompliancePolicies` + per-configuration assignments — "
            "managed-device compliance state and configuration-policy posture, Azure AD "
            "client_credentials at `login.microsoftonline.com/{tenant}/oauth2/v2.0/token` "
            "with the `https://graph.microsoft.com/.default` scope; needs AZURE_TENANT_ID + "
            "AZURE_CLIENT_ID + AZURE_CLIENT_SECRET), carbon_black (VMware / Broadcom "
            "Carbon Black Cloud — POST `/api/alerts/v7/orgs/{org_key}/alerts/_search` for "
            "the unified v7 alert envelope plus POST "
            "`/appservices/v6/orgs/{org_key}/devices/_search` for the sensor inventory, with "
            "criteria.minimum_severity floor and time_range.range rolling-window filtering "
            "applied server-side; per-API-Key `X-Auth-Token: <API_SECRET>/<API_ID>` auth via "
            "a Connector API Key created in the CB Cloud console — needs CB_HOST + "
            "CB_API_ID + CB_API_SECRET plus the mandatory CB_ORG_KEY arg) and cybereason "
            "(Cybereason Defense Platform — POST `/rest/crimes/unified` for the canonical "
            "Malop catalogue with a multi-type queryPath + OVERVIEW templateContext, POST "
            "`/rest/sensors/query` for paginated sensor inventory, plus optional per-malop "
            "process evidence via POST `/rest/visualsearch/query/simple` gated by "
            "CR_INCLUDE_PROCESS_EVIDENCE; session-cookie auth rooted at form-encoded POST "
            "`/login.html` which sets a JSESSIONID carried across every /rest/ call; takes "
            "CR_MIN_SEVERITY + CR_MALOP_TYPE CSV; needs CR_HOST + CR_USER + CR_PASSWORD) and "
            "cylance (BlackBerry Cylance / CylancePROTECT — GET `/devices/v2/` paginated "
            "device inventory + GET `/devices/v2/{device_id}/threats` per-device threat walk "
            "+ GET `/threats/v2/` global threat catalogue + GET `/policies/v2/` policy "
            "catalogue, JWT auth at POST `/auth/v2/token` where the dispatcher signs an HS256 "
            "JWT locally with the App Secret carrying the App Id (sub) + Tenant Id (tid) + "
            "random jti + comma-separated scope (sco) and stores the returned bearer token "
            "for the rest of the run; severity from cylance_score (-1.0 .. 1.0) + "
            "classification enum (Malware / Ransomware / PUP / Trusted) with CVSS fallback; "
            "takes mandatory CYLANCE_TENANT_ID + CYLANCE_REGION (na | euc1 | au | sae1 | jp) "
            "plus optional CYLANCE_MIN_SEVERITY; needs CYLANCE_APP_ID + CYLANCE_APP_SECRET "
            "from a Custom Application created in the Cylance console with device:read / "
            "device:list / threat:read / threat:list / policy:read / policy:list scopes). "
            "Configure each "
            "vendor's URL and API credentials as agent env vars (SENTINELONE_URL/_TOKEN, "
            "WAZUH_URL/_USERNAME/_PASSWORD, MS_DEFENDER_TENANT_ID/_CLIENT_ID/_CLIENT_SECRET, "
            "AZURE_TENANT_ID/_CLIENT_ID/_CLIENT_SECRET, CB_HOST/_API_ID/_API_SECRET, "
            "CR_HOST/_USER/_PASSWORD, CYLANCE_APP_ID/_APP_SECRET, DSM_HOST/_API_KEY, "
            "NETRISE_HOST/_TOKEN) before scanning. "
            "trendmicro_deep_security (Trend Micro Deep Security — POST `/api/computers/search` for "
            "the managed-computer inventory with searchCriteria.policyID filter + expand=all, "
            "POST `/api/searches/eventsantimalware` for paginated AM events, and POST "
            "`/api/ipsrules/search` for the IPS rule catalogue used to expand each computer's "
            "intrusionPrevention.ruleIDs into virtual-patching findings — all three surfaces "
            "use Deep Security's canonical id-cursor pagination (searchCriteria.idValue + "
            "idTest=greater-than, maxItems=5000); API key header auth via api-secret-key + "
            "api-version: v1; takes optional DSM_POLICY_ID + DSM_HOSTNAME_FILTER args; needs "
            "DSM_HOST + DSM_API_KEY from an API Key created in the DSM console under "
            "Administration -> User Management -> API Keys with a Full Access role). "
            "cortex_xdr (Palo Alto Cortex XDR — POST `/public_api/v1/incidents/get_incidents/` "
            "for the incidents catalogue with server-side severity + status filters, POST "
            "`/public_api/v1/endpoints/get_endpoints/` for the managed-endpoint inventory, and "
            "POST `/public_api/v1/alerts/get_alerts_multi_events` for the per-alert "
            "multi-event detail — all three surfaces use Cortex XDR's canonical search_from / "
            'search_to integer cursor pagination wrapped in `{"request_data": {...}}` '
            "envelopes; Standard API Key header auth via Authorization + x-xdr-auth-id "
            "(`Standard` security level on the API Key, the recommended posture for read-only "
            "data ingestion — the Advanced HMAC-signed flow is intentionally not used); takes "
            "optional CXDR_MIN_SEVERITY + CXDR_INCIDENT_STATUS args; needs CXDR_HOST + "
            "CXDR_API_KEY_ID + CXDR_API_KEY from an API Key created in the Cortex XDR console "
            "under Settings -> Configurations -> Integrations -> API Keys with at least a "
            "read-only role). "
            "netrise (NetRise XIoT — GET `/api/v1/devices` for the managed firmware / "
            "embedded / IoT device inventory and GET `/api/v1/firmware-vulnerabilities` for "
            "the per-device firmware vulnerability catalogue, both walked with NetRise's "
            "canonical `page` / `limit` cursor pagination and a `meta.total` exhaustion check; "
            "static bearer-token auth via `Authorization: Bearer <NETRISE_TOKEN>` plus "
            "`Accept: application/json`; host.os is set to the firmware vendor / model "
            "(e.g. Cisco / ASR-9000) rather than the OS because NetRise targets firmware "
            "/ embedded / IoT assets where the OS layer is often a stripped-down vendor blob; "
            "takes optional NETRISE_DEVICE_GROUP arg (the device-group label assigned in the "
            "NetRise console — forwarded server-side via the devices.list query param and "
            "re-applied client-side); needs NETRISE_HOST + NETRISE_TOKEN from an API token "
            "created in the NetRise console under Settings -> API Tokens)."
        ),
    },
    "cloud-native-posture": {
        "agent_name": "cloud-native-posture-agent",
        "executors": [
            "amazon_inspector",
            "aws_security_hub",
            "ms_defender_for_cloud",
            "gcp_scc",
            "gcp_asset_inventory",
        ],
        "description": (
            "Vendor-native cloud posture management — pulls security findings directly from "
            "AWS / Azure / GCP first-party services so the data lands in Faraday without "
            "going through a cross-cloud CNAPP. Complements `cloud-security` for orgs that "
            "prefer the vendor's own dashboard but still want central aggregation. Runs "
            "amazon_inspector (AWS Inspector v2 — paginated "
            "`boto3.client('inspector2').list_findings` with filterCriteria.resourceType "
            "(AWS_EC2_INSTANCE | AWS_ECR_CONTAINER_IMAGE | AWS_LAMBDA_FUNCTION) and "
            "filterCriteria.severity (CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL) "
            "filters, AWS SigV4 via the standard boto3 credential chain; needs AWS_REGION + "
            "AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY plus optional AWS_SESSION_TOKEN for "
            "STS-vended session credentials), aws_security_hub (AWS Security Hub — paginated "
            "`boto3.client('securityhub').get_findings` driven by a JSON-encoded "
            "AwsSecurityFindingFilters spec (SECHUB_FILTERS_JSON) and SECHUB_MAX_RESULTS, "
            "same AWS SigV4 credential chain as amazon_inspector; needs AWS_REGION + "
            "AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY plus optional AWS_SESSION_TOKEN), "
            "ms_defender_for_cloud (Microsoft Defender for Cloud — Azure REST API "
            "`/subscriptions/{sub}/providers/Microsoft.Security/alerts?api-version=2022-01-01` "
            "+ `/subscriptions/{sub}/providers/Microsoft.Security/assessments?api-version="
            "2020-01-01` (resource-group-scoped when DEFENDER_RESOURCE_GROUP is set), Azure "
            "AD client_credentials at `login.microsoftonline.com/{tenant}/oauth2/v2.0/token` "
            "with the `https://management.azure.com/.default` scope; needs "
            "AZURE_SUBSCRIPTION_ID + AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET), "
            "gcp_scc (Google Cloud Security Command Center v2 — paginated `list_findings` "
            "via the `google-cloud-securitycenter` SDK against an organization (or per-source "
            "scope via GCP_SOURCE), client-side SCC_MIN_SEVERITY floor + SCC_STATE "
            "(ACTIVE | INACTIVE) filter, Application Default Credentials resolved from a "
            "service-account JSON; needs GCP_ORGANIZATION_ID + GOOGLE_APPLICATION_CREDENTIALS), "
            "and gcp_asset_inventory (GCP Cloud Asset Inventory — paginated `list_assets` "
            "via the `google-cloud-asset` SDK against an organization, optional ASSET_TYPES "
            "CSV filter like `compute.googleapis.com/Instance,storage.googleapis.com/Bucket`; "
            "emits assets as Faraday hosts to pair with gcp_scc findings; needs "
            "GCP_ORGANIZATION_ID + GOOGLE_APPLICATION_CREDENTIALS). ms_intune is intentionally "
            "NOT in this group — Microsoft Intune is endpoint device management (Windows / "
            "macOS / iOS / Android compliance + configuration posture), not cloud posture, "
            "and lives in `endpoint-edr` per its own integration spec."
        ),
    },
    "vulnscan": {
        "agent_name": "vulnscan",
        "executors": [
            "nessus",
            "tenableio",
            "tenablesc",
            "insightvm",
            "qualys",
            "gvm_openvas",
            "tripwire_ip360",
            "vulndb",
            "edgescan",
            "eclypsium",
            "frontline_vm",
            "cyberwatch",
            "besecure",
            "dradis",
            "dynatrace_security",
            "outpost24",
            "oligo",
            "xsoar",
            "pingcastle",
            "qradar_soar",
            "anssi_oradad",
            "anssi_silene",
            "report_processor",
        ],
        "description": (
            "Enterprise vulnerability management and report ingest. Pulls findings from "
            "Nessus, Tenable.io and Tenable.sc (Tenable family), Rapid7 InsightVM, Qualys "
            "VMDR, and OpenVAS/GVM; plus report_processor as a generic SARIF/JSON/XML "
            "import path for scan exports produced outside the agents. OT / ICS sensors "
            "(Cisco Cyber Vision, Claroty CTD / xDome, Forescout eyeInspect, Nozomi "
            "Guardian / Vantage, Ordr) live in the sibling `ot-security` group. Each "
            "vendor needs its API URL + token as agent env vars "
            "(TENABLE_IO_ACCESS_KEY/SECRET_KEY, NESSUS_URL/USERNAME/PASSWORD, "
            "QUALYS_URL/USERNAME/PASSWORD, INSIGHTVM_URL/USERNAME/PASSWORD, "
            "OPENVAS_URL/USERNAME/PASSWORD, etc.) before scanning."
        ),
    },
    "redteam": {
        "agent_name": "redteam",
        "executors": ["crackmapexec", "ldap_audit"],
        "description": (
            "Red-team / post-exploitation tooling. Runs CrackMapExec (CME) for Active "
            "Directory enumeration, SMB / WinRM / MSSQL / SSH authentication checks, "
            "credential validation, share / session listing, and protocol-level attacks "
            "across a target range. CrackMapExec needs reachable target hosts and a set of "
            "credentials passed at scan time (username + password or hash). Also runs "
            "ldap_audit (ldap3-backed LDAP / Active Directory weak-userAccountControl "
            "auditor; walks users / groups / computers under LDAP_BASE_DN with optional "
            "LDAP_FILTER + LDAP_ATTRIBUTES projection and surfaces accounts whose UAC has "
            "ACCOUNTDISABLE clear plus PASSWD_NOTREQD (critical — empty-password binds "
            "permitted) or DONT_EXPIRE_PASSWORD (medium — long-lived credentials) set; "
            "simple bind via LDAP_USER / LDAP_PASSWORD or anonymous, LDAP_USE_TLS promotes "
            "the connection to ldaps://). Use this agent only against environments where "
            "you have explicit testing authorization."
        ),
    },
    "easm": {
        "agent_name": "easm",
        "executors": [
            "assetnote",
            "bishopfox_cosmos",
            "censys",
            "cortex_xpanse",
            "cybelangel",
            "cycognito",
            "detectify",
            "hadrian",
            "hardenize",
            "ionix",
            "rf_asi",
            "riskiq",
            "watchtowr",
        ],
        "description": (
            "External Attack Surface Management — continuous discovery and "
            "assessment of internet-exposed assets across an organisation's "
            "domain footprint. Cross-product so users can pick a primary EASM "
            "platform and still ingest auxiliary discovery from open-source "
            "recon (subfinder, amass, dnstwist already in `discovery-osint`). "
            "Runs censys (Censys Search v2 REST API import — paginated "
            "GET /api/v2/hosts/search (host inventory with embedded services "
            "/ TLS / autonomous-system / OS / location enrichment) and GET "
            "/api/v2/certificates/search (certificate inventory with embedded "
            "Subject Alternative Names + validity + fingerprints), both walked "
            "with Censys' canonical opaque cursor pagination (per_page=100 "
            "capped at CENSYS_PAGES=5 per surface, clamped to [1, 50]); HTTP "
            "Basic auth via the API ID / API Secret pair (Authorization: Basic "
            "<base64(API_ID:API_SECRET)>); takes mandatory CENSYS_QUERY plus "
            "optional CENSYS_VIRTUAL_HOSTS (INCLUDE | EXCLUDE | ONLY, "
            "defaulting to EXCLUDE) + CENSYS_PAGES; needs CENSYS_API_ID + "
            "CENSYS_API_SECRET from a key pair created in the Censys console "
            "under Account -> API, with CENSYS_HOST defaulting to "
            "https://search.censys.io and settable for on-prem / federated "
            "deployments). Runs cortex_xpanse (Palo Alto Cortex Xpanse "
            "Expander REST API import — paginated GET /api/v1/assets "
            "(external-asset inventory; the canonical Xpanse pivot — every "
            "service / issue joins by asset_id), GET /api/v1/services "
            "(external-service inventory with port + protocol + service_type "
            "+ TLS metadata + cloud-provider enrichment) and GET /api/v1/issues "
            "(finding inventory with severity + category + cves + remediation "
            "guidance), all three walked with offset-based pagination "
            "(limit=100 per page, advanced via the envelope's next_offset "
            "cursor or current_offset + page_size when silent, capped at "
            "XPANSE_PAGES=5 per surface clamped to [1, 50]); Standard API Key "
            "auth via the API Key Id + API Key pair created in the Xpanse "
            "console (Authorization: <XPANSE_API_KEY> + x-xdr-auth-id: "
            "<XPANSE_API_KEY_ID>); takes optional XPANSE_BUSINESS_UNIT "
            "(server-side business-unit filter) + XPANSE_MIN_SEVERITY "
            "(server-side severity floor, also re-applied client-side); "
            "needs XPANSE_HOST + XPANSE_API_KEY_ID + XPANSE_API_KEY from a "
            "key pair created in the Xpanse console under Settings -> "
            "Configurations -> API Keys -> New with Security Level set to "
            "Standard). Runs cybelangel (CybelAngel REST API import — "
            "paginated GET /api/2.0/assets (external-asset inventory; the "
            "canonical CybelAngel pivot — every threat joins by asset_id) "
            "and GET /api/2.0/threats (digital-risk threats inventory — "
            "leaked credentials, leaked code, exposed PII, brand abuse, "
            "fraud sites — with severity + category + remediation guidance "
            "and an optional created_after date floor), both walked with "
            "offset-based pagination (limit=100 per page, advanced via the "
            "envelope's next_offset cursor or current_offset + page_size "
            "when silent, capped at CYBELANGEL_PAGES=5 per surface clamped "
            "to [1, 50]); OAuth2 client_credentials — the dispatcher "
            "exchanges CYBELANGEL_CLIENT_ID + CYBELANGEL_CLIENT_SECRET for "
            "a short-lived JWT at https://auth.cybelangel.com/oauth/token "
            "(audience https://platform.cybelangel.com/) then carries "
            "Authorization: Bearer <access_token> on every /api/2.0/ call; "
            "takes optional CYBELANGEL_MIN_SEVERITY (client-side severity "
            "floor) + CYBELANGEL_FROM_DATE (ISO 8601 date floor forwarded "
            "as created_after on the threats surface) + CYBELANGEL_PAGES; "
            "needs CYBELANGEL_CLIENT_ID + CYBELANGEL_CLIENT_SECRET from a "
            "client created in the CybelAngel console under Settings -> "
            "API Keys -> New Client, with CYBELANGEL_HOST defaulting to "
            "https://platform.cybelangel.com and CYBELANGEL_AUTH_HOST / "
            "CYBELANGEL_AUDIENCE settable for on-prem / federated "
            "deployments). Runs cycognito (CyCognito REST API import — "
            "paginated POST /v1/assets (external-asset inventory; the "
            "canonical CyCognito pivot — every issue joins by asset_id) and "
            "POST /v1/issues (finding inventory with severity + category + "
            "cves + remediation guidance), both walked with offset-based "
            "pagination (count=100 per page, advanced via the envelope's "
            "next_offset cursor or current_offset + page_size when silent, "
            "capped at CYCOG_PAGES=5 per surface clamped to [1, 50]); JSON "
            "body carries realm (CYCOG_REALM) + filter (CYCOG_FILTER, the "
            "operator-supplied free-form JSON filter) + count + offset; "
            "single long-lived API token auth via the Authorization: "
            "<CYCOG_TOKEN> header; takes optional CYCOG_FILTER (free-form "
            "JSON filter forwarded verbatim in the body) + CYCOG_MIN_SEVERITY "
            "(client-side severity floor); needs CYCOG_HOST + CYCOG_REALM + "
            "CYCOG_TOKEN from an API token created in the CyCognito console "
            "under Settings -> API). Runs detectify (Detectify v3 REST API "
            "import — paginated GET /rest/v3/teams/{team_token}/domains/ "
            "(domain inventory for the team; the canonical Detectify pivot "
            "— every finding joins by domain_token / domain name) and GET "
            "/rest/v3/teams/{team_token}/findings/ (finding inventory at "
            "team scope, or /rest/v3/teams/{team_token}/domains/"
            "{domain_token}/findings/ when DETECTIFY_DOMAIN_TOKEN narrows "
            "to a single domain), both walked with cursor-based pagination "
            "(limit=100 per page, advanced via the envelope's next_marker "
            "cursor, capped at DETECTIFY_PAGES=5 per surface clamped to "
            "[1, 50]); HMAC-SHA256 signed requests — the canonical request "
            "string <METHOD>;<URL>;<API_KEY>;<TIMESTAMP>;<BODY> is signed "
            "with base64_decode(DETECTIFY_SECRET) and the result base64-"
            "encoded into X-Detectify-Signature alongside X-Detectify-Key "
            "+ X-Detectify-Timestamp headers; takes mandatory "
            "DETECTIFY_TEAM_TOKEN plus optional DETECTIFY_DOMAIN_TOKEN "
            "(narrow to single domain) + DETECTIFY_MIN_SEVERITY (client-"
            "side severity floor) + DETECTIFY_PAGES; needs DETECTIFY_API_"
            "KEY + DETECTIFY_SECRET from a key created in the Detectify "
            "console under Team Settings -> API Keys -> New, with "
            "DETECTIFY_HOST defaulting to https://api.detectify.com). "
            "Runs hadrian (Hadrian REST API import — paginated GET "
            "/api/v1/assets (external-asset inventory; the canonical "
            "Hadrian pivot — every issue joins by asset_id) and GET "
            "/api/v1/issues (finding inventory with severity + "
            "category + cves + remediation guidance), both walked "
            "with offset-based pagination (limit=100 per page, "
            "advanced via the envelope's next_offset cursor or "
            "current_offset + page_size when silent, capped at "
            "HADRIAN_PAGES=5 per surface clamped to [1, 50]); single "
            "long-lived API token auth via the Authorization: Bearer "
            "<HADRIAN_TOKEN> header; takes optional HADRIAN_WORKSPACE "
            "(server-side workspace filter forwarded as the workspace "
            "query param) + HADRIAN_MIN_SEVERITY (client-side severity "
            "floor); needs HADRIAN_HOST + HADRIAN_TOKEN from an API "
            "token created in the Hadrian console under Settings -> "
            "API Tokens -> New). "
            "Runs hardenize (Hardenize / Red Sift REST API import — "
            "single canonical surface GET /api/v0/orgs/{org}/reports/"
            "latest returning the latest TLS / email-security "
            "assessment report for every host registered in the "
            "organisation, with per-check verdicts across the TLS "
            "configuration, certificate validity, email authentication "
            "(SPF / DKIM / DMARC), DNSSEC, MTA-STS and TLS-RPT "
            "surfaces; offset-based pagination (limit=100 per page, "
            "advanced via the envelope's next_offset cursor or "
            "current_offset + page_size when silent, capped at "
            "HARDENIZE_PAGES=5 clamped to [1, 50]); HTTP Basic auth "
            "via the HARDENIZE_USER (API user) + HARDENIZE_API_KEY "
            "(API key) pair created in the Hardenize / Red Sift "
            "console under Settings -> API Keys -> New, carried as "
            "the standard Authorization: Basic <base64(USER:KEY)> "
            "header via requests' auth=(user, key) handling; takes "
            "mandatory HARDENIZE_ORG (organisation slug copied from "
            "the Hardenize console URL) plus optional HARDENIZE_HOST_"
            "FILTER (client-side hostname substring filter) + "
            "HARDENIZE_MIN_SEVERITY (client-side severity floor); "
            "needs HARDENIZE_USER + HARDENIZE_API_KEY, with "
            "HARDENIZE_HOST defaulting to https://www.hardenize.com "
            "and settable for federated deployments). "
            "Runs ionix (Ionix REST API import — paginated GET "
            "/api/v1/assets (external-asset inventory; the canonical "
            "Ionix pivot — every finding joins by asset_id) and GET "
            "/api/v1/findings (finding inventory with severity + "
            "category + cves + remediation guidance; query string "
            "also carries the operator-supplied status floor so Ionix "
            "narrows server-side), both walked with offset-based "
            "pagination (limit=100 per page, advanced via the "
            "envelope's next_offset cursor or current_offset + "
            "page_size when silent, capped at IONIX_PAGES=5 per "
            "surface clamped to [1, 50]); single long-lived API key "
            "auth via the Authorization: Bearer <IONIX_API_KEY> "
            "header; takes optional IONIX_MIN_SEVERITY (client-side "
            "severity floor) + IONIX_STATUS (server-side status "
            "filter on /api/v1/findings, also re-applied client-side "
            "as a defensive belt + braces — open / closed / "
            "risk-accepted plus Ionix-side aliases); needs IONIX_HOST "
            "+ IONIX_API_KEY from a key created in the Ionix console "
            "under Settings -> API Keys -> New). "
            "Runs riskiq (RiskIQ PassiveTotal REST API import — now "
            "Microsoft Defender EASM after the 2021 acquisition; the "
            "v2 PassiveTotal endpoints are still the canonical OEM "
            "surface as of this writing — single-shot GET "
            "/v2/account/sources (the operator's enabled PassiveTotal "
            "data sources — Whois, Passive DNS, Malware, OSINT, SSL "
            "Certificates, Trackers — surfaced as a log line + "
            "per-host description count; failure non-fatal), GET "
            "/v2/account/quotas (the operator's per-source daily / "
            "monthly call quota state — surfaced as a log line + "
            "per-host description summary; failure non-fatal) and "
            "GET /v2/enrichment?query=<RISKIQ_QUERY>&type=<RISKIQ_"
            "TYPE> (the canonical single-record enrichment surface — "
            "returns primaryDomain, classification malicious / "
            "suspicious / non_malicious / unknown, everCompromised "
            "flag, tags with per-tag category, subdomains when "
            "type=domain, TLDs registered against the same name, "
            "ASNs and hostingHistory); PassiveTotal enrichment is "
            "single-record so the executor does not paginate. "
            "Classification bucketing: malicious -> high, suspicious "
            "-> medium, non_malicious / unknown -> info. Tag "
            "bucketing: malware / phishing / fraud / ransomware / "
            "c2 / exploit -> high; suspicious / tor -> medium; "
            "proxy / vpn -> low; everything else surfaced in host "
            "description only. everCompromised=true emits a high-"
            "severity finding with a compromise-window remediation "
            "hint. HTTP Basic auth via the RISKIQ_USER email + "
            "RISKIQ_API_KEY pair (Authorization: Basic <base64(USER:"
            "API_KEY)>); takes mandatory RISKIQ_QUERY plus optional "
            "RISKIQ_TYPE (domain | ip | host, defaulting to domain); "
            "needs RISKIQ_USER + RISKIQ_API_KEY from a key pair "
            "created in the PassiveTotal / Defender EASM console "
            "(Account -> API), with RISKIQ_HOST defaulting to "
            "https://api.passivetotal.org and settable for federated "
            "/ on-prem Defender EASM deployments). "
            "Runs watchtowr (watchTowr REST API import — paginated "
            "GET /api/v1/asset-inventory (external-asset inventory; "
            "the canonical watchTowr pivot — every finding joins by "
            "asset_id) and GET /api/v1/findings (finding inventory "
            "with severity + category + cves + remediation "
            "guidance; query string also carries the operator-"
            "supplied project_id so watchTowr narrows server-side), "
            "both walked with offset-based pagination (limit=100 "
            "per page, advanced via the envelope's next_offset "
            "cursor or current_offset + page_size when silent, "
            "capped at WT_PAGES=5 per surface clamped to [1, 50]); "
            "single long-lived API key auth via the Authorization: "
            "Bearer <WT_API_KEY> header; takes optional "
            "WT_PROJECT_ID (server-side project filter) + "
            "WT_MIN_SEVERITY (client-side severity floor); needs "
            "WT_HOST + WT_API_KEY from a key created in the "
            "watchTowr console under Settings -> API Keys -> New). "
            "Runs assetnote (AssetNote / Searchlight Cyber "
            "Continuous Security REST API import - paginated GET "
            "/api/v1/assets (external-asset inventory; the "
            "canonical AssetNote pivot - every issue joins by "
            "asset_id) and GET /api/v1/issues (issue inventory "
            "with severity + category + cves + remediation "
            "guidance), both walked with offset-based pagination "
            "(limit=100 per page, advanced via the envelope's "
            "next_offset cursor or current_offset + page_size when "
            "silent, capped at AN_PAGES=5 per surface clamped to "
            "[1, 50]); single long-lived API key auth via the "
            "Authorization: Bearer <AN_API_KEY> header; takes "
            "optional AN_MIN_SEVERITY (client-side severity floor); "
            "needs AN_HOST + AN_API_KEY from a key created in the "
            "AssetNote console under Settings -> API Keys -> New). "
            "Runs bishopfox_cosmos (Bishop Fox Cosmos / formerly "
            "CAST - Continuous Attack Surface Testing REST API "
            "import - paginated GET /api/v1/assets (external-asset "
            "inventory; the canonical Cosmos pivot - every finding "
            "joins by asset_id) and GET /api/v1/findings (finding "
            "inventory with severity + category + cves + remediation "
            "guidance; query string also carries the operator-"
            "supplied engagement_id so Cosmos narrows server-side), "
            "both walked with offset-based pagination (limit=100 per "
            "page, advanced via the envelope's next_offset cursor or "
            "current_offset + page_size when silent, capped at "
            "COSMOS_PAGES=5 per surface clamped to [1, 50]); single "
            "long-lived API key auth via the Authorization: Bearer "
            "<COSMOS_API_KEY> header; takes optional "
            "COSMOS_ENGAGEMENT_ID (server-side engagement filter) + "
            "COSMOS_MIN_SEVERITY (client-side severity floor); needs "
            "COSMOS_HOST + COSMOS_API_KEY from a key created in the "
            "Cosmos console under Settings -> API Keys -> New). "
            "Runs rf_asi (Recorded Future Attack Surface Intelligence "
            "REST API import - paginated GET /v2/attack-surface-"
            "intelligence/assets (external-asset inventory; the "
            "canonical ASI pivot - every finding joins by asset_id) "
            "and GET /v2/attack-surface-intelligence/findings (finding "
            "inventory with severity + category + cves + remediation "
            "guidance; query string also carries the operator-supplied "
            "project_id so Recorded Future narrows server-side), both "
            "walked with offset-based pagination (limit=100 per page, "
            "advanced via the envelope's next_offset cursor or "
            "current_offset + page_size when silent, capped at "
            "RF_ASI_PAGES=5 per surface clamped to [1, 50]); single "
            "long-lived API token auth via the X-RFToken: <RF_ASI_TOKEN> "
            "header (Recorded Future's canonical auth shape); takes "
            "optional RF_ASI_PROJECT_ID (server-side project filter) + "
            "RF_ASI_MIN_SEVERITY (client-side severity floor); needs "
            "RF_ASI_TOKEN from a token created in the Recorded Future "
            "console under User Settings -> API Access, with "
            "RF_ASI_HOST defaulting to https://api.recordedfuture.com "
            "and settable for federated / on-prem deployments."
        ),
    },
    "asset-inventory": {
        "agent_name": "asset-inventory",
        "executors": [
            "armis",
            "axonius",
            "device42",
            "fleet_osquery",
            "jamf_pro",
            "jira_insight",
            "leanix_eam",
            "opslevel",
            "runzero",
        ],
        "description": (
            "Asset inventory and CMDB-class connectors — pulls hosts, devices, and "
            "managed endpoints into Faraday so other agents' findings can be "
            "correlated against a live asset list. Read-only ingest; complements the "
            "active-discovery agents in `discovery-osint`. "
            "Runs armis (Armis v1 REST API import — paginated GET /api/v1/devices/ "
            "(device inventory; the canonical Armis pivot — every alert joins by "
            "ip / device) and GET /api/v1/alerts/ (digital-risk + policy violation "
            "alerts inventory), both walked with offset-based pagination "
            "(length=100 per page, advanced via from += length, capped at "
            "ARMIS_PAGES=5 per surface clamped to [1, 50]); two-step auth — the "
            "dispatcher exchanges ARMIS_SECRET_KEY for a short-lived access token "
            "at POST /api/v1/access_token/ then carries it on every subsequent "
            "/api/v1/ request as the standard Authorization: <token> header (NO "
            "`Bearer ` prefix — the raw token IS the header value); takes optional "
            "ARMIS_SITE_ID + ARMIS_BOUNDARY composed into ASQ predicates "
            '(in:devices,siteId:<id>,boundary:"<value>"); needs ARMIS_HOST + '
            "ARMIS_SECRET_KEY from an Access Token created in the Armis console "
            "under Settings -> Users & Roles -> Access Tokens). "
            "Runs axonius (Axonius v4 REST API import — paginated POST "
            "/api/V4.0/assets/devices (cyber-asset inventory; the canonical Axonius "
            "pivot — devices are IP-keyed via specific_data.data.network_interfaces "
            ".ips) and POST /api/V4.0/assets/users (identity inventory — synthetic "
            "hosts via the 0.0.0.0 sentinel since identities aren't IP-keyed), both "
            "walked with the canonical Axonius search envelope "
            '{"data": {"type": "entity_request_schema", "attributes": '
            '{"filter": <AQL>, "fields": {entity: [...]}, "page": '
            '{"limit": 100, "offset": N}, "use_cursor": false}}} and '
            "offset-based pagination (limit=100 per page, offset += 100 per "
            "request, capped at AXONIUS_PAGES=5 per surface clamped to [1, 50]); "
            "API Key + API Secret pair auth carried on every request as the "
            "`api-key` and `api-secret` headers (Axonius v4 explicitly does NOT "
            "use Authorization: Bearer / Basic); takes optional AXONIUS_QUERY "
            "(AQL filter forwarded server-side) + AXONIUS_FIELDS (CSV of "
            "specific_data.data.* field projections); needs AXONIUS_HOST + "
            "AXONIUS_API_KEY + AXONIUS_API_SECRET from a credential pair created "
            "in the Axonius console under Account -> API Key). "
            "Runs device42 (Device42 v1 REST API import — paginated GET "
            "/api/1.0/devices/all/ (CMDB device inventory; the canonical Device42 "
            "pivot — every IP joins by device_id) and GET /api/1.0/ips/ (loose IP "
            "inventory — reservations, DHCP pool entries, VIPs; de-duped against "
            "the device set via device_id), both walked with offset-based "
            "pagination (limit=100 per page, offset += limit per request, capped "
            "at D42_PAGES=5 per surface clamped to [1, 50]); HTTP Basic auth "
            "carried on every /api/1.0/ call as the standard Authorization: Basic "
            "<base64(D42_USER:D42_PASSWORD)> header, built inline so requests "
            "won't strip on cross-host redirects; takes optional D42_BUILDING "
            "(server-side ?building=<value> filter) + D42_LIMIT (per-page record "
            "cap, default 100 clamped to [1, 1000]); needs D42_HOST + D42_USER + "
            "D42_PASSWORD from a Device42 user with read access). "
            "Runs fleet_osquery (Fleet REST API import — paginated GET "
            "/api/v1/fleet/hosts (osquery-managed host inventory; the canonical "
            "Fleet pivot — every host carries primary_ip + osquery_version + "
            "labels enrichment) and GET /api/v1/fleet/queries (operator-defined "
            "saved query inventory — synthetic hosts via the 0.0.0.0 sentinel "
            "since queries aren't IP-keyed), both walked with page-number "
            "pagination (per_page=100 fixed, page += 1 per request, capped at "
            "FLEET_PAGES=5 per surface clamped to [1, 50]); single long-lived "
            "bearer token auth via the standard Authorization: Bearer "
            "<FLEET_TOKEN> header (generated via the Fleet UI under Settings -> "
            "My Account -> Get API token, or via fleetctl login --json for "
            "service accounts); takes optional FLEET_TEAM_ID (server-side "
            "?team_id=<value> filter on both surfaces) + FLEET_LABEL_ID "
            "(server-side ?label_id=<value> filter on the hosts surface only); "
            "needs FLEET_HOST + FLEET_TOKEN). "
            "Runs jamf_pro (Jamf Pro MDM REST API import — three-surface walk "
            "across the Classic API's lightweight GET /JSSResource/computers "
            "(belt-and-suspenders id list, de-duped against the modern walk via "
            "shared id) + the modern Jamf Pro API's GET "
            "/api/v1/computers-inventory?page=N&page-size=100&section=GENERAL"
            "&section=HARDWARE&section=OPERATING_SYSTEM&section=USER_AND_LOCATION "
            "(rich per-section computer inventory with page-number pagination "
            "page += 1 per request, capped at JAMF_PAGES=5 clamped to [1, 50]) + "
            "the Classic API's GET /JSSResource/mobiledevices (mobile-device "
            "inventory; the Classic API IS rich enough for mobile records since "
            "they don't carry the same depth as computer records); OAuth2 "
            "client-credentials at POST /api/oauth/token exchanges JAMF_CLIENT_ID "
            "+ JAMF_CLIENT_SECRET for a short-lived access token carried on "
            "every subsequent /JSSResource/ or /api/v1/ request as the standard "
            "Authorization: Bearer <token> header; takes optional "
            "JAMF_DEVICE_TYPE (computer | mobile | both, default `both`, case-"
            "insensitive with invalid-value fallback to `both`) so operators "
            "can scope the walk; needs JAMF_HOST + JAMF_CLIENT_ID + "
            "JAMF_CLIENT_SECRET from an API role + client registered in the "
            "Jamf Pro console under Settings -> System -> API roles and "
            "clients). "
            "Runs jira_insight (Atlassian Insight / Assets v1 REST API import — "
            "single canonical IQL object walk via GET "
            "/rest/insight/1.0/iql/objects?iql=<IQL>&page=N&resultPerPage=50"
            "(&objectSchemaId=...) returning per-object Insight CMDB records "
            "with full attributes[*].objectAttributeValues[*] projection, "
            "walked with page-number pagination (page += 1 per request 1-"
            "indexed, capped at INSIGHT_PAGES=5 clamped to [1, 50]); HTTP Basic "
            "auth carried on every /rest/insight/1.0/ call as the standard "
            "Authorization: Basic <base64(JIRA_USER:JIRA_API_TOKEN)> header "
            "(Cloud tenants generate the token at "
            "https://id.atlassian.com/manage/api-tokens; on-prem Server / DC "
            "tenants accept the user's actual password or a PAT issued from "
            "the user profile); takes optional INSIGHT_WORKSPACE_ID (server-"
            "side objectSchemaId filter) + INSIGHT_OBJECT_TYPE (composed into "
            'the IQL as `objectType = "<value>"`) + INSIGHT_IQL (operator-'
            "supplied free-form IQL predicate preserved under parentheses so "
            "the type filter is never silently overridden); needs JIRA_HOST + "
            "JIRA_USER + JIRA_API_TOKEN). "
            "Runs leanix_eam (LeanIX EAM / SAP LeanIX Enterprise Architecture "
            "Management REST API import — paginated GET "
            "/services/pathfinder/v1/factSheets returning factSheet records "
            "(Application / BusinessCapability / ITComponent / Project / "
            "DataObject / Interface / TechnicalStack / etc.) under the "
            "canonical Pagination envelope `{type: Pagination, total: N, "
            'data: [...], pageToken: "..."}`, walked with cursor-based '
            "pagination (PAGE_SIZE=100 per page, pageToken cursor, capped "
            "at MAX_PAGES=200 = 20k records per scan); two-step OAuth2 auth "
            "— the dispatcher exchanges LEANIX_API_TOKEN for a short-lived "
            "bearer at POST /services/mtm/v1/oauth2/token using HTTP Basic "
            "with `apitoken` as the username + the API token in the password "
            "slot and grant_type=client_credentials on the form-encoded "
            "body, then carries the returned access_token on every "
            "subsequent /services/pathfinder/ call as the standard "
            "Authorization: Bearer <access_token> header; takes optional "
            "LEANIX_WORKSPACE_ID (server-side ?workspaceId=<value> filter — "
            "defence-in-depth since the token's scope already determines "
            "which workspace it sees) + LEANIX_FACTSHEET_TYPE (server-side "
            "?factSheetType=<value> filter scoped to a single factSheet "
            "family, defaults to fanning out across all types in the "
            "workspace); needs LEANIX_API_TOKEN from a Technical User "
            "credential created in the LeanIX console under Administration "
            "-> Technical Users with LEANIX_HOST defaulting to "
            "https://app.leanix.net for SaaS-only operators and settable "
            "for tenant-specific subdomains (https://<tenant>.leanix.net) "
            "and EU / US-region / on-prem deployments). "
            "Runs opslevel (OpsLevel developer-portal / service-catalog "
            "REST/GraphQL API import — single GraphQL `account.services` "
            "connection at POST <OPSLEVEL_HOST>/graphql returning Service "
            "records (the canonical OpsLevel surface) with full nested "
            "type / tier / lifecycle / owner / tags / aliases / "
            "managedAliases / htmlUrl projection, walked with Relay-style "
            "first + after cursors under the canonical `{nodes, pageInfo: "
            "{hasNextPage, endCursor}, totalCount}` envelope (PAGE_SIZE="
            "100 per page, after cursor, capped at MAX_PAGES=200 = 20k "
            "records per scan); single long-lived bearer token auth via "
            "the standard Authorization: Bearer <OPSLEVEL_TOKEN> header "
            "(generated via the OpsLevel console under Account Settings "
            "-> API Tokens); takes optional OPSLEVEL_TIER (tier_1 / "
            "tier_2 / tier_3 / tier_4 — the executor normalises common "
            "synonyms like 1 / tier1 / t1 -> tier_1 before composing "
            "the tierAlias list-arg) + OPSLEVEL_LIFECYCLE (operator-"
            "configured lifecycle alias forwarded as the lifecycleAlias "
            "list-arg, defaults to fanning out across all lifecycles); "
            "needs OPSLEVEL_TOKEN with OPSLEVEL_HOST defaulting to "
            "https://app.opslevel.com for SaaS-only operators and "
            "settable for EU-region / on-prem deployments. "
            "Runs runzero (runZero v1.0 REST API import — paginated GET "
            "/api/v1.0/org/assets (asset inventory; the canonical runZero "
            "pivot — every service joins by asset_id) and GET "
            "/api/v1.0/org/services (per-port service inventory — services ARE "
            "IP-keyed in runZero unlike Fleet's saved queries), both walked "
            "with offset-based pagination (limit=1000 default clamped to "
            "[1, 5000], offset += limit per request, capped at RUNZERO_PAGES=5 "
            "per surface clamped to [1, 50]); Organization-scoped API key auth "
            "via the standard Authorization: Bearer <RUNZERO_TOKEN> header "
            "(Account-scoped keys are explicitly rejected at the API tier so "
            "the executor MUST be wired with an Organization key); takes "
            "optional RUNZERO_SEARCH (server-side ?search=<value> filter "
            "using the runZero search query language, e.g. `type:server "
            "os:linux site:HQ alive:true tag:pci last_seen:<1d`) + "
            "RUNZERO_LIMIT (per-page record cap); needs RUNZERO_TOKEN with "
            "RUNZERO_HOST defaulting to https://console.runzero.com for "
            "SaaS-only operators and settable for on-prem / self-hosted "
            "appliances. Severity across all nine connectors is always "
            "`info` since these are inventory entries not vulnerability "
            "findings — operators correlate against the other agents' "
            "findings via per-vendor refs (Armis-Id / Axonius-Id / Device42-"
            "Id / Fleet-Id / Jamf-Id / Insight-Id / LeanIX-Id / OpsLevel-Id "
            "/ RunZero-Id)."
        ),
    },
    "threat-intel": {
        "agent_name": "threat-intel",
        "executors": [
            "cert_ist",
            "cisa_kev",
            "crowdstrike_intel",
            "digital_shadows",
            "first_epss",
            "groupib",
            "intsights_threat_command",
            "iriusrisk",
            "mandiant",
            "msrc",
            "nist_nvd",
            "patrowl",
            "recorded_future",
            "secureworks_taegis",
            "sekoia_defend",
            "threatconnect",
            "trustar",
        ],
        "description": (
            "Threat Intelligence feeds and enrichment platforms — pulls "
            "known-exploited CVE lists, EPSS scores, MSRC advisories, vendor TI "
            "products, and commercial enrichment APIs into Faraday. Many of these "
            "aren't host-scanners; they emit one vuln record per CVE/IOC tagged "
            "with the source feed. All seventeen executors emit one Faraday vuln "
            "per CVE / IOC / advisory under a single synthetic 0.0.0.0 host so "
            "operators can pivot from the other agents' host-side findings into "
            "the threat-intel record via shared CVE / refs. "
            "Runs cert_ist (CERT-IST advisory feed import — paginated GET "
            "/public/avis/rss/feed.xml?fromDate=YYYY-MM-DD with stdlib "
            "xml.etree.ElementTree dispatching on RSS 2.0 and Atom 1.0 envelopes; "
            "Bearer-token auth via CERTIST_API_KEY (subscription-gated — the "
            "executor exits cleanly when missing); one Faraday vuln per affected "
            "product extracted from the labelled `Produits affectés:` / "
            "`Affected products:` block; severity mapped from the analyst-"
            "published French + English `Critique` / `Majeure` / `Modérée` / "
            "`Mineure` vocabulary into Faraday's ladder via accent-stripped "
            "lookup; analyst-authored `Remediation:` / `Solution:` text wins as "
            "resolution; tagged `[cert-ist]`; takes optional CERTIST_FROM_DATE "
            "for trailing-window delta imports; needs CERTIST_HOST defaulting to "
            "https://www.cert-ist.com plus CERTIST_API_KEY). "
            "Runs cisa_kev (CISA Known Exploited Vulnerabilities catalog import "
            "against the fully-public GET "
            "/sites/default/files/feeds/known_exploited_vulnerabilities.json "
            "endpoint — no auth, no pagination, the entire catalog ships in one "
            "document; one Faraday vuln per CVE tagged `[cisa-kev]` with "
            "`dateAdded` + `dueDate` surfaced; severity bucketed by BOD 22-01 "
            "`dueDate` proximity (overdue -> critical / due-within-14-days -> "
            "high / due-within-60-days -> medium / further -> low / missing -> "
            "high) and bumped to critical on `knownRansomwareCampaignUse: "
            "Known`; takes optional KEV_MIN_DATE for delta imports; needs no "
            "env vars and defaults CISA_KEV_HOST to https://www.cisa.gov). "
            "Runs crowdstrike_intel (CrowdStrike Falcon Intel REST API import — "
            "paginated GET /intel/combined/indicators/v1?filter=type:'<type>'"
            "&offset=N&limit=N&sort=last_updated.desc returning the canonical "
            "Falcon envelope `{meta: {pagination: {offset, limit, total}}, "
            "resources: [...], errors: []}`; reuses standard Falcon OAuth2 "
            "client-credentials at POST /oauth2/token sharing FALCON_CLIENT_ID "
            "/ FALCON_CLIENT_SECRET / FALCON_HOST with the sibling "
            "`crowdstrike` EDR executor — one set of Falcon credentials covers "
            "both surfaces; severity bucketed from `malicious_confidence` "
            "(`high` / `medium` / `low` / `unverified`) and bumped one tier on "
            "named threat actors and one more on `actionOnObjectives` kill-"
            "chain entries (caps at critical); tagged `[crowdstrike-intel]`; "
            "takes mandatory INTEL_INDICATOR_TYPE "
            "(hash_md5|hash_sha256|ip_address|domain|url) + optional "
            "INTEL_MAX_RESULTS clamped to [1, 10000]; needs the same "
            "FALCON_CLIENT_ID + FALCON_CLIENT_SECRET + FALCON_HOST env vars "
            "as the EDR `crowdstrike` executor). "
            "Runs digital_shadows (Reliaquest Digital Shadows SearchLight REST "
            "import — paginated POST /incidents/find then POST "
            "/intel-incidents/find with the canonical filter body "
            "`{limit, offset, filter: {severity: [...]}}` and Spring-style "
            "`{content, total, offset, limit}` response envelope; HMAC-SHA256 "
            "signed requests — `Authorization: hmac <DS_KEY>:<base64-sig>` + "
            "`searchlight-timestamp: <epoch_ms>` with the legacy `X-DS-"
            "Timestamp` / `X-DS-Signature` pair emitted in parallel for on-prem "
            "mirrors; DS_HOST is mandatory (no default — SearchLight runs in "
            "multiple regions); severity bucketed from SearchLight's Very-Low "
            "/ Low / Medium / High / Very-High ladder onto Faraday's info / "
            "low / medium / high / critical; terminal Closed / Resolved states "
            "floored to info; tagged `[digital-shadows]`; takes optional "
            "DS_MIN_SEVERITY + DS_LIMIT; needs DS_HOST + DS_KEY + DS_SECRET). "
            "Runs first_epss (FIRST EPSS REST import — paginated GET "
            "/data/v1/epss?cve=<csv>&offset=0&limit=100 against the fully-"
            "public api.first.org host; one Faraday vuln per CVE with the "
            "exact 5-decimal EPSS score surfaced in the title; severity "
            "bucketed by probability (`>=0.9 critical / >=0.5 high / >=0.1 "
            "medium / >=0.01 low / <0.01 info`); unscored CVEs fall to info; "
            "tagged `[first-epss]`; takes mandatory EPSS_CVES (CSV) + optional "
            "EPSS_MIN_PROBABILITY client-side filter; needs no env vars (the "
            "API is fully public and unauthenticated). "
            "Runs groupib (Group-IB Threat Intelligence REST import — "
            "paginated GET /api/v2/compromised/account (compromised-credential "
            "feed) and GET /api/v2/attacks/phishing (phishing-campaign feed) "
            "via `seqUpdate` cursor advancement; HTTP Basic auth via base64-"
            "encoded `{GROUPIB_USER}:{GROUPIB_API_KEY}`; severity for "
            "compromised-account defaults high, bumps to critical on "
            "plaintext+client, floors to info on terminal states; severity "
            "for phishing maps Group-IB's Low/Medium/High label, bumps to "
            "critical on Active+target-brand, floors to info on Blocked / "
            "TakenDown; tagged `[groupib]`; takes mandatory GROUPIB_FEED_TYPE "
            "(compromised_account | phishing with aliases) + optional "
            "GROUPIB_LIMIT [1, 500]; needs GROUPIB_USER + GROUPIB_API_KEY "
            "with GROUPIB_HOST defaulting to https://tap.group-ib.com). "
            "Runs intsights_threat_command (Rapid7 Threat Command — formerly "
            "IntSights — REST import against the canonical Threat Command "
            "public-v1 surface; HTTP Basic auth via base64-encoded "
            "`{TC_ACCOUNT_ID}:{TC_API_KEY}`; pages GET "
            "/public/v1/data/alerts/alerts-list?type=<...>&severity=<...>"
            "&skip=N&limit=50 for `AttackIndication` / `DataLeakage` / "
            "`Phishing` / `BrandSecurity` / `ExploitableData` / `VIP` / "
            "`ReputationLeakage` types (plus the `all` sentinel) and GET "
            "/public/v1/iocs/threat-indicators?severity=<...>&skip=N&limit=100 "
            "for the `iocs` sentinel — TC_MIN_SEVERITY is forwarded server-"
            "side as a repeated `severity=` parameter; severity maps Threat "
            "Command's High / Medium / Low onto Faraday's high / medium / low; "
            "Closed / Acknowledged / Dismissed floored to info; tagged "
            "`[intsights-threat-command]`; we use INTSIGHTS_HOST not TC_HOST "
            "to avoid colliding with the sibling `threatconnect` executor "
            "(default https://api.ti.insight.rapid7.com); takes mandatory "
            "TC_ALERT_TYPE + optional TC_MIN_SEVERITY (Low | Medium | High); "
            "needs TC_ACCOUNT_ID + TC_API_KEY). "
            "Runs iriusrisk (IriusRisk threat-model import — paginated GET "
            "/api/v1/products?page=N&size=100 via Spring HATEOAS "
            "(`_embedded.products` envelope) then GET "
            "/api/v1/products/{ref}/threats per product; per-user API token "
            "carried as the lowercase `api-token: <IRIUS_TOKEN>` header on "
            "every request; one Faraday vuln per IriusRisk threat under the "
            "`product-ref::threat-ref` composite external_id; severity from "
            "`riskLevel` (Very High / High / Medium / Low / Very Low / "
            "Nothing) with numeric `riskRating` (0..100) fallback; terminal "
            "Mitigated / NotApplicable / Rejected floored to info; tagged "
            "`[iriusrisk]`; takes optional IRIUS_PRODUCT_REF for per-product "
            "scheduled imports (blank walks every product); needs IRIUS_HOST "
            "(mandatory — tenant-keyed, no default) + IRIUS_TOKEN). "
            "Runs mandiant (Mandiant Advantage REST import — OAuth2 "
            "client-credentials at POST /token (HTTP Basic + `grant_type="
            "client_credentials`) yielding a short-lived Bearer; two "
            "operational modes freely combined: per-CVE lookups via GET "
            "/v4/vulnerability/{cve_id} and per-IOC lookups via GET "
            "/v4/indicator/{type}/{value} for md5 / sha1 / sha256 / ipv4 "
            "(alias ip) / ipv6 / fqdn (alias domain) / url; severity for "
            "vulns from analyst `risk_rating` (CRITICAL / HIGH / MEDIUM / "
            "LOW / NONE) with CVSS fallback and a Wild / "
            "was_seen_in_the_wild override -> critical; severity for "
            "indicators from `mscore` (>=80 critical / >=50 high / >=25 "
            "medium / >=10 low / <10 info); tagged `[mandiant]` with "
            "`[MANDIANT]` / `[MANDIANT IOC]` name prefixes so operators can "
            "filter the two streams independently in the Faraday UI; takes "
            "optional MANDIANT_VULN_CVES + MANDIANT_INDICATOR_LIST; needs "
            "MANDIANT_KEY_ID + MANDIANT_KEY_SECRET with MANDIANT_HOST "
            "defaulting to https://api.intelligence.mandiant.com). "
            "Runs msrc (Microsoft Security Response Center CVRF feed import — "
            "single GET /cvrf/v3.0/cvrf/{YYYY-MMM} per Patch Tuesday release; "
            "MSRC_API_KEY optional and sent as the `api-key` header when "
            "present (free signup at https://msrc.microsoft.com/developer "
            "raises the rate-limit ceiling); MSRC_YEAR_MONTH accepts both "
            "`YYYY-MMM` (2026-May) and numeric `YYYY-MM` forms normalised "
            "into Microsoft's title-case month name; severity from the "
            "highest `BaseScore` across multiple `CVSSScoreSets` with the "
            "explicit `BaseSeverity` text mapped via "
            "`Critical -> critical / Important -> high / Moderate -> medium "
            "/ Low -> low` and a `Threats.Exploited` / `Exploit Code Maturity"
            ": Functional` override -> critical; tagged `[msrc]`; takes "
            "mandatory MSRC_YEAR_MONTH + optional MSRC_PRODUCT substring "
            "filter; needs MSRC_API_KEY env var with MSRC_HOST defaulting "
            "to https://api.msrc.microsoft.com). "
            "Runs nist_nvd (NIST NVD 2.0 REST import — single canonical "
            "endpoint GET /rest/json/cves/2.0 with two mutually-exclusive "
            "modes: per-CVE lookups via ?cveId=CVE-YYYY-NNNN (one HTTP GET "
            "per id) and paged trailing-window via "
            "?lastModStartDate=...&lastModEndDate=...&startIndex=N&"
            "resultsPerPage=2000 (NVD's documented 1..120 day ceiling); "
            "NVD_API_KEY is optional and sent as the `apiKey` header to "
            "raise the rate-limit ceiling from 5/30s to 50/30s; severity "
            "from CVSSv3.1 preferred over v3.0 over v2 with `baseSeverity` "
            "text wins-over-numeric and a `Rejected` -> info override; "
            "tagged `[nist-nvd]`; takes optional NVD_CVE_LIST (CSV) OR "
            "NVD_LAST_MOD_DAYS (integer, default 7); needs the optional "
            "NVD_API_KEY with NVD_HOST defaulting to "
            "https://services.nvd.nist.gov). "
            "Runs patrowl (Patrowl REST import — DRF TokenAuthentication "
            "via POST /api/auth/login exchanging "
            "{username: PATROWL_USER, password: PATROWL_PASSWORD} for a "
            "40-char hex token carried as `Authorization: Token <...>` on "
            "every subsequent request — the password never leaves the "
            "dispatcher's process memory after the token is returned; pages "
            "GET /findings/api/v1/findings/?page=N&page_size=N with "
            "PATROWL_MIN_SEVERITY forwarded server-side as repeated "
            "`severity=` parameters; severity passes through verbatim "
            "(Patrowl uses Faraday's exact info / low / medium / high / "
            "critical vocabulary); terminal patched / closed / "
            "false-positive / mitigated / resolved states floored to info; "
            "tagged `[patrowl]`; takes optional PATROWL_MIN_SEVERITY; needs "
            "PATROWL_HOST (mandatory — tenant-keyed, no default) + "
            "PATROWL_USER + PATROWL_PASSWORD). "
            "Runs recorded_future (Recorded Future REST import — Bearer "
            "auth as `X-RFToken: <RF_TOKEN>` (the v2 API rejects "
            "unauthenticated requests with HTTP 401); two operational "
            "modes: per-CVE lookups via GET /v2/vulnerability/{cveId} (one "
            "HTTP GET per CVE in RF_CVE_LIST) and paged search via GET "
            "/v2/vulnerability/search?from=N&limit=100&riskScore_gte=N"
            "&fields=... — RF_MIN_RISK_SCORE forwarded server-side via "
            "`riskScore_gte`; severity from RF's `criticalityLabel` text "
            "(Very Malicious / Malicious / Suspicious / Unusual / No "
            "current evidence) with numeric `score` 0..99 fallback "
            "(>=90 critical / >=65 high / >=25 medium / >=5 low / <5 info); "
            "tagged `[recorded-future]`; takes optional RF_CVE_LIST + "
            "RF_MIN_RISK_SCORE; needs RF_TOKEN with RF_HOST defaulting to "
            "https://api.recordedfuture.com). "
            "Runs secureworks_taegis (Secureworks Taegis XDR GraphQL "
            "import — OAuth2 client-credentials at POST "
            "/auth/api/v2/auth/token (HTTP Basic + `grant_type="
            "client_credentials`) for a short-lived Bearer; two GraphQL "
            "POSTs against POST /graphql in sequence: the `investigations` "
            "query for tenant investigations and the `alertsServiceSearch` "
            "query for XDR alerts; TAEGIS_TENANT_ID is forwarded both as a "
            "GraphQL variable and as the `x-tenant-context` HTTP header on "
            "every request; severity for alerts from `metadata.severity` "
            "as a 0..1 float (>=0.8 critical / >=0.6 high / >=0.4 medium / "
            ">=0.2 low / <0.2 info) plus label-vocab fallback; severity for "
            "investigations from `priority` label (Critical / High / Medium "
            "/ Low / Informational) with 1..5 numeric fallback; Closed / "
            "Resolved / Suspended / False Positive states floored to info; "
            "tagged `[secureworks-taegis]` with `[Taegis Alert]` / `[Taegis "
            "Investigation]` name prefixes; takes mandatory TAEGIS_TENANT_ID "
            "+ optional TAEGIS_MIN_SEVERITY; needs TAEGIS_CLIENT_ID + "
            "TAEGIS_CLIENT_SECRET with TAEGIS_HOST defaulting to "
            "https://api.ctpx.secureworks.com). "
            "Runs sekoia_defend (Sekoia.io SOC + CTI REST import — Bearer "
            "auth via `Authorization: Bearer <SEKOIA_TOKEN>`; walks two "
            "canonical endpoints in sequence: GET /v1/sic/alerts?limit=N"
            "&offset=N[&filter=<expr>] (paginated SIC alert inventory) then "
            "GET /v1/iocs/observables?limit=N&offset=N[&filter=<expr>] "
            "(paginated CTI observable inventory); both share the canonical "
            "`{items, total}` envelope; severity for alerts from `urgency` "
            "0..100 score (>=80 critical / >=60 high / >=40 medium / >=20 "
            "low / <20 info) and severity for observables from `confidence` "
            "via the same ladder; Closed / Rejected / Mitigated states "
            "floored to info; tagged `[sekoia-defend]` with `[Sekoia][Alert]` "
            "/ `[Sekoia][IOC]` name prefixes; takes optional SEKOIA_FILTER "
            "(forwarded server-side as `filter=` per Sekoia.io's filter "
            "DSL) + SEKOIA_LIMIT [1, 100]; needs SEKOIA_HOST defaulting to "
            "https://api.sekoia.io + SEKOIA_TOKEN). "
            "Runs threatconnect (ThreatConnect REST import — HMAC-SHA256 "
            "signed requests with canonical signing string "
            "`<URI_PATH>:<HTTP_METHOD>:<UNIX_TIMESTAMP>`, base64-encoded "
            "signature sent as `Authorization: TC <access_id>:<sig>` + "
            "`Timestamp: <unix>` headers; paginated GET "
            "/api/v3/indicators?tql=<TQL>&fields=<...>&resultStart=N"
            "&resultLimit=N&sorting=lastModified+desc with TQL filter "
            '`ownerName EQ "TC_OWNER" AND typeName EQ "TC_INDICATOR_TYPE"`; '
            "severity from `threatAssessScore` 0..1000 ladder (>=800 "
            "critical / >=500 high / >=200 medium / >=50 low / <50 info) "
            "with 1..5 `rating` fallback; inactive indicators floored to "
            "info; tagged `[threatconnect]`; takes mandatory TC_OWNER + "
            "TC_INDICATOR_TYPE (Address | EmailAddress | File | Host | URL "
            "with operator-friendly aliases); needs TC_HOST + TC_ACCESS_ID "
            "+ TC_SECRET_KEY). "
            "Runs trustar (Splunk Intelligence Management — formerly "
            "TruSTAR — REST import; OAuth2 client-credentials at POST "
            "/oauth/token (HTTP Basic + `grant_type=client_credentials`) "
            "for a short-lived Bearer; two endpoints: GET /api/1.3/enclaves "
            "for the enclave-discovery step (used when TRUSTAR_ENCLAVE_IDS "
            "is blank) and POST /api/1.3/indicators/search?pageNumber=N"
            "&pageSize=N for the per-page indicator pull; canonical filter "
            "body `{enclaveIds: [...], priorityScores: [...]}` and Spring-"
            "style `{items, pageNumber, pageSize, totalElements, hasNext}` "
            "envelope; severity bucketed from HIGH / MEDIUM / LOW priority "
            "with a HIGH+correlationCount>=10 bump to critical; tagged "
            "`[trustar]`; takes optional TRUSTAR_ENCLAVE_IDS (CSV) + "
            "TRUSTAR_PRIORITY (LOW | MEDIUM | HIGH); needs TRUSTAR_API_KEY "
            "+ TRUSTAR_API_SECRET with TRUSTAR_HOST defaulting to "
            "https://api.trustar.co). "
            "Severity ladders vary by source — see each per-executor "
            "description above — but every record carries the canonical "
            "feed-source tag (`[cisa-kev]` / `[nist-nvd]` / `[first-epss]` "
            "/ `[msrc]` / `[recorded-future]` / `[mandiant]` / "
            "`[crowdstrike-intel]` / `[threatconnect]` / "
            "`[intsights-threat-command]` / `[digital-shadows]` / "
            "`[iriusrisk]` / `[secureworks-taegis]` / `[groupib]` / "
            "`[trustar]` / `[patrowl]` / `[sekoia-defend]` / `[cert-ist]`) "
            "plus a vendor-specific `Foo-CveID` / `Foo-Probability` / "
            "`Foo-RiskScore` / etc. ref pivot so operators can pivot from a "
            "Faraday finding back to the exact source record."
        ),
    },
    "ot-security": {
        "agent_name": "ot-security",
        "executors": [
            "cisco_cybervision",
            "claroty",
            "claroty_xdome",
            "forescout_eyeinspect",
            "nozomi_guardian",
            "nozomi_vantage",
            "ordr",
        ],
        "description": (
            "Operational Technology (OT) and Industrial Control System (ICS) "
            "security platforms — pulls device inventories and detection alerts "
            "from ICS-aware sensors. Read-only, passive in scope. Existing "
            "`cisco_cybervision` is part of this group; the rest are new. "
            "All seven connectors emit one Faraday host per OT / ICS endpoint "
            "the upstream sensor has fingerprinted, plus one Faraday vuln per "
            "endpoint with the `[ASSET-INVENTORY]` engine prefix so OT "
            "inventory entries land alongside the other CMDB-class feeds in "
            "`asset-inventory`; security alerts emit a second vuln keyed on the "
            "related-asset IP under the appropriate per-vendor name prefix "
            "(`[Claroty Alert]` / `[xDome Alert]` / `[eyeInspect Alert]` / "
            "`[Nozomi Alert]` / `[Vantage Alert]` / `[Ordr Alert]`). "
            "Runs cisco_cybervision (Cisco Cyber Vision OT / ICS preset-based "
            "import — paginated GET /api/3.0/presets walks the configured "
            "preset roster then per-preset GET /api/3.0/presets/{id}/components "
            "and GET /api/3.0/presets/{id}/vulnerabilities pulls the asset "
            "inventory and the matched vulnerability set; long-lived API token "
            "carried as the documented `x-token-id: <CYBERVISION_TOKEN>` "
            "header on every /api/3.0/ request; MY_PRESETS / "
            "PRESETS_CONTAINING / REFRESH_PRESETS / SPECIFIC_PRESETS scope the "
            "preset roster the executor walks per run; needs CYBERVISION_TOKEN "
            "+ CYBERVISION_HTTPS_URL). "
            "Runs claroty (Claroty Continuous Threat Detection REST API "
            "import — paginated GET /api/v1/assets?site_id=<id>&page=N"
            "&page_size=M (OT asset inventory; canonical envelope "
            "`{objects, count, next, previous}` with each record carrying "
            "id, name, ip, mac, vendor, model, firmware, os, asset_type, "
            "criticality, site_id / site_name, first_seen / last_seen, "
            "risk_score, optional cve_list / vulnerabilities) and GET "
            "/api/v1/alerts?site_id=<id>&page=N&page_size=M (security alert "
            "feed; same envelope shape with each record carrying id, name / "
            "title, description, severity, category, status, created_at / "
            "updated_at, site_id / site_name, related_assets); session-token "
            "auth — the dispatcher POSTs {username: CLAROTY_USER, password: "
            "CLAROTY_PASSWORD} to /api/v1/auth/login and receives a token "
            "(canonical `{token}`, federated mirrors expose `{access_token}` "
            "/ `{key}` — all three tolerated) carried as Authorization: "
            "Bearer <token> on every /api/v1/ request; CLAROTY_HOST has no "
            "default (on-prem); pagination one-based via page=N + page_size=M "
            "capped at CLAROTY_PAGES=10 clamped to [1, 100]; takes optional "
            "CLAROTY_SITE_ID (server-side site_id= filter) + "
            "CLAROTY_MIN_SEVERITY (client-side severity floor); terminal "
            "Resolved / Muted / Suppressed / Dismissed / false-positive "
            "states floored to info via the Claroty-Status pivot; tagged "
            "`[claroty]` with the `ot-security` group tag; needs CLAROTY_HOST "
            "+ CLAROTY_USER + CLAROTY_PASSWORD). "
            "Runs claroty_xdome (Claroty xDome OT / IoT / IoMT REST API "
            "import — paginated GET /api/v2/devices?device_type=<type>"
            "&page=N&page_size=M (connected-device inventory; canonical "
            "envelope `{results, count, next, previous}` with each record "
            "carrying id, name, ip, mac, manufacturer, model, firmware, os, "
            "device_type, category, criticality, location / site_name, "
            "first_seen / last_seen, risk_score, optional cve_list / "
            "vulnerabilities) and GET /api/v2/alerts?device_type=<type>"
            "&page=N&page_size=M (security alert feed; same envelope shape "
            "with each record carrying id, title / name, description, "
            "severity, category, status, created_at / updated_at, "
            "device_type, related_devices, risk_score); long-lived API "
            "token flow — XDOME_API_TOKEN provisioned in the xDome console "
            "and carried verbatim as Authorization: Bearer <token> on every "
            "/api/v2/ request (no login exchange); XDOME_HOST has no "
            "default (multi-tenant SaaS); pagination one-based capped at "
            "XDOME_PAGES=10 clamped to [1, 100]; takes optional "
            "XDOME_DEVICE_TYPE (server-side device_type= filter — accepts "
            "medical / iot / ot / it labels or numeric ids) + "
            "XDOME_MIN_SEVERITY (client-side severity floor); terminal "
            "states floored to info via the Xdome-Status pivot; tagged "
            "`[claroty_xdome]` with the `ot-security` group tag; needs "
            "XDOME_HOST + XDOME_API_TOKEN). "
            "Runs forescout_eyeinspect (Forescout eyeInspect — formerly "
            "SilentDefense — REST API import — paginated GET "
            "/api/devices?site_id=<id>&page=N&page_size=M (OT device "
            "inventory; canonical envelope `{results, count, next, "
            "previous}` with each record carrying id, name, ip, mac, "
            "vendor, model, firmware, os, device_type, criticality, "
            "site_id / site_name, first_seen / last_seen, risk_score, "
            "optional cve_list / vulnerabilities) and GET /api/alerts"
            "?site_id=<id>&page=N&page_size=M (security alert feed; same "
            "envelope shape with each record carrying id, name / title, "
            "description, severity, category, status, created_at / "
            "updated_at, site_id / site_name, related_devices); session-"
            "token auth — the dispatcher POSTs {username: EI_USER, "
            "password: EI_PASSWORD} to /api/auth/login and receives a "
            "token (canonical `{token}`, federated mirrors expose "
            "`{access_token}` / `{key}` — all three tolerated) carried as "
            "Authorization: Bearer <token> on every /api/ request; "
            "EI_HOST has no default (on-prem); pagination one-based "
            "capped at EI_PAGES=10 clamped to [1, 100]; takes optional "
            "EI_SITE_ID (server-side site_id= filter) + EI_MIN_SEVERITY "
            "(client-side severity floor); terminal states floored to info "
            "via the EyeInspect-Status pivot; tagged "
            "`[forescout_eyeinspect]` with the `ot-security` group tag; "
            "needs EI_HOST + EI_USER + EI_PASSWORD). "
            "Runs nozomi_guardian (Nozomi Networks Guardian / CMC Open "
            "Query REST API import — single canonical endpoint GET "
            "/api/open/query/do?query=<surface> | head N | skip M with "
            "three distinct query keywords: `assets` (OT asset inventory; "
            "canonical envelope `{result, total}` — singular `result` per "
            "Nozomi's documented Open Query shape — with each record "
            "carrying id, name, ip, mac_address, vendor, product_name, "
            "firmware_version, os, type (PLC / RTU / HMI / Historian / "
            "Engineering Workstation / IT), level (numeric 0..4 Purdue "
            "level), criticality, zone_id / zone_name, site_id / "
            "site_name, first_activity_time / last_activity_time, risk "
            "(0..10), optional cve_list / vulnerabilities), `alerts` "
            "(same envelope shape with each record carrying id, name / "
            "type_name, description, severity, type_id (Nozomi's "
            "SIGN:/VI:/anomaly taxonomy), status, record_created_at / "
            "record_updated_at, src_ip / dst_ip, risk, zone_id / "
            "zone_name), and `vulnerabilities` (same envelope shape with "
            "each record carrying id, cve_id, name, description, severity "
            "/ cvss_score, node_id (asset id), node_label, node_ip, "
            "zone_id / zone_name); HTTP Basic Auth — Authorization: "
            "Basic <base64(NOZOMI_USER:NOZOMI_PASSWORD)> on every "
            "/api/open/ request with no separate login round-trip (the "
            "appliance also exposes an /api/open/sign_in session-cookie "
            "flow but the dispatcher unconditionally uses Basic Auth so a "
            "stale session cookie can't silently authorise a request); "
            "NOZOMI_HOST has no default (on-prem); pagination one-based "
            "via the Nozomi-specific `| head N | skip M` DSL operators "
            "capped at NOZOMI_PAGES=10 clamped to [1, 100]; takes "
            "optional NOZOMI_QUERY_SCOPE (assets | alerts | vulns / "
            "vulnerabilities | all — blank / missing / unknown walks all "
            "three in the canonical order assets -> alerts -> "
            "vulnerabilities) + NOZOMI_MIN_SEVERITY (client-side "
            "severity floor); terminal Resolved / Muted / Closed / "
            "Suppressed / Dismissed / Acknowledged / Mitigated / "
            "Accepted-Risk states floored to info via the Nozomi-Status "
            "pivot; tagged `[nozomi_guardian]` with the `ot-security` "
            "group tag; needs NOZOMI_HOST + NOZOMI_USER + "
            "NOZOMI_PASSWORD). "
            "Runs nozomi_vantage (Nozomi Networks Vantage SaaS REST API "
            "import — paginated GET /v1/sites?site_id=<id>&page=N"
            "&page_size=M (OT site inventory — each Vantage site models "
            "one OT facility / plant / process line; canonical envelope "
            "`{results, count, next, previous}` — Django-REST style — "
            "with each record carrying id, name, description, location / "
            "address, city, country, latitude / longitude, time_zone, "
            "created_at / updated_at, the appliance roster (appliances / "
            "guardian_count), asset_count, alert_count, optional "
            "criticality / risk_score rollups) and GET /v1/alerts"
            "?site_id=<id>&page=N&page_size=M (same envelope shape; each "
            "record carries id, name / type_name, description, severity, "
            "type_id (Vantage inherits Guardian's published alert "
            "taxonomy: SIGN:NETWORK:MALWARE / SIGN:PROTOCOL:ANOMALY / "
            "VI:UNAUTHORIZED-COMMAND etc), status, record_created_at / "
            "record_updated_at, src_ip / dst_ip, risk, site_id / "
            "site_name, zone_id / zone_name); same stateless auth shape "
            "as Guardian (no login round-trip) — VANTAGE_API_KEY is "
            "passed verbatim as Authorization: Bearer <key> on every "
            "/v1/ request (Vantage issues a single bearer-shaped key per "
            "tenant in the Vantage console rather than the user + "
            "password pair Guardian uses); VANTAGE_HOST has no default "
            "(multi-tenant SaaS); pagination one-based capped at "
            "VANTAGE_PAGES=10 clamped to [1, 100]; takes optional "
            "VANTAGE_SITE_ID (server-side site_id= filter on both "
            "surfaces); terminal Resolved / Muted / Closed / Suppressed "
            "/ Dismissed / Acknowledged / Mitigated / Accepted-Risk "
            "states floored to info via the Vantage-Status pivot; tagged "
            "`[nozomi_vantage]` with the `ot-security` group tag; needs "
            "VANTAGE_HOST + VANTAGE_API_KEY). "
            "Runs ordr (Ordr Core REST API import — paginated GET "
            "/api/v1/devices?category=<cat>&page=N&page_size=M "
            "(connected-device inventory; canonical envelope `{results, "
            "count, next, previous}` with each record carrying id, name, "
            "ip, mac, manufacturer, model, firmware / firmware_version, "
            "os / operating_system, category / device_category, "
            "device_type, criticality, location / site_name, first_seen "
            "/ last_seen, risk_score, optional cve_list / "
            "vulnerabilities) and GET /api/v1/alerts?category=<cat>"
            "&page=N&page_size=M (security alert feed; same envelope "
            "shape with each record carrying id, title / name, "
            "description, severity, category, status, created_at / "
            "updated_at, device_type, related_devices, risk_score); "
            "long-lived API token flow — ORDR_TOKEN provisioned in the "
            "Ordr console and carried verbatim as Authorization: Bearer "
            "<token> on every /api/v1/ request (no login exchange); "
            "ORDR_HOST has no default (deployed both as on-prem and as "
            "SaaS); pagination one-based capped at ORDR_PAGES=10 clamped "
            "to [1, 100]; takes optional ORDR_CATEGORY (server-side "
            "category= filter — accepts medical / iot / ot / it labels "
            "or numeric ids) + ORDR_MIN_SEVERITY (client-side severity "
            "floor); terminal states floored to info via the Ordr-Status "
            "pivot; tagged `[ordr]` with the `ot-security` group tag; "
            "needs ORDR_HOST + ORDR_TOKEN). "
            "Severity bucketing across the six new connectors: device / "
            "asset / site records bucket from the vendor's criticality "
            "field (Critical / High / Medium / Low / Info label, or 0..4 "
            "numeric, falling back to 0..10 / 0..100 for federated "
            "mirrors); alert records bucket from the vendor's severity "
            "field directly (label or 0..10 numeric, falling back to "
            "risk / risk_score / cvss_score); terminal alert states "
            "(`Resolved` / `Muted` / `Suppressed` / `Dismissed` / "
            "`false-positive` plus Nozomi-specific `Acknowledged` / "
            "`Mitigated` / `Accepted-Risk`) floor the severity to `info` "
            "regardless of the published bucket. Each record carries the "
            "vendor-specific ref pivots (`Claroty-AssetID` / "
            "`Xdome-DeviceID` / `EyeInspect-DeviceID` / `Nozomi-AssetID` "
            "/ `Vantage-SiteID` / `Ordr-DeviceID` for inventory; "
            "`*-AlertID` for the alert stream; `Nozomi-VulnID` for the "
            "Nozomi vulnerability surface) plus the canonical NVD CVE "
            "permalink for any CVE ids surfaced in the cve_list / "
            "vulnerabilities / description / title fields so operators "
            "can pivot from a Faraday finding back to the exact OT "
            "sensor record. Cisco Cyber Vision was historically wired "
            "into the `vulnscan` group; it moved into `ot-security` "
            "alongside the six new sensors so operators get a single "
            "OT-focused dispatcher agent instead of having OT findings "
            "spread across two groups."
        ),
    },
    "pentest-platforms": {
        "agent_name": "pentest-platforms",
        "executors": [
            "bugcrowd",
            "cobalt",
            "hackerone",
            "intigriti",
            "plextrac",
        ],
        "description": (
            "Crowd-sourced bug bounty and pentest-as-a-service platforms — "
            "pulls validated vulnerabilities and engagement findings into "
            "Faraday so external pentest data lands in the same workflow "
            "as internal scanner output. All five connectors emit one "
            "Faraday host per report / submission / finding (with "
            "host.ip set to the 0.0.0.0 sentinel because bug-bounty and "
            "pentest records are keyed on a URL / asset path rather than "
            "an IP) plus one Faraday vulnerability under the appropriate "
            "engine prefix (`[BUG-BOUNTY]` for the crowd-sourced platforms "
            "hackerone / bugcrowd / intigriti; `[PENTEST]` for the "
            "engagement-driven platforms cobalt / plextrac) so external "
            "researcher and pentester output lands alongside the other "
            "crowd-sourced feeds. "
            "Runs hackerone (HackerOne v1 REST API — paginated GET "
            "/v1/reports?filter[program][]=<handle>&filter[state][]=<csv>"
            "&page[number]=N&page[size]=M (bug-bounty report feed; "
            "canonical JSON:API envelope `{data, links}` with each "
            "record's attributes carrying title, vulnerability_information, "
            "state (new / triaged / needs-more-info / pending-program-"
            "review / informative / resolved / not-applicable / duplicate "
            "/ spam / retesting — HackerOne's published state machine), "
            "severity (critical / high / medium / low / none label, or "
            "nested {rating, score}), created_at / updated_at / triaged_at "
            "/ closed_at / disclosed_at, bounty_awarded_amount / "
            "bounty_currency, cve_ids (attributed CVE strings), weakness "
            "(CWE attribution under relationships.weakness.data.attributes"
            ".external_id), vulnerable_endpoint (URL / asset the researcher "
            "targeted); relationships pointers to program (handle + name) "
            "and reporter (researcher username)); HTTP Basic Auth — the "
            "dispatcher sends Authorization: Basic <base64(H1_USER:"
            "H1_API_TOKEN)> on every /v1/ request with no separate login "
            "round-trip (H1_USER is the identity's API handle, not the "
            "human-readable display name; H1_API_TOKEN is provisioned per "
            "identity in HackerOne's API settings); H1_HOST is an env-only "
            "override that defaults to https://api.hackerone.com (the rare "
            "on-prem / staging mirror or api.staging.hackerone.com is "
            "supported by overriding the env var); pagination one-based "
            "via JSON:API's page[number]=N + page[size]=M capped at "
            "H1_PAGES=10 clamped to [1, 100]; takes optional "
            "H1_PROGRAM_HANDLE (server-side filter[program][] filter — "
            "CSV-aware so a single agent can pull from several programs), "
            "H1_STATE (server-side filter[state][] filter — CSV-aware "
            "with operator-friendly aliases like `needs-info` -> `needs-"
            "more-info`, `closed` / `fixed` -> `resolved`), and "
            "H1_MIN_SEVERITY (client-side Faraday severity floor); "
            "terminal Resolved / Informative / Not-Applicable / Duplicate "
            "/ Spam reports floored to info via the H1-State pivot; "
            "tagged `[hackerone]` with the `pentest-platforms` group tag "
            "and the `report` source tag; needs H1_USER + H1_API_TOKEN). "
            "Runs bugcrowd (Bugcrowd REST API — paginated GET "
            "/submissions?filter[program][]=<uuid>&filter[state][]=<csv>"
            "&page[offset]=N&page[limit]=M (bug-bounty submission feed; "
            "canonical JSON:API envelope `{data, meta, links}` with each "
            "record's attributes carrying title, description / "
            "vulnerability_information, state (new / triaged / unresolved "
            "/ resolved / duplicate / not-reproducible / not-applicable / "
            "out-of-scope / informational / needs-reproduction / spam — "
            "Bugcrowd's published state machine), substate (additional "
            "triage detail), priority (integer 1..5 — Bugcrowd's P1..P5 "
            "ladder where P1 is most critical and P5 is least), "
            "cvss_vector / cvss_score, vrt_id (Bugcrowd's Vulnerability "
            "Rating Taxonomy id — canonical issue-type ontology with CWE "
            "mapping), bug_url (URL / asset the researcher targeted), cve "
            "(attributed CVE strings), created_at / submitted_at / "
            "triaged_at / resolved_at / disclosed_at / last_updated_at, "
            "monetary_reward / reward_currency; relationships pointers to "
            "program (uuid + handle), researcher (username), target "
            "(scoped asset), and vrt (canonical issue-type ontology "
            "pointer)); long-lived single-token auth — BC_API_TOKEN is "
            "forwarded verbatim as Authorization: Token <BC_API_TOKEN> on "
            "every REST request with no separate login round-trip (no "
            "username — the token alone is the identity); the dispatcher "
            "locks the API version with the Accept: application/vnd."
            "bugcrowd.v4+json header so later API breaking changes do not "
            "silently warp the ingest shape; BC_HOST is an env-only "
            "override that defaults to https://api.bugcrowd.com (the rare "
            "enterprise mirror or a Bugcrowd-provided sandbox is supported "
            "by overriding the env var); pagination offset-based via "
            "JSON:API's page[offset]=N + page[limit]=M capped at "
            "BC_PAGES=10 clamped to [1, 100]; takes optional "
            "BC_PROGRAM_UUID (server-side filter[program][] filter — "
            "Bugcrowd accepts either the program's uuid or its slug; "
            "CSV-aware so a single agent can pull from several programs), "
            "BC_STATE (server-side filter[state][] filter — CSV-aware "
            "with operator-friendly aliases like `open` -> `unresolved`, "
            "`oos` -> `out-of-scope`, `closed` / `fixed` -> `resolved`), "
            "and BC_MIN_PRIORITY (client-side P1..P5 priority floor — "
            "inverted so the smaller number wins: `min_priority=3` keeps "
            "P1/P2/P3 and drops P4/P5; P1 -> critical, P2 -> high, P3 -> "
            "medium, P4 -> low, P5 -> info); terminal Resolved / Duplicate "
            "/ Not-Reproducible / Not-Applicable / Out-Of-Scope / "
            "Informational / Spam submissions floored to info via the "
            "BC-State pivot; tagged `[bugcrowd]` with the `pentest-"
            "platforms` group tag and the `submission` source tag; needs "
            "BC_API_TOKEN). "
            "Runs intigriti (Intigriti Researcher REST API — paginated "
            "GET /external/researcher/v1/submissions?programId=<uuid>"
            "&statusId=<status>&limit=N&offset=M (bug-bounty submission "
            "feed; canonical envelope `{records, maxCount}` with each "
            "record carrying id, code, title, state (`Open` / `Closed` "
            "plus substate detail under state.value — Intigriti's "
            "published state machine includes New / Triage / Triaged / "
            "Accepted / Pending review / Resolved / Closed / Duplicate / "
            "Out of scope / Spam / Informative / Won't fix), severity "
            "(label or {id, value} shape with the canonical Intigriti "
            "ladder Exceptional / Critical / High / Medium / Low / None / "
            "Informational), type (issue-type ontology with CWE mapping), "
            "endpoint (URL / asset the researcher targeted), programId "
            "(uuid pointer to the program), researcher.username, createdAt "
            "/ lastUpdatedAt / closedAt (epoch seconds), bountyAmount / "
            "bountyCurrency (payout breakdown), cvssScore / cvssVector, "
            "cve (attributed CVE strings), cwe (attributed CWE strings, "
            "or nested {id, value}))); long-lived single-token bearer "
            "auth — INTIG_TOKEN is forwarded verbatim as Authorization: "
            "Bearer <INTIG_TOKEN> on every REST request with no separate "
            "login round-trip (no username — the token alone is the "
            "identity); INTIG_HOST is an env-only override that defaults "
            "to https://api.intigriti.com (the rare enterprise mirror or "
            "an Intigriti-provided sandbox is supported by overriding the "
            "env var); pagination offset-based via limit=N + offset=M "
            "capped at INTIG_PAGES=10 clamped to [1, 100]; takes optional "
            "INTIG_PROGRAM_ID (server-side programId= filter — Intigriti "
            "accepts either the program's uuid or its slug; CSV-aware so "
            "a single agent can pull from several programs) and "
            "INTIG_STATUS (server-side statusId= filter — repeated for "
            "each status; CSV-aware with operator-friendly aliases like "
            "`triaging` -> `triage`, `fixed` -> `resolved`, `info` -> "
            "`informative`, `wontfix` -> `wont-fix`); severity ladder "
            "collapses Intigriti's `Exceptional` rating into Faraday's "
            "`critical` bucket (Intigriti's most-severe rating sits above "
            "CVSS-style critical so the two collapse together for "
            "Faraday's ladder); terminal Closed / Resolved / Duplicate / "
            "Out-Of-Scope / Spam / Informative / Wont-Fix submissions "
            "floored to info via the INTIG-Status pivot; tagged "
            "`[intigriti]` with the `pentest-platforms` group tag and the "
            "`submission` source tag; needs INTIG_TOKEN). "
            "Runs cobalt (Cobalt.io v2 REST API — paginated GET "
            "/v2/findings?filter[pentest_id]=<id>&limit=N&offset=M "
            "(pentest finding feed; canonical JSON:API envelope "
            "`{data, links, meta}` with each record's attributes carrying "
            "title, description, log (researcher proof / reproduction "
            "notes), type_category (Cobalt's published issue-type "
            "ontology — e.g. 'Server Security Misconfiguration', "
            "'Application-Logic & Server-Side', 'Sensitive Data "
            "Exposure'), severity ('informational' / 'low' / 'medium' / "
            "'high' / 'critical' — Cobalt's CVSS-aligned ladder), state "
            "('new' / 'triaging' / 'valid_triaged' / 'invalid' / "
            "'out_of_scope' / 'accepted_risk' / 'wont_fix' / "
            "'need_more_info' / 'not_applicable' / 'duplicate' / "
            "'resolved' / 'check_fix' / 'fix_in_progress' — Cobalt's "
            "published state machine), affected_targets (list of scoped "
            "assets), vulnerable_url (URL the pentester targeted), "
            "proof_of_concept / suggested_fix (remediation guidance), "
            "cvss_score / cvss_vector, impact / likelihood (1..5 ladders "
            "for the program-set severity rating), created_at / "
            "submitted_at / triaged_at / resolved_at / updated_at; "
            "relationships pointers to pentest (engagement uuid + handle), "
            "pentester (researcher username), and asset (scoped target)); "
            "the /v2/pentests endpoint is documented for operator reference "
            "(the dispatcher never fetches it directly — operators paste "
            "the relevant COBALT_PENTEST_ID into the manifest argument); "
            "two-header auth — COBALT_TOKEN (user-identity API token) is "
            "forwarded verbatim as Authorization: Bearer <COBALT_TOKEN> "
            "plus COBALT_ORG_TOKEN (organisation scope token) forwarded "
            "verbatim as X-Org-Token: <COBALT_ORG_TOKEN> so a single user "
            "identity can scope the call to a specific organisation under "
            "its access (Cobalt's documented v2 auth shape — the API "
            "token identifies the user identity, the org token narrows "
            "the call to a specific organisation under that identity's "
            "access); the dispatcher locks the API version with the "
            "Accept: application/vnd.cobalt.v2+json header so later API "
            "breaking changes do not silently warp the ingest shape; "
            "COBALT_HOST defaults to https://api.cobalt.io (the rare "
            "enterprise mirror or a Cobalt-provided sandbox is supported "
            "by overriding the env var); pagination offset-based via "
            "limit=N + offset=M capped at COBALT_PAGES=10 clamped to "
            "[1, 100]; takes optional COBALT_PENTEST_ID (server-side "
            "filter[pentest_id] filter — Cobalt accepts either the "
            "pentest uuid or its slug; CSV-aware so a single agent can "
            "pull findings from several engagements) and COBALT_MIN_"
            "SEVERITY (client-side Faraday severity floor — scalar label "
            "preferred, nested {rating, score} tolerated with the CVSS v3 "
            "0..10 ladder as a fallback: 0.0 -> info, 0.1..3.9 -> low, "
            "4.0..6.9 -> medium, 7.0..8.9 -> high, 9.0..10.0 -> critical); "
            "terminal invalid / out_of_scope / not_applicable / duplicate "
            "/ accepted_risk / wont_fix / resolved findings floored to "
            "info via the Cobalt-State pivot; tagged `[cobalt]` with the "
            "`pentest-platforms` group tag and the `finding` source tag; "
            "needs COBALT_HOST + COBALT_TOKEN + COBALT_ORG_TOKEN). "
            "Runs plextrac (PlexTrac REST API — short-lived JWT minted "
            "from POST /api/v1/authenticate with body {username: "
            "PLEXTRAC_USER, password: PLEXTRAC_PASSWORD}; the returned "
            "JWT is forwarded verbatim as Authorization: Bearer <token> "
            "on every subsequent /api/v1/ request (the extract_token "
            "helper tolerates older PlexTrac releases that return "
            "{token} directly, newer multi-tenant releases that expose "
            "it under access_token / jwt / id_token, and federated "
            "mirrors that nest under data.token — all shapes collapse to "
            "the same canonical JWT string); paginated GET /api/v1/"
            "findings?client_id=<id>&report_id=<id>&limit=N&offset=M "
            "(pentest finding feed; canonical envelope `{data, total}` "
            "on newer PlexTrac releases or a bare list on older releases "
            "— both shapes plus the federated `results` / `items` / "
            "`findings` / `records` / `flaws` fallbacks are tolerated by "
            "extract_records; each record carries flaw_id / id, title, "
            "severity ('Critical' / 'High' / 'Medium' / 'Low' / "
            "'Informational' — PlexTrac's published label ladder), "
            "status ('Open' / 'In Process' / 'Closed' / 'Mitigated' / "
            "'Accepted Risk' / 'Resolved' — PlexTrac's published state "
            "machine), description (finding write-up), recommendations "
            "(remediation guidance), references (free-text refs body), "
            "affected_assets (dict of scoped asset id -> {asset, status} "
            "for the assets the finding hits), cvss / cvss_vector, cve / "
            "cwe (attributed CVE / CWE strings), client_id / report_id, "
            "assignedTo / createdBy (PlexTrac user identifiers), "
            "created_at / updated_at / closed_at / last_update (epoch "
            "seconds or ISO 8601), tags (operator-set free-text tags)); "
            "the /api/v1/clients/<id>/reports endpoint is documented for "
            "operator reference (the dispatcher never fetches it directly "
            "— operators paste the relevant PLEXTRAC_REPORT_ID into the "
            "manifest argument); the dispatcher forces Accept: "
            "application/json + Content-Type: application/json on every "
            "request so PlexTrac never tries to negotiate an HTML "
            "envelope; PLEXTRAC_HOST is an env-only override that defaults "
            "to https://api.plextrac.com (the public PlexTrac SaaS multi-"
            "tenant endpoint — almost every PlexTrac tenant runs on its "
            "own <tenant>.plextrac.com subdomain so this env var typically "
            "needs to be overridden to the operator's tenant URL); "
            "pagination offset-based via limit=N + offset=M capped at "
            "PLEXTRAC_PAGES=10 clamped to [1, 100]; takes optional "
            "PLEXTRAC_CLIENT_ID (server-side client_id= filter — CSV-aware "
            "so a single agent can pull from several clients) and "
            "PLEXTRAC_REPORT_ID (server-side report_id= filter — CSV-aware "
            "so a single agent can pull from several reports); severity "
            "label preferred, nested {rating, score} tolerated with the "
            "CVSS v3 0..10 ladder as a fallback (0.0 -> info, 0.1..3.9 -> "
            "low, 4.0..6.9 -> medium, 7.0..8.9 -> high, 9.0..10.0 -> "
            "critical); terminal Closed / Resolved / Mitigated / Accepted "
            "Risk findings floored to info via the PlexTrac-Status pivot; "
            "tagged `[plextrac]` with the `pentest-platforms` group tag "
            "and the `finding` source tag; needs PLEXTRAC_HOST + "
            "PLEXTRAC_USER + PLEXTRAC_PASSWORD). "
            "Auth shape summary across the five connectors: HackerOne "
            "uses HTTP Basic Auth (H1_USER + H1_API_TOKEN base64-joined); "
            "Bugcrowd uses a single long-lived Token-scheme header "
            "(BC_API_TOKEN); Intigriti uses a single long-lived Bearer "
            "header (INTIG_TOKEN); Cobalt uses a two-header pair (Bearer "
            "COBALT_TOKEN + X-Org-Token COBALT_ORG_TOKEN); PlexTrac uses "
            "a short-lived JWT minted from PLEXTRAC_USER + "
            "PLEXTRAC_PASSWORD via a POST /api/v1/authenticate exchange. "
            "All five lazy-import requests inside main() so the module "
            "loads (and all helpers exercise) without requests installed; "
            "all five trim whitespace and add https:// when the operator "
            "pasted a bare FQDN into the host env var. Severity bucketing "
            "is per-vendor: HackerOne / Cobalt / PlexTrac use the "
            "published CVSS-aligned label ladder (critical / high / "
            "medium / low / info — `none` / `informational` collapse to "
            "Faraday's `info` bucket so the record is still visible); "
            "Bugcrowd inverts its P1..P5 ladder (P1 most severe, P5 "
            "least, so the floor is inverted relative to Faraday's "
            "ladder); Intigriti collapses its `Exceptional` rating into "
            "Faraday's `critical` bucket. Terminal closed states across "
            "all five vendors floor the severity to `info` regardless of "
            "the published rating; the closed state is preserved via an "
            "explicit per-vendor pivot in the refs (H1-State / BC-State / "
            "INTIG-Status / Cobalt-State / PlexTrac-Status). Each record "
            "carries the vendor-specific ref pivots (H1-ReportID / "
            "BC-SubmissionID / INTIG-SubmissionID / Cobalt-FindingID / "
            "PlexTrac-FindingID plus per-vendor program / researcher / "
            "state / created-at / updated-at / bounty / cvss / endpoint "
            "pivots) plus the canonical platform permalinks "
            "(https://hackerone.com/reports/<id>, "
            "https://tracker.bugcrowd.com/submissions/<id>, "
            "https://app.intigriti.com/researcher/submissions/<id>, "
            "https://app.cobalt.io/findings/<id>, "
            "https://app.plextrac.com/client/<client>/report/<report>/"
            "finding/<id>) and the canonical NVD CVE + MITRE CWE "
            "permalinks for any CVE / CWE ids surfaced in the per-vendor "
            "fields so operators can pivot from a Faraday finding back to "
            "the exact bug-bounty report / pentest finding on the source "
            "platform."
        ),
    },
    "identity-iam": {
        "agent_name": "identity-iam-agent",
        "executors": [
            "okta",
            "adaptive_shield",
            "bloodhound_enterprise",
            "cloudknox",
        ],
        "description": (
            "Identity providers and IAM-posture platforms — pulls user/group/role data and "
            "identity-attack-surface findings into Faraday for blast-radius correlation."
        ),
    },
    "secrets-mgmt-vault": {
        "agent_name": "secrets-mgmt-vault-agent",
        "executors": [
            "beyondtrust_passwordsafe",
        ],
        "description": (
            "Privileged Access Management and secrets vault platforms — pulls credential-hygiene "
            "and vault-policy findings into Faraday."
        ),
    },
    "network-mgmt": {
        "agent_name": "network-mgmt-agent",
        "executors": [
            "netbox",
            "infoblox_ddi",
            "infoblox_netmri",
            "menandmice",
        ],
        "description": (
            "Network management and IPAM systems — pulls device inventories, DNS/DHCP records, "
            "and subnet ownership into Faraday for cross-referencing scanner output."
        ),
    },
    "security-ratings": {
        "agent_name": "security-ratings-agent",
        "executors": [
            "bitsight",
            "securityscorecard",
        ],
        "description": (
            "Security rating services — pulls third-party risk grades and exposure findings "
            "for monitored domains/companies into Faraday."
        ),
    },
    "siem-analytics": {
        "agent_name": "siem-analytics-agent",
        "executors": [
            "splunk",
            "qradar",
            "uptycs",
            "eventsentry",
        ],
        "description": (
            "SIEM / security analytics platforms — pulls saved-search results and "
            "analytics-driven detections into Faraday as host vulnerabilities. Set "
            "SEARCH_QUERY/AQL_QUERY per scan to scope what's pulled."
        ),
    },
    "patch-management": {
        "agent_name": "patch-management-agent",
        "executors": [
            "vicarius",
            "ivanti_security_controls",
            "redhat_satellite",
            "sccm",
            "wsus",
        ],
        "description": (
            "Patch management consoles — pulls patch compliance and missing-update status "
            "into Faraday so unpatched-system vulnerabilities are visible alongside scanner "
            "findings."
        ),
    },
    "sap-security": {
        "agent_name": "sap-security-agent",
        "executors": [
            "securitybridge_sap",
        ],
        "description": (
            "SAP-stack security — pulls SAP-aware findings (auth defects, config drift, "
            "transport-bypass attempts) from SAP-specialised security platforms into Faraday."
        ),
    },
    "governance-compliance": {
        "agent_name": "governance-compliance-agent",
        "executors": [
            "vanta",
            "drata",
            "sprinto",
        ],
        "description": (
            "GRC / continuous-compliance platforms — pulls failing controls, evidence gaps and "
            "monitored assets from Vanta / Drata / Sprinto into Faraday so SOC 2 / ISO 27001 / "
            "HIPAA-relevant control failures show up alongside scanner findings. Each failing "
            "test becomes one Faraday vulnerability tagged '[GRC]' on the affected asset."
        ),
    },
    "agentic-security": {
        "agent_name": "agentic-security-agent",
        "executors": [
            "strix",
            "aikido",
            "xbow",
            "aws_security_agent",
        ],
        "description": (
            "Agentic / autonomous security platforms — pulls findings from AI-driven pentest "
            "agents (XBOW, Strix.ai) and continuously-monitored AppSec/cloud platforms "
            "(Aikido, AWS Security Agent) into Faraday. Each surfaced issue becomes one "
            "Faraday vulnerability tagged '[AGENT]' on the affected asset. Since these tools "
            "self-triage, findings arrive already scored and are mapped 1:1 into Faraday's "
            "severity buckets."
        ),
    },
    "database-security": {
        "agent_name": "database-security-agent",
        "executors": [
            "oracle_datasafe",
            "ibm_guardium",
        ],
        "description": (
            "Database-layer security platforms — pulls DAM (Database Activity Monitoring), "
            "classification, and sensitive-data exposure findings into Faraday."
        ),
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an Offensive Checks dispatcher manifest with all official Faraday executors."
    )
    parser.add_argument("--agent-token", required=True, help="64-character token returned by POST /_api/v3/agents")
    parser.add_argument("--namespace", default="offensive-checks")
    parser.add_argument("--deployment", default="offensive-checks-agent-dispatcher")
    parser.add_argument("--agent-name", default="offensive-checks-dispatcher")
    parser.add_argument("--host", required=True, help="Faraday server hostname (e.g. faraday.example.com)")
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
        deployment = f"offensive-checks-{args.group}-dispatcher"
        description = group.get("description") or f"Offensive Checks {args.group} agent"
        return agent_name, deployment, group["executors"], description
    return (
        args.agent_name,
        args.deployment,
        None,
        "Offensive Checks dispatcher with all official Faraday executors",
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
        "app.kubernetes.io/instance": "offensive-checks",
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
