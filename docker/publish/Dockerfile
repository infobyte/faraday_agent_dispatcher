# syntax=docker/dockerfile:1.6
# Pin the BuildKit frontend so the `RUN python - <<'PY' ... PY` heredoc on
# line ~36 parses. The bundled v0 frontend (which BuildKit defaults to
# without this directive) rejects heredoc bodies as Dockerfile instructions
# and dies with `unknown instruction: IMPORT`.
ARG TAG=""
ARG REGISTRY="registry.gitlab.com/faradaysec/cloud"
# Final-stage base. Defaults to the private cloud registry image (REGISTRY+TAG).
# Override for local builds, e.g. --build-arg BASE_IMAGE=faradaysec/faraday_agent_dispatcher:3.9.1
ARG BASE_IMAGE="${REGISTRY}/faraday_agent_dispatcher:${TAG}"
ARG KICS_VERSION=2.1.6

#### KICS binary + query assets (no standalone release binary exists) ####
FROM checkmarx/kics:v${KICS_VERSION} AS kics

#### Dispatcher builder ####
FROM python:3.13.7-slim AS dispatcher-build
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1

WORKDIR /app/

RUN python -m venv /opt/dispatcher_venv
ENV PATH="/opt/dispatcher_venv/bin:$PATH"
COPY . .
RUN pip install --no-cache-dir .

# --- Offensive Checks: vendored bagre threat-intel package ---
# Installs the bagre subpackage (clickhouse + intelx sources, credential
# validators, password-spray engine) into the dispatcher venv so the
# bagre / bagre_spray executors under static/executors/official can do
# `from bagre.config import load_config` etc. Pulls clickhouse-driver,
# tldextract, paramiko, smbprotocol as transitive deps.
RUN pip install --no-cache-dir /app/offensive_checks/bagre_pkg

# --- Offensive Checks: patch bundled faraday_plugins parsers ---
# Apply the compatibility fixes in-place with Python instead of installing the
# system `patch` package in the builder. This keeps the build deterministic
# while reducing storage pressure on the shell runner's Docker daemon.
RUN python - <<'PY'
import os
from pathlib import Path

import faraday_plugins

plugins_dir = Path(os.path.dirname(faraday_plugins.__file__))
replacements = {
    plugins_dir / "plugins" / "repo" / "crowdstrike" / "plugin.py": [
        (
            "            severity = site.get('severity').lower()\n",
            "            # Defensive: severity may be missing from Spotlight rows.\n"
            "            severity = (site.get('severity') or 'unclassified').lower()\n",
        )
    ],
    plugins_dir / "plugins" / "repo" / "trivy_json" / "DTO.py": [
        (
            "        if self.node.get(\"Lines\"):\n"
            "            return [Line(i) for i in self.node.get(\"Lines\")]\n"
            "        else:\n"
            "            return None\n",
            "        # Defensive: Trivy may emit Code: null for some misconfigurations.\n"
            "        if self.node and self.node.get(\"Lines\"):\n"
            "            return [Line(i) for i in self.node.get(\"Lines\")]\n"
            "        return None\n",
        )
    ],
    plugins_dir / "plugins" / "repo" / "sarif" / "plugin.py": [
        (
            "                    desc = rule.get(\"fullDescription\").get(\"text\") if rule.get(\"fullDescription\", {}).get(\"text\") \\\n"
            "                        else markdown2text(rule.get(\"fullDescription\").get(\"markdown\", \"\"))\n",
            "                    full_description = rule.get(\"fullDescription\") or {}\n"
            "                    desc = full_description.get(\"text\") if full_description.get(\"text\") \\\n"
            "                        else markdown2text(full_description.get(\"markdown\", \"\"))\n",
        )
    ],
}

for path, snippets in replacements.items():
    text = path.read_text(encoding="utf-8")
    original = text
    for old, new in snippets:
        if old not in text:
            raise SystemExit(f"expected snippet not found in {path}")
        text = text.replace(old, new, 1)
    if text == original:
        raise SystemExit(f"no replacements applied in {path}")
    path.write_text(text, encoding="utf-8")
    print(f"patched {path}")
PY

# --- Offensive Checks: surface our manifests to faraday_agent_parameters_types ---
# The dispatcher's on_connect (dispatcher_io.py:657) reads executor categories
# from faraday_agent_parameters_types.utils.get_manifests(), which scans only
# that package's static/manifests dir. Without copying our 21 manifests there,
# every offensive-check executor lands on the Faraday server with category=null
# (the manifests in faraday_agent_dispatcher/static/manifests are only seen by
# our metadata_utils fallback, which on_connect doesn't use).
RUN PT_DIR="$(python -c 'import os, faraday_agent_parameters_types; print(os.path.join(os.path.dirname(faraday_agent_parameters_types.__file__), "static", "manifests"))')" \
    && cp /app/faraday_agent_dispatcher/static/manifests/*.json "$PT_DIR"/ \
    && echo "vendored offensive-check manifests into $PT_DIR"

#### Final image ####
FROM ${BASE_IMAGE}
COPY --from=dispatcher-build /opt/dispatcher_venv /opt/dispatcher_venv

ENV PATH="/opt/dispatcher_venv/bin:$PATH"

# ---------------------------------------------------------------------------
# Offensive Checks tool binaries
# Pinned versions; linux/amd64 (EKS corporate node-group).
# ---------------------------------------------------------------------------
ARG TARGETARCH=amd64
ARG TRIVY_VERSION=0.69.3
ARG GRYPE_VERSION=0.87.0
ARG GITLEAKS_VERSION=8.21.2
ARG TRUFFLEHOG_VERSION=3.88.0
ARG FFUF_VERSION=2.1.0
ARG NAABU_VERSION=2.3.3
ARG SUBFINDER_VERSION=2.6.7
ARG KUBESCAPE_VERSION=3.0.22
ARG KUBE_BENCH_VERSION=0.10.0
ARG TFSEC_VERSION=1.28.13
ARG AMASS_VERSION=4.2.0

USER root

# System packages: shellcheck (SAST shell), node/npm (snyk), pipx (isolated py CLIs),
# libpcap for naabu, masscan (folded in here rather than as a later layer because
# the runner's disk fills up across the cumulative pipx-install layers below) and
# the usual download tooling.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git unzip tar xz-utils jq \
        shellcheck nodejs npm pipx libpcap0.8 masscan \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Python CLI tools in isolated pipx envs (avoids clashing with the dispatcher venv).
# prowler is pinned to v3.x: the faraday_plugins ProwlerPlugin parses Prowler v3
# native JSON (keys Region/CheckTitle/Status); v4+ emit OCSF which it cannot read.
# Separate RUN layers so a transient network failure only re-runs the failed tool,
# and give pip generous retries/timeouts (PyPI resets are common under emulation).
ENV PIPX_HOME=/opt/pipx
ENV PIPX_BIN_DIR=/usr/local/bin
ENV PIP_DEFAULT_TIMEOUT=120
ENV PIP_RETRIES=10
ENV PIP_NO_CACHE_DIR=1
RUN pipx install semgrep
RUN pipx install bandit
RUN pipx install checkov
RUN pipx install 'prowler<4'
# Round-3 discovery-osint additions:
# dnstwist for typo-squat detection, theHarvester for OSINT. (masscan is
# installed in the system-packages layer above to keep disk available.)
RUN pipx install dnstwist
# theHarvester's PyPI release ships no CLI entry point — install from the
# upstream git repo where setup.py declares console_scripts properly.
RUN pipx install "git+https://github.com/laramies/theHarvester.git"

# Snyk CLI (Node).
RUN npm config set fetch-retries 5 && npm install -g snyk && npm cache clean --force

# Go / release-binary tools (linux/${TARGETARCH}). curl retries transient resets.
RUN set -eux; \
    cd /tmp; \
    dl() { curl -sSL --retry 4 --retry-delay 3 --retry-connrefused "$@"; }; \
    # Trivy
    dl "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | tar -xz trivy && mv trivy /usr/local/bin/; \
    # Grype
    dl "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${TARGETARCH}.tar.gz" | tar -xz grype && mv grype /usr/local/bin/; \
    # Gitleaks
    dl "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz gitleaks && mv gitleaks /usr/local/bin/; \
    # TruffleHog
    dl "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TARGETARCH}.tar.gz" | tar -xz trufflehog && mv trufflehog /usr/local/bin/; \
    # ffuf
    dl "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${TARGETARCH}.tar.gz" | tar -xz ffuf && mv ffuf /usr/local/bin/; \
    # naabu
    dl -o naabu.zip "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${TARGETARCH}.zip" && unzip -o naabu.zip naabu && mv naabu /usr/local/bin/ && rm naabu.zip; \
    # subfinder
    dl -o subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${TARGETARCH}.zip" && unzip -o subfinder.zip subfinder && mv subfinder /usr/local/bin/ && rm subfinder.zip; \
    # kubescape
    dl -o /usr/local/bin/kubescape "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape-ubuntu-latest" && chmod +x /usr/local/bin/kubescape; \
    # kube-bench
    dl "https://github.com/aquasecurity/kube-bench/releases/download/v${KUBE_BENCH_VERSION}/kube-bench_${KUBE_BENCH_VERSION}_linux_${TARGETARCH}.tar.gz" | tar -xz kube-bench && mv kube-bench /usr/local/bin/; \
    # tfsec
    dl -o /usr/local/bin/tfsec "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-${TARGETARCH}" && chmod +x /usr/local/bin/tfsec; \
    # amass (subdomain + DNS recon)
    dl -o amass.zip "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_Linux_${TARGETARCH}.zip" && unzip -j -o amass.zip "*/amass" -d /usr/local/bin/ && rm amass.zip; \
    chmod +x /usr/local/bin/*; \
    rm -rf /tmp/*

# KICS has no standalone release binary; copy the binary + query assets from the
# official image. kics resolves its query library from KICS_QUERIES_PATH.
COPY --from=kics /app/bin/kics /usr/local/bin/kics
COPY --from=kics /app/bin/assets /opt/kics/assets
ENV KICS_QUERIES_PATH=/opt/kics/assets/queries

ENTRYPOINT ["faraday-dispatcher", "run"]
