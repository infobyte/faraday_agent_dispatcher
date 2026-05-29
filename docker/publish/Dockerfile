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

WORKDIR /app/

RUN python -m venv /opt/dispatcher_venv
ENV PATH="/opt/dispatcher_venv/bin:$PATH"
COPY . .
RUN pip install .

# --- Offensive Checks: patch bundled faraday_plugins parsers ---
# The offensive-check manifests ship inside the dispatcher package
# (faraday_agent_dispatcher/static/manifests, resolved by metadata_utils), so no
# parameters-types copy is needed. We only patch two plugin parsers here until
# the fixes are released upstream (Trivy Code:null, CrowdStrike missing severity).
RUN apt-get update && apt-get install -y --no-install-recommends patch \
    && PLUGINS_DIR="$(python -c 'import os, faraday_plugins; print(os.path.dirname(faraday_plugins.__file__))')" \
    && patch -p2 -d "$PLUGINS_DIR" < /app/offensive_checks/patches/faraday_plugins_offensive_fixes.patch \
    && rm -rf /var/lib/apt/lists/*

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
# plus libpcap for naabu and the usual download tooling.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git unzip tar xz-utils jq \
        shellcheck nodejs npm pipx libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Python CLI tools in isolated pipx envs (avoids clashing with the dispatcher venv).
# prowler is pinned to v3.x: the faraday_plugins ProwlerPlugin parses Prowler v3
# native JSON (keys Region/CheckTitle/Status); v4+ emit OCSF which it cannot read.
# Separate RUN layers so a transient network failure only re-runs the failed tool,
# and give pip generous retries/timeouts (PyPI resets are common under emulation).
ENV PIPX_HOME=/opt/pipx
ENV PIPX_BIN_DIR=/usr/local/bin
ENV PIP_DEFAULT_TIMEOUT=120
ENV PIP_RETRIES=10
RUN pipx install semgrep
RUN pipx install bandit
RUN pipx install checkov
RUN pipx install 'prowler<4'
# Round-3 discovery-osint additions:
# dnstwist for typo-squat detection, theHarvester for OSINT, masscan via apt.
RUN pipx install dnstwist
RUN pipx install theHarvester
RUN apt-get update && apt-get install -y --no-install-recommends masscan \
    && rm -rf /var/lib/apt/lists/*

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
