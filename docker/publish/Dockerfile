ARG TAG=""
ARG REGISTRY="registry.gitlab.com/faradaysec/cloud"

#### Dispatcher builder ####
FROM python:3.13.7-slim AS dispatcher-build
ENV PYTHONUNBUFFERED=1

WORKDIR /app/

RUN python -m venv /opt/dispatcher_venv
ENV PATH="/opt/dispatcher_venv/bin:$PATH"
COPY . .
RUN pip install .

# --- Offensive Checks: vendor manifests + patch plugins into the venv ---
# The dispatcher only discovers tool manifests from the installed
# faraday_agent_parameters_types package, so copy the offensive-check
# manifests into its static/manifests dir (avoids a package release).
RUN apt-get update && apt-get install -y --no-install-recommends patch \
    && PARAM_DIR="$(python -c 'import os, faraday_agent_parameters_types.utils as u; print(os.path.join(os.path.dirname(u.__file__), "static", "manifests"))')" \
    && cp /app/offensive_checks/manifests/*.json "$PARAM_DIR/" \
    && PLUGINS_DIR="$(python -c 'import os, faraday_plugins; print(os.path.dirname(faraday_plugins.__file__))')" \
    && patch -p2 -d "$PLUGINS_DIR" < /app/offensive_checks/patches/faraday_plugins_offensive_fixes.patch \
    && rm -rf /var/lib/apt/lists/*

#### Final image ####
FROM ${REGISTRY}/faraday_agent_dispatcher:$TAG
COPY --from=dispatcher-build /opt/dispatcher_venv /opt/dispatcher_venv

ENV PATH="/opt/dispatcher_venv/bin:$PATH"

# ---------------------------------------------------------------------------
# Offensive Checks tool binaries
# Pinned versions; linux/amd64 (EKS corporate node-group).
# ---------------------------------------------------------------------------
ARG TARGETARCH=amd64
ARG TRIVY_VERSION=0.58.1
ARG GRYPE_VERSION=0.87.0
ARG GITLEAKS_VERSION=8.21.2
ARG TRUFFLEHOG_VERSION=3.88.0
ARG FFUF_VERSION=2.1.0
ARG NAABU_VERSION=2.3.3
ARG SUBFINDER_VERSION=2.6.7
ARG KUBESCAPE_VERSION=3.0.22
ARG KUBE_BENCH_VERSION=0.10.0
ARG TFSEC_VERSION=1.28.13
ARG KICS_VERSION=2.1.6

USER root

# System packages: shellcheck (SAST shell), node/npm (snyk), pipx (isolated py CLIs),
# plus libpcap for naabu and the usual download tooling.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git unzip tar xz-utils jq \
        shellcheck nodejs npm pipx libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Python CLI tools in isolated pipx envs (avoids clashing with the dispatcher venv).
ENV PIPX_HOME=/opt/pipx
ENV PIPX_BIN_DIR=/usr/local/bin
RUN pipx install semgrep \
    && pipx install bandit \
    && pipx install checkov \
    && pipx install prowler

# Snyk CLI (Node).
RUN npm install -g snyk && npm cache clean --force

# Go / release-binary tools (linux/${TARGETARCH}).
RUN set -eux; \
    cd /tmp; \
    # Trivy
    curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | tar -xz trivy && mv trivy /usr/local/bin/; \
    # Grype
    curl -sSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${TARGETARCH}.tar.gz" | tar -xz grype && mv grype /usr/local/bin/; \
    # Gitleaks
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz gitleaks && mv gitleaks /usr/local/bin/; \
    # TruffleHog
    curl -sSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TARGETARCH}.tar.gz" | tar -xz trufflehog && mv trufflehog /usr/local/bin/; \
    # ffuf
    curl -sSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${TARGETARCH}.tar.gz" | tar -xz ffuf && mv ffuf /usr/local/bin/; \
    # naabu
    curl -sSL -o naabu.zip "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${TARGETARCH}.zip" && unzip -o naabu.zip naabu && mv naabu /usr/local/bin/ && rm naabu.zip; \
    # subfinder
    curl -sSL -o subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${TARGETARCH}.zip" && unzip -o subfinder.zip subfinder && mv subfinder /usr/local/bin/ && rm subfinder.zip; \
    # kubescape
    curl -sSL -o /usr/local/bin/kubescape "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape-ubuntu-latest" && chmod +x /usr/local/bin/kubescape; \
    # kube-bench
    curl -sSL "https://github.com/aquasecurity/kube-bench/releases/download/v${KUBE_BENCH_VERSION}/kube-bench_${KUBE_BENCH_VERSION}_linux_${TARGETARCH}.tar.gz" | tar -xz kube-bench && mv kube-bench /usr/local/bin/; \
    # tfsec
    curl -sSL -o /usr/local/bin/tfsec "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-${TARGETARCH}" && chmod +x /usr/local/bin/tfsec; \
    # kics (needs its query packs; install under /opt and wrap)
    curl -sSL -o kics.tar.gz "https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/kics_${KICS_VERSION}_linux_x64.tar.gz" && mkdir -p /opt/kics && tar -xz -C /opt/kics -f kics.tar.gz && mv /opt/kics/kics /usr/local/bin/kics && rm kics.tar.gz; \
    chmod +x /usr/local/bin/*; \
    rm -rf /tmp/*

# kics resolves its query library relative to this path unless -q is passed.
ENV KICS_QUERIES_PATH=/opt/kics/assets/queries

ENTRYPOINT ["faraday-dispatcher", "run"]
