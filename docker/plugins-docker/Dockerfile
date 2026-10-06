#### Golang tools builder ####
FROM golang:latest AS go-tools
WORKDIR /app
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

#### main tools ####
# kali-last-release is a less-volatile tag than kali-rolling (snapshot of the
# latest periodic cut), but its apt suite still tracks rolling and ships
# systemd 260.1-1, whose postinst aborts inside an unprivileged Docker build.
# We therefore neuter both halves of the failing postinst before apt-get install:
#   1. policy-rc.d=101 makes the postinst's systemctl-enable calls a no-op
#      during dpkg configure (kills the "Failed to enable units" path).
#   2. dpkg-divert + /bin/true stub for systemd-machine-id-setup makes the
#      postinst's open('/etc/machine-id', O_RDWR|O_NOFOLLOW) call never happen,
#      sidestepping the EUNATCH (49) "Protocol driver not attached" error that
#      the shell runner's overlayfs/seccomp returns on that specific syscall.
# dpkg-divert uses --no-rename because the file does not exist yet — the divert
# is registered up-front so when systemd unpacks, dpkg writes the real binary
# to .distrib and the postinst's call resolves to our /bin/true stub instead.
FROM kalilinux/kali-last-release AS final

RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
 && chmod +x /usr/sbin/policy-rc.d \
 && dpkg-divert --local --no-rename --add /usr/sbin/systemd-machine-id-setup \
 && ln -s /bin/true /usr/sbin/systemd-machine-id-setup

RUN apt-get update -y && apt-get install --yes --no-install-recommends \
        build-essential git \
        python3 python3-pip python3-venv python3-setuptools \
        # Installing Nikto
        nikto \
        # Installing Nmap
        nmap \
        # Installing CrackMapExec \
        crackmapexec \
        # Needs for sublist3r
        jq \
        # Ruby for wpscan (nokogiri and misc prerequisites)
        ruby-full ruby-dev curl patch zlib1g-dev liblzma-dev \
        # cpan for perl
        libpath-tiny-perl \
        # libs for wpscan
        libffi-dev \
        # openvas
        openvas \
        # libs for arachni
        tar \
        chromium \
        pkg-config \
        python3-dev


# Clean commands
RUN rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt && \
    apt-get purge --auto-remove --yes && \
    apt-get clean

# Adding to env PATH for arachni
ENV PATH=${PATH}:/usr/local/src/arachni/bin
ENV OPENSSL_CONF=/etc/ssl/
ENV ARACHNI_PATH=/usr/local/src/arachni/bin

RUN mkdir /usr/local/src/arachni
RUN curl -L https://github.com/Arachni/arachni/releases/download/v1.6.1.3/arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz --output arachni.tar.gz
RUN tar -xvzf arachni.tar.gz -C /usr/local/src/arachni --strip-components 1
RUN rm -f arachni.tar.gz

# Installing wpscan
RUN gem install nokogiri
RUN gem install wpscan
RUN wpscan --update

# Add nmap script vulners
RUN curl https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse --output  /usr/share/nmap/scripts/vulners.nse

# Go related tools
COPY --from=go-tools /go/bin/nuclei /usr/local/bin/.

# Symbolic link for dispatcher venv python
RUN ln -s /usr/bin/python3 /usr/local/bin/python
