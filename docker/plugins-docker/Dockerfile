#### Golang tools builder ####
FROM golang:latest AS go-tools
WORKDIR /app
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

#### main tools ####
FROM kalilinux/kali-rolling AS final

# openvas pulls systemd, whose postinst fails on sandboxed CI runners with
# EUNATCH ("Protocol driver not attached") when it runs systemctl and
# systemd-machine-id-setup. Divert systemctl to a no-op (the diversion survives
# the systemd package unpack), block service auto-start via policy-rc.d, and
# pre-seed a valid machine-id so dpkg can configure systemd during the install.
RUN dpkg-divert --local --rename --add /usr/bin/systemctl \
 && ln -sf /bin/true /usr/bin/systemctl \
 && printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
 && chmod 0755 /usr/sbin/policy-rc.d \
 && tr -d '-' < /proc/sys/kernel/random/uuid > /etc/machine-id
ENV SYSTEMD_OFFLINE=1

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
