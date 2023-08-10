FROM kalilinux/kali-rolling as FINAL

RUN groupadd -r user && useradd -r -g user faraday_user

# Updating repos
RUN apt-get update && \
# Installing packages
    apt-get install --yes --no-install-recommends \
        build-essential git \
        # Python
        python3 python3-pip python3-venv python3-setuptools\
        # Dependencies for w3af
        libxml2 \
        libxslt-dev \
        libssl-dev \
        npm \
        # Go
        golang \
        # Installing Nikto
        nikto \
        # Installing Nmap
        nmap \
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
        chromium
# Clean commands
RUN rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt && \
    apt-get purge --auto-remove --yes && \
    apt-get clean

RUN npm install -g retire@2.0.3
RUN git clone https://github.com/andresriancho/w3af.git /usr/local/src/w3af
# Installing CrackMapExec
RUN pip3 install pipx
RUN pipx ensurepath
ENV PIPX_BIN_DIR=/usr/local/bin
RUN pipx install crackmapexec
RUN mkdir /usr/local/src/arachni
# Getting arachni latest release
RUN arachniTarUrl=$(curl -s https://api.github.com/repos/Arachni/arachni/releases/latest | tr ',' '\n' | grep browser_download_url | grep 'linux-x86_64.tar.gz\"' | cut -d\" -f4) && \
    fileName="${arachniTarUrl##*/}" && \
    echo "Downloading Arachni from Github: $arachniTarUrl" && \
    curl -L $arachniTarUrl -o $fileName && \
    tar -xvzf $fileName -C /usr/local/src/arachni --strip-components 1

# Adding to env PATH
ENV PATH=${PATH}:/usr/local/src/arachni/bin
ENV OPENSSL_CONF=/etc/ssl/
ENV ARACHNI_PATH=/usr/local/src/arachni/bin

# Installing wpscan
RUN gem install nokogiri
RUN gem install wpscan
# Updating wpscan
RUN wpscan --update
# Add nmap script vulners
RUN curl https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse --output  /usr/share/nmap/scripts/vulners.nse
# Installing Nuclei
RUN cd /usr/local/src && git clone https://github.com/projectdiscovery/nuclei.git
RUN cd /usr/local/src/nuclei/v2/cmd/nuclei/ &&  go build && mv nuclei /usr/local/bin/ && nuclei -version
RUN cd /usr/local/src/nuclei/v2/cmd/nuclei/ && git clone https://github.com/projectdiscovery/nuclei-templates.git

# Setting default folder and bash for entrypoint
WORKDIR /home/
# ENTRYPOINT [ "/bin/bash" , "-l", "-c"]
