FROM kalilinux/kali-rolling as FINAL

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
        chromium \
        pkg-config \
        python3-dev
# Clean commands
RUN rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt && \
    apt-get purge --auto-remove --yes && \
    apt-get clean

#Install w4af
RUN npm install -g retire@2.0.3
RUN git clone https://github.com/w4af/w4af.git /usr/local/src/w4af
# Installing CrackMapExec
RUN pip3 install pipx
RUN pipx ensurepath
ENV PIPX_BIN_DIR=/usr/local/bin
RUN mkdir /usr/local/src/arachni
# Getting arachni latest release
RUN arachniTarUrl=$(curl -s https://api.github.com/repos/Arachni/arachni/releases/latest | tr ',' '\n' | grep browser_download_url | grep 'linux-x86_64.tar.gz\"' | cut -d\" -f4) && \
    fileName="${arachniTarUrl##*/}" && \
    curl -L $arachniTarUrl -o $fileName && \
    tar -xvzf $fileName -C /usr/local/src/arachni --strip-components 1

# Installing wpscan
RUN gem install nokogiri
RUN gem install wpscan
# Updating wpscan
RUN wpscan --update
# Add nmap script vulners
RUN curl https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse --output  /usr/share/nmap/scripts/vulners.nse
# Installing Nuclei
RUN cd /usr/local/src && git clone https://github.com/projectdiscovery/nuclei.git
RUN cd /usr/local/src/nuclei/cmd/nuclei/ &&  go build && mv nuclei /usr/local/bin/ && nuclei -version
RUN cd /usr/local/src/nuclei/cmd/nuclei/ && git clone https://github.com/projectdiscovery/nuclei-templates.git

RUN useradd -m -s /bin/bash faraday && \
    echo 'faraday:faraday' | chpasswd && \
    usermod -aG sudo faraday

RUN ln -s /usr/bin/python3 /usr/bin/python

# Set the home directory ownership to the new user
RUN mkdir -p /home/faraday/.faraday/logs
RUN git clone https://github.com/w4af/HTTPretty.git /usr/local/src/utils/HTTPretty
RUN git clone https://github.com/w4af/mitmproxy.git /usr/local/src/utils/mitmproxy
RUN git clone https://github.com/w4af/netlib.git /usr/local/src/utils/netlib
RUN git clone https://github.com/w4af/vulndb-python-sdk.git /usr/local/src/utils/vulndb-python-sdk
RUN git clone https://github.com/w4af/DartsPyLRU.git /usr/local/src/utils/DartsPyLRU
RUN chown -R faraday:faraday /usr/local/
ENV PATH=${PATH}:/home/faraday/.local/bin
# Switch to the 'faraday' user
USER faraday

RUN pip3 install /usr/local/src/utils/HTTPretty/
RUN pip3 install /usr/local/src/utils/mitmproxy/
RUN pip3 install /usr/local/src/utils/netlib/
RUN pip3 install /usr/local/src/utils/vulndb-python-sdk/
RUN pip3 install /usr/local/src/utils/DartsPyLRU/
COPY ./requierments_w4af.txt /usr/local/src/requierments_w4af.txt
RUN pip3 install -r /usr/local/src/requierments_w4af.txt

# Setting default folder and bash for entrypoint
WORKDIR /home/
# ENTRYPOINT [ "/bin/bash" , "-l", "-c"]
