FROM alpine:3.12.0 as GETTER

RUN apk update && \
    apk add --no-cache git wget tar


# Getting Sublist3r code
RUN git clone --depth 1 https://github.com/aboul3la/Sublist3r.git Sublist3r

# Getting arachni tar file (v1.5.1)
RUN mkdir ./temp
RUN mkdir ./arachni
RUN wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz \
        -O ./temp/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
RUN tar -xvzf ./temp/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz --directory ./arachni
RUN rm ./temp/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz


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
        openvas
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

# Getting arachni from GETTER
COPY --from=GETTER /arachni/arachni-1.5.1-0.5.12/ /usr/local/src/arachni
# Adding to env PATH
ENV PATH=${PATH}:/usr/local/src/arachni/bin
ENV OPENSSL_CONF=/etc/ssl/
ENV ARACHNI_PATH=/usr/local/src/arachni/bin

# Installing dependencies for Sublist3r
COPY --from=GETTER /Sublist3r/requirements.txt /usr/local/src/Sublist3r/requirements.txt
WORKDIR /usr/local/src/Sublist3r
RUN pip3 --no-cache install -r requirements.txt
# Getting Sublist3r from GETTER
COPY --from=GETTER /Sublist3r /usr/local/src/Sublist3r
# Adding to env PATH
ENV PATH=${PATH}:/usr/local/src/Sublist3r
RUN ln -s /usr/bin/python3 /usr/bin/python

# Installing wpscan
RUN gem install nokogiri
RUN gem install wpscan
# Updating wpscan
RUN wpscan --update
# Add nmap script vulners
RUN curl https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse --output  /usr/share/nmap/scripts/vulners.nse
# Installing Nuclei
RUN cd /usr/local/src && git clone https://github.com/projectdiscovery/nuclei.git --branch v2.9.15
RUN cd /usr/local/src/nuclei/v2/cmd/nuclei/ &&  go build && mv nuclei /usr/local/bin/ && nuclei -version
RUN cd /usr/local/src/nuclei/v2/cmd/nuclei/ && git clone https://github.com/projectdiscovery/nuclei-templates.git

# Setting default folder and bash for entrypoint
WORKDIR /home/
# ENTRYPOINT [ "/bin/bash" , "-l", "-c"]
