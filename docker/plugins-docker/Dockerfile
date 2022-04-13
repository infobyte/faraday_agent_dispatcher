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
RUN python3 -m pip install -U pip
run apt-get install --yes  python-pip python2.7 python2.7-dev && \
# Clean commands
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt && \
    apt-get purge --auto-remove --yes && \
    apt-get clean
RUN python2.7 -m pip install -U --force pip
RUN python2.7 -m pip install setuptools-git==1.1 pyClamd==0.4.0 PyGithub==1.21.0 GitPython==2.1.15 \
        pybloomfiltermmap==0.3.14 esmre==0.3.1 phply==0.9.1 nltk==3.0.1 chardet==3.0.4 \
        pdfminer==20140328 futures==3.2.0 pyOpenSSL==18.0.0 scapy==2.4.0 guess-language==0.2 \
        cluster==1.1.1b3 msgpack-python==0.5.6 python-ntlm==1.0.1 halberd==0.2.4 \
        darts.util.lru==0.5 ndg-httpsclient==0.4.0 pyasn1==0.4.2 Jinja2==2.10 vulndb==0.1.1 \
        markdown==2.6.1 psutil==5.4.8 Tornado==4.5 mitmproxy==0.13 ruamel.ordereddict==0.4.8 \
        Flask==0.10.1 PyYAML==3.12 ds-store==1.1.2 termcolor==1.1.0 tldextract==1.7.2 pebble==4.3.8 \
        acora==2.1 diff-match-patch==20121119 bravado-core==5.15.0 lz4==1.1.0 vulners==1.3.0 \
        tblib==0.2.0 lxml==3.4.4 msgpack==0.5.6 subprocess32==3.5.4 ipaddresses==0.0.2
RUN npm install -g retire@2.0.3
RUN git clone https://github.com/andresriancho/w3af.git /usr/local/src/w3af

# Installing CrackMapExec
RUN python3 -m pip install pipx
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

# Installing Nuclei
RUN cd /usr/local/src && git clone https://github.com/projectdiscovery/nuclei.git
RUN cd /usr/local/src/nuclei/v2/cmd/nuclei/ &&  go build && mv nuclei /usr/local/bin/ && nuclei -version
RUN cd /usr/local/src/nuclei/v2/cmd/nuclei/ && git clone https://github.com/projectdiscovery/nuclei-templates.git

# Setting default folder and bash for entrypoint
WORKDIR /home/
# ENTRYPOINT [ "/bin/bash" , "-l", "-c"]
