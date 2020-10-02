FROM alpine:3.12.0 as GETTER

RUN apk update && \
    apk add --no-cache git wget tar 

# Getting nikto2 code
RUN git clone https://github.com/sullo/nikto.git nikto2

# Getting Sublist3r code
RUN git clone https://github.com/aboul3la/Sublist3r.git Sublist3r

# Getting arachni tar file (v1.5.1) 
RUN mkdir ./temp
RUN mkdir ./arachni
RUN wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz \
        -O ./temp/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz  
RUN tar -xvzf ./temp/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz --directory ./arachni 
RUN rm ./temp/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz

# Getting CrackMapExec code
RUN git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec CrackMapExec

# Getting OpenVas
RUN git clone https://github.com/greenbone/openvas.git OpenVas
RUN git clone https://github.com/greenbone/gvm-libs.git gvmLibs
# Needs cmake to compile openvas
RUN mkdir ./cmake
RUN wget https://github.com/Kitware/CMake/releases/download/v3.18.3/cmake-3.18.3.tar.gz \
        -O ./temp/cmake-3.18.3.tar.gz
RUN tar -xvzf ./temp/cmake-3.18.3.tar.gz --directory ./cmake         
RUN rm ./temp/cmake-3.18.3.tar.gz


FROM kalilinux/kali-rolling as FINAL

# Updating repos
RUN apt-get update && \ 
# Installing packages
    apt-get install --yes --no-install-recommends \ 
        build-essential \
        # Python
        python3.8 python3-pip \
        # Installing Nmap 
        nmap \
        # Ruby for wpscan (nokogiri and misc prerequisites)
        ruby-full ruby-dev curl patch zlib1g-dev liblzma-dev \
        # cpan for perl 
        libpath-tiny-perl \
        # libs for wpscan
        libffi-dev \
        # SSL Support for nikto
        libnet-ssleay-perl \
        # Deps for openvas
        gcc pkg-config libssh-gcrypt-dev libgnutls28-dev libglib2.0-dev libpcap-dev libgpgme-dev bison libksba-dev libsnmp-dev libgcrypt20-dev redis-server rsync \
        # Deps for gvm libs
        libgnutls28-dev uuid-dev libldap2-dev libhiredis-dev libxml2-dev libradcli-dev && \
# Clean commands
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt && \
    apt-get purge --auto-remove && \
    apt-get clean
        
# Getting nikto from GETTER
COPY --from=GETTER /nikto2/program /usr/local/src/nikto2
# Installing perl modules for nikto2
RUN cpan -i install Time::Local Net::hostent TIME::HiRes \
    # For SSL support
    Net::SSLeay

# Installing dependencies for Sublist3r 
COPY --from=GETTER /Sublist3r/requirements.txt /usr/local/src/Sublist3r/requirements.txt
WORKDIR /usr/local/src/Sublist3r
RUN pip3 --no-cache install -r requirements.txt
# Getting Sublist3r from GETTER
COPY --from=GETTER /Sublist3r /usr/local/src/Sublist3r

# Getting arachni from GETTER
COPY --from=GETTER /arachni/arachni-1.5.1-0.5.12/ /usr/local/src/arachni

# Getting CrackMapExec from GETTER
COPY --from=GETTER /CrackMapExec /usr/local/src/CrackMapExec
# Installing CrackMapExec
WORKDIR /usr/local/src/CrackMapExec
RUN pip install poetry
RUN poetry install
# Configure first run
RUN poetry run crackmapexec --help

# Installing wpscan
RUN gem install nokogiri
RUN gem install wpscan
# Updating wpscan
RUN wpscan --update

# Getting openvas from GETTER
COPY --from=GETTER /OpenVas /usr/local/src/OpenVas
# Compiling cmake for openvas
COPY --from=GETTER /cmake/cmake-3.18.3 /usr/local/src/cmake
WORKDIR /usr/local/src/cmake
RUN ./bootstrap
RUN make
RUN make install
# Compiling gvm libs for openvas
COPY --from=GETTER /gvmLibs /usr/local/src/gvmLibs
WORKDIR /usr/local/src/gvmLibs
RUN cmake .
RUN make install
# Compiling openvas
WORKDIR /usr/local/src/OpenVas
RUN cmake .
RUN make install
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
# Configuring redis for openvas
RUN cp config/redis-openvas.conf /etc/redis/
RUN chown redis:redis /etc/redis/redis-openvas.conf
RUN mkdir /etc/openvas
RUN echo "db_address = /run/redis-openvas/redis.sock" > /etc/openvas/openvas.conf
RUN service redis-server start
# Get collection of Network Vulnerability Tests (NVTs), needs non root users
RUN groupadd -r non-root && useradd --no-log-init -r -g non-root non-root
USER non-root
RUN greenbone-nvt-sync
USER root

# Setting default folder and bash for entrypoint
WORKDIR /home/
ENTRYPOINT [ "/bin/bash" ]