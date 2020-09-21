FROM alpine:3.12.0 as BUILDER

RUN apk update && \
    apk add --no-cache git wget tar 

# Getting nikto2 code
RUN git clone https://github.com/sullo/nikto.git nikto2

# Getting Sublist3r code
RUN git clone https://github.com/aboul3la/Sublist3r.git Sublist3r

# Getting arachni tar file (v1.5.1) 
RUN mkdir ./arachni
RUN wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz \
        -O ./arachni/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz  
RUN tar -xvzf ./arachni/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz --directory ./arachni 
RUN rm ./arachni/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz

# Getting CrackMapExec code
RUN git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec CrackMapExec


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
        # Installing openvas
        openvas && \
# Clean commands
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt && \
    apt-get purge --auto-remove && \
    apt-get clean
        
# Getting nikto from BUILDER
COPY --from=BUILDER /nikto2/program /usr/bin/nikto2
# Installing perl modules for nikto2
RUN cpan -i install Time::Local Net::hostent TIME::HiRes \
    # For SSL support
    Net::SSLeay

# Installing dependencies for Sublist3r 
COPY --from=BUILDER /Sublist3r/requirements.txt /usr/bin/Sublist3r/requirements.txt
WORKDIR /usr/bin/Sublist3r
RUN pip3 --no-cache install -r requirements.txt
# Getting Sublist3r from BUILDER
COPY --from=BUILDER /Sublist3r /usr/bin/Sublist3r

# Getting arachni from BUILDER
COPY --from=BUILDER /arachni/arachni-1.5.1-0.5.12/ /usr/bin/arachni

# Getting CrackMapExec from BUILDER
COPY --from=BUILDER /CrackMapExec /usr/bin/CrackMapExec
# Installing CrackMapExec
WORKDIR /usr/bin/CrackMapExec
RUN python3 setup.py install
# Configure first run
RUN cme --help 

# Installing wpscan
RUN gem install nokogiri
RUN gem install wpscan
# Updating wpscan
RUN wpscan --update

# @TODO configure openvas

# Setting default folder and bash for entrypoint
WORKDIR /home/
ENTRYPOINT [ "/bin/bash" ]