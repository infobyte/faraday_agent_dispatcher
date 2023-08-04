ARG TAG=faraday-agent-dispatcher
FROM registry.gitlab.com/faradaysec/cloud/faraday_agent_dispatcher:tools

WORKDIR /home/faraday_user/src/faraday_agent_dispatcher
RUN mkdir /home/faraday_user/.faraday

RUN chown -R faraday_user:user /usr/local/src/arachni/
RUN chown -R faraday_user:user /usr/local/src/nuclei/
RUN chown -R faraday_user:user /usr/local/src/w3af/
RUN chown -R faraday_user:user /home/faraday_user/
ENV PATH=${PATH}:/home/faraday_user/.local/bin

USER faraday_user

COPY ./faraday_agent_dispatcher/ /home/faraday_user/src/faraday_agent_dispatcher/faraday_agent_dispatcher
COPY ./setup.py /home/faraday_user/src/faraday_agent_dispatcher/setup.py
COPY ./README.md /home/faraday_user/src/faraday_agent_dispatcher/README.md
COPY ./RELEASE.md /home/faraday_user/src/faraday_agent_dispatcher/RELEASE.md
COPY ./MANIFEST.in /home/faraday_user/src/faraday_agent_dispatcher/MANIFEST.in

RUN pip3 install . --user --use-pep517

ENTRYPOINT ["faraday-dispatcher", "run"]