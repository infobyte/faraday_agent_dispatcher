#### Dispatcher builder ####
FROM python:3.13.7-slim AS dispatcher-build
ENV PYTHONUNBUFFERED=1

WORKDIR /app/

RUN python -m venv /opt/dispatcher_venv
ENV PATH="/opt/dispatcher_venv/bin:$PATH"
COPY . .
RUN pip install .

#### Final image ####
ARG TAG=tools
ARG BASE_IMAGE_TAG=tools
ARG REGISTRY=registry.gitlab.com/faradaysec/cloud
#FROM ${REGISTRY}/faraday_agent_dispatcher:$TAG
FROM registry.gitlab.com/faradaysec/cloud/faraday_agent_dispatcher:$BASE_IMAGE_TAG
COPY --from=dispatcher-build /opt/dispatcher_venv /opt/dispatcher_venv

ENV PATH="/opt/dispatcher_venv/bin:$PATH"
ENTRYPOINT ["faraday-dispatcher", "run"]
