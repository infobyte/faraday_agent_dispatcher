#!/usr/bin/env bash

set -e

die(){
    echo $1 >/dev/stderr
    exit 1
}

which sublist3r.py >/dev/null 2>/dev/null || \
  die "sublist3r.py binary not found. Add sublist3r directory to $PATH or sublist3r.py file to /usr/bin. Aborting"

if [[ -z "${EXECUTOR_CONFIG_DOMAIN}" ]]; then
    die "Domain not defined. Please define the EXECUTOR_CONFIG_DOMAIN environment variable"
fi

OUTPUT_FILE="$(mktemp)"

sublist3r.py -d "${EXECUTOR_CONFIG_DOMAIN}" -o "${OUTPUT_FILE}" >/dev/stderr

resolve_domains(){
    while read domain
    do
        ip="$(getent hosts "${domain}" | awk '{ print $1 }' | head -n1)"
        if [[ "$ip" ]]
        then
            echo "${ip},${domain}"
        fi
    done
}

cat "${OUTPUT_FILE}" | resolve_domains | jq -Rc '{hosts: [{ip: (. | split(",") | .[0]), description: "Discovered using Sublist3r", hostnames: [(. | split(",") | .[1])]}]}'

rm $OUTPUT_FILE
