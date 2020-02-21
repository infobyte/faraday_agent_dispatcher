#!/usr/bin/env bash

# 16.30 - 1730
# 1945 - 20:05
# 21.05 -

source /home/blas/.virtualenvs/w3af/bin/activate
cd /home/blas/Desarrollos/w3af
exec ./w3af_console -s /home/blas/Desarrollos/faraday_agent_dispatcher/contrib/config_report_file.w3af
