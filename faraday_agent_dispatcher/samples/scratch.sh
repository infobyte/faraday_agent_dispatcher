#!/usr/bin/env bash

exec 3<&1
exec 1>&2

echo esto va a stderr
echo esto va a stdout >&3