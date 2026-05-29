#!/usr/bin/env python3
"""Resolve a filesystem path for source-scanning executors.

If EXECUTOR_CONFIG_<PREFIX>_GIT_URL is set, the repo is shallow-cloned to a temp
directory (cleaned up at process exit) and that path is returned; private repos
authenticate with GIT_USERNAME / GIT_TOKEN. Otherwise EXECUTOR_CONFIG_<PREFIX>_TARGET
is returned unchanged. When both are set, TARGET is treated as a subpath inside
the clone (e.g. scan only `terraform/`).
"""

import atexit
import os
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlparse, urlunparse


def resolve_source_path(prefix: str) -> str:
    git_url = os.environ.get(f"EXECUTOR_CONFIG_{prefix}_GIT_URL")
    target = os.environ.get(f"EXECUTOR_CONFIG_{prefix}_TARGET")

    if not git_url:
        if not target:
            print(f"EXECUTOR_CONFIG_{prefix}_TARGET or EXECUTOR_CONFIG_{prefix}_GIT_URL is required", file=sys.stderr)
            sys.exit(1)
        return target

    ref = os.environ.get(f"EXECUTOR_CONFIG_{prefix}_GIT_REF")
    user = os.environ.get("GIT_USERNAME")
    token = os.environ.get("GIT_TOKEN")

    clone_url = git_url
    if token and git_url.startswith("https://"):
        parsed = urlparse(git_url)
        host = parsed.hostname + (f":{parsed.port}" if parsed.port else "")
        netloc = f"{user or 'oauth2'}:{token}@{host}"
        clone_url = urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))

    tmp = tempfile.mkdtemp(prefix=f"oc_{prefix.lower()}_")
    atexit.register(shutil.rmtree, tmp, ignore_errors=True)

    cmd = ["git", "clone", "--depth", "1"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [clone_url, tmp]

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        err = result.stderr
        if token:
            err = err.replace(token, "***")
        print(f"git clone of {git_url} failed: {err}", file=sys.stderr)
        sys.exit(1)

    return os.path.join(tmp, target) if target else tmp
