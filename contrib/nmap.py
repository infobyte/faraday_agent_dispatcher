#!/usr/bin/env python
import os
import subprocess

"""Yo need to clone and install faraday plugins"""
from faraday_plugins.plugins.repo.nmap.plugin import NmapPlugin

cmd = [
    "nmap",
    "-p{}".format(os.environ.get('PORT_LIST')),
    os.environ.get('TARGET'),
    "-oX",
    "-",
]


results = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
nmap = NmapPlugin()
nmap.parseOutputString(results.stdout)
print(nmap.get_json())
