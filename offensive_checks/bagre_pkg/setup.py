"""Install the vendored bagre threat-intelligence package into the dispatcher venv.

This is a thin packaging shim around the upstream bagre source vendored at
`bagre/`. The executors under `static/executors/official/bagre*.py` import
from this package (`from bagre.config import load_config`, etc.).
"""
from setuptools import setup, find_packages

setup(
    name="bagre-agent",
    version="1.1.0",
    description="Bagre threat-intelligence credential lookup + password spray (vendored)",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "tldextract>=5.0.0",
        "clickhouse-driver>=0.2.6",
        "paramiko>=3.0.0",
        "smbprotocol>=1.10.1",
    ],
    python_requires=">=3.8",
)
