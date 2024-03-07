#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""The setup script."""

from re import search
from setuptools import setup, find_packages

with open("faraday_agent_dispatcher/__init__.py", "rt", encoding="utf8") as f:
    version = search(r"__version__ = \"(.*?)\"", f.read()).group(1)

with open("README.md") as readme_file:
    readme = readme_file.read()

with open("RELEASE.md") as history_file:
    history = history_file.read()


requirements = [
    "Click>=7",
    "websockets",
    "aiohttp",
    "syslog_rfc5424_formatter",
    "requests",
    "itsdangerous",
    "faraday-plugins>=1.16.0",
    "python-owasp-zap-v2.4",
    "python-gvm",
    "faraday_agent_parameters_types>=1.4.0",
    "pyyaml",
    "psutil",
    "pytenable",
    "python-socketio==5.8.0",
]

setup_requirements = ["pytest-runner", "click", "setuptools_scm"]

extra_req = {
    "dev": ["giteasychangelog", "flake8", "pre-commit", "black"],
    "test": [
        "pytest",
        "pytest-cov",
        "pytest-asyncio==0.18.3",
    ],
    "docs": [
        "mkdocs",
        "mkdocs-material",
    ],
}

setup(
    author="Faraday Development Team",
    author_email="devel@infobytesec.com",
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    description="Faraday agent dispatcher to communicate an agent to faraday",
    entry_points={
        "console_scripts": [
            "faraday-dispatcher=faraday_agent_dispatcher.cli.main:cli",
        ],
    },
    install_requires=requirements,
    extras_require=extra_req,
    license="GNU General Public License v3",
    long_description=readme + "\n\n" + history,
    long_description_content_type="text/markdown",
    include_package_data=True,
    keywords="faraday integration",
    name="faraday_agent_dispatcher",
    packages=find_packages(include=["faraday_agent_dispatcher", "faraday_agent_dispatcher.*"]),
    setup_requires=setup_requirements,
    url="https://github.com/infobyte/faraday_agent_dispatcher",
    version=version,
    zip_safe=False,
)
