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

import sys
from re import search
from setuptools import setup, find_packages

if sys.version_info.major < 3 or sys.version_info.minor < 7:
    print("Python >=3.7 is required to run the dispatcher.")
    print("Install a newer Python version to proceed")
    sys.exit(1)


with open('faraday_agent_dispatcher/__init__.py', 'rt', encoding='utf8') as f:
    version = search(r'__version__ = \'(.*?)\'', f.read()).group(1)

with open('README.md') as readme_file:
    readme = readme_file.read()

with open('RELEASE.md') as history_file:
    history = history_file.read()


requirements = [
    'Click',
    'websockets',
    'aiohttp',
    'syslog_rfc5424_formatter',
    'requests',
    'itsdangerous',
    'faraday-plugins',
    'python-owasp-zap-v2.4',
]

setup_requirements = ['pytest-runner', 'click', 'setuptools_scm']

extra_req = {
        'dev': [
            'giteasychangelog',
            'flake8',
            'pre-commit',
        ],
        'test': [
            'pytest',
            'pytest-cov',
            'pytest-asyncio',
        ],
        'docs': [
            'mkdocs',
            'mkdocs-material',
        ]
    }

setup(
    author="Eric Horvat",
    author_email='erich@infobytesec.com',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    description="Faraday agent dispatcher to communicate an agent to faraday",
    entry_points={
        'console_scripts': [
            'faraday-dispatcher=faraday_agent_dispatcher.cli.main:cli',
        ],
    },
    install_requires=requirements,
    extras_require=extra_req,
    license="GNU General Public License v3",
    long_description=readme + '\n\n' + history,
    long_description_content_type='text/markdown',
    include_package_data=True,
    keywords='faraday integration',
    name='faraday_agent_dispatcher',
    packages=find_packages(
        include=['faraday_agent_dispatcher', 'faraday_agent_dispatcher.*']
    ),
    use_scm_version=False,
    setup_requires=setup_requirements,
    url='https://github.com/infobyte/faraday_agent_dispatcher',
    version=version,
    zip_safe=False,
)
