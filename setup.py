#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = ['Click>=6.0', ]

setup_requirements = ['pytest-runner', 'click', 'requests', 'syslog_rfc5424_formatter']

test_requirements = ['pytest', ]

setup(
    author="Eric Horvat",
    author_email='erich@infobytesec.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    description="Faraday agent dispatcher to communicate an agent to faraday",
    entry_points={
        'console_scripts': [
            'dispatcher=faraday_agent_dispatcher.cli:main',
        ],
    },
    install_requires=requirements,
    license="GNU General Public License v3",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='',
    name='faraday_agent_dispatcher',
    packages=find_packages(include=['faraday_agent_dispatcher', 'faraday_agent_dispatcher.*']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/EricHorvat/faraday_agent_dispatcher',
    version='0.1.0',
    zip_safe=False,
)
