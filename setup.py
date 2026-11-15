#!/usr/bin/env python3
# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import os
import codecs
from setuptools import setup, find_packages


def read(fname):
    file_path = os.path.join(os.path.dirname(__file__), fname)
    return codecs.open(file_path, encoding="utf-8").read()


setup(
    name="pytest-client-tools",
    version="0.0.1",
    author="Pino Toscano",
    author_email="ptoscano@redhat.com",
    maintainer="Pino Toscano",
    maintainer_email="ptoscano@redhat.com",
    license="MIT",
    url="https://github.com/RedHatInsights/pytest-client-tools",
    description="pytest plugin to test RHSM client tools",
    long_description=read("README.md"),
    py_modules=["pytest_client_tools"],
    packages=find_packages(where="."),
    python_requires=">=3.6",
    install_requires=[
        "dataclasses;python_version<'3.7'",
        "dynaconf>=3.2.13,<4; python_version >= '3.8'",
        "dynaconf>=3.1.5,<3.2; python_version < '3.8'",
        "pytest>=4",
        "requests",
        "toml",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Framework :: Pytest",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Testing",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
    ],
    entry_points={
        "pytest11": [
            "client-tools = pytest_client_tools.plugin",
        ],
    },
)
