#!/usr/bin/env python3
from setuptools import find_packages, setup

with open("requirements.txt") as fh:
    requirements = [
        line.strip()
        for line in fh
        if line.strip() and not line.startswith("#")
    ]

with open("VERSION", encoding="utf-8") as fh:
    version = fh.read().strip()

setup(
    name="open-ai-grid-auth",
    version=version,
    description="Authentication service for Open AI Grid",
    author="Open AI Grid Contributors",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={"console_scripts": ["aig-auth=cli.main:cli"]},
    python_requires=">=3.10",
)
