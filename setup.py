#!/usr/bin/env python3
"""
Setup script for IsItSecure? Password Security Scanner
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="isitsecure",
    version="1.0.0",
    author="Chris Mathew Aje",
    author_email="chrismaje63@gmail.com",
    description="A comprehensive password security scanner that analyzes strength and checks breach exposure",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/chrismat-05/IsItSecure",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "isitsecure=isitsecure.cli:main",
        ],
    },
    keywords="password security breach scanner cybersecurity privacy",
    project_urls={
        "Bug Reports": "https://github.com/chrismat-05/IsItSecure/issues",
        "Source": "https://github.com/chrismat-05/IsItSecure",
        "Documentation": "https://github.com/chrismat-05/IsItSecure#readme",
    },
    include_package_data=True,
    zip_safe=False,
)