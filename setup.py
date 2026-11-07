#!/usr/bin/env python3
"""
WebSentry - Web Server Security Assessment Tool
Developer: Isha Sonaria
GitHub: https://github.com/ishasonaria568-prog
"""

from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (
    (this_directory / "README.md").read_text(encoding="utf-8")
    if (this_directory / "README.md").exists()
    else "WebSentry - Web Server Security Assessment Tool"
)

setup(
    name="websentry",
    version="1.2.0",
    author="Isha Sonaria",
    author_email="ishasonaria568@gmail.com",
    description="Professional CLI-based web server security scanner inspired by Nikto.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ishasonaria568-prog/websentry",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "websentry": ["signatures/*.json"],
        "websentry.signatures": ["*.json"],
    },
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "websentry=websentry.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    keywords="security, scanner, vulnerability-scanner, nikto, audit, web-security",
)
