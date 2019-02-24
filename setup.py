#!/usr/bin/env python3.6

import os
import sys

try:
    from setuptools import setup, find_packages
except ImportError:
    print("Please install setuptools.")
    sys.exit(1)

if sys.version_info < (3, 6):
    sys.exit("Sorry, Python < 3.6 is not supported")

version_raw = os.environ.get("VERSION", None)
if version_raw is None:
    version_raw = open("VERSION").read()

version = version_raw.split("-")

pypi_version = version[0] + "+" + ".".join(version[1:])

print("Setting package version to:", pypi_version.strip())

setup(
    name="teg-aws",
    version=pypi_version,
    description="TEG AWS Tools",
    author="Will Rouesnel",
    author_email="william.rouesnel@ticketek.com.au",
    url="",
    install_requires=["structlog","keyring","pytz","ruamel.yaml","click","pyrfc3339", "pyotp","awscli"],
    packages=find_packages("."),
    package_data={"": ["VERSION"]},
    entry_points={"console_scripts": ["teg-aws=teg_aws.__main__:main"]},
)
