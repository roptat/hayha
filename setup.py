#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='hayha',
    version='1.0.0',
    description='Verify cloudformation templates to check for sniping attacks',
    long_description=open("README.md").read(),
    packages=find_packages(exclude=['tests']),
    entry_points={
        "console_scripts": [
            "hayha=hayha.main:cli"
        ]
    },
    python_requires='>=3.7',
    install_requires=[
        "pyyaml"
    ],
    classifiers=[
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Operating System :: Unix",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",

        "Development Status :: 4 - Beta"
    ],
    include_package_data=True,
    zip_safe=False,
    keywords=[
        'yaml', 'json', 'cloudformation', 'security'
    ]
)
