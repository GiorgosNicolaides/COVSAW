# setup.py

from setuptools import setup, find_packages

setup(
    name="cryptoanalyzer",
    version="0.1.0",
    description="Static analysis of cryptographic usage vulnerabilities",
    author="Giorgos Nicolaides",
    packages=find_packages(exclude=["tests", "examples", "docs"]),
    install_requires=[
        "toml",      # for config loading
        "PyYAML",    # if you want YAML support
    ],
    entry_points={
        "console_scripts": [
            "cryptoanalyzer=cryptoanalyzer.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires=">=3.8",
)
