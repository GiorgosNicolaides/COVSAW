# setup.py

from setuptools import setup, find_packages

setup(
    name="cryptoanalyzer",
    version="2.0.0",
    description="Static analysis of cryptographic usage vulnerabilities in Python code",
    author="Giorgos Nicolaides",
    packages=find_packages(exclude=["tests", "examples", "docs"]),
    install_requires=[
        "toml>=0.10.2",      # TOML config loading
        "PyYAML>=6.0",       # YAML config loading
        "colorama>=0.4.6",   # colored terminal banner output
    ],
    extras_require={
        "dev": ["pytest>=7.0", "black>=23.0", "flake8>=6.0"],
    },
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
