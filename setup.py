from setuptools import setup, find_packages

setup(
    name="covsaw",
    version="1.0.0",
    description="Classification Of cryptographic Vulnerabilies and Security Assesment of Web appilcations",
    author="Giorgos Nicolaides",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "requests>=2.28.0",
        "idna>=3.3"
    ],
    entry_points={
        "console_scripts": [
            "covsaw=covsaw.cli:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance"
    ],
)
