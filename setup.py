from setuptools import setup, find_packages
from pathlib import Path

# Read the long description from your README
long_description = Path(__file__).parent.joinpath("README.md").read_text()

setup(
    name='covsaw',
    version='1.0.0',
    description='Classification Of Cryptographic Vulnerabilities and Security Assessment of Web Applications',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Giorgos Nicolaides',
    author_email='you@example.com',
    url='https://github.com/yourusername/covsaw',

    # Automatically find your package and subpackages
    packages=find_packages(),

    # Runtime dependencies
    install_requires=[
        'cryptography>=3.4',
        'requests>=2.25',
        'toml>=0.10.0',
        'colorama>=0.4.0',
    ],
    # Optional dependencies for development
    extras_require={
        'dev': [
            'pytest>=6.0',
            'pytest-sslserver',
            'flake8',
        ],
    },

    # Define console entry point for the CLI
    entry_points={
        'console_scripts': [
            'covsaw=covsaw.cli:main',
        ],
    },

    include_package_data=True,
    zip_safe=False,
    python_requires='>=3.6',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
