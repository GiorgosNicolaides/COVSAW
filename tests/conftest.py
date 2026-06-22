"""Shared pytest fixtures for the CryptoAnalyzer test suite."""

import os

import pytest

from cryptoanalyzer.analyzer import Analyzer
from cryptoanalyzer.config import Config

# Absolute path to the bundled deliberately-vulnerable demo file.
SAMPLE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "examples",
    "vulnerable_sample.py",
)


@pytest.fixture(scope="session")
def analyzer():
    """Return a single Analyzer instance with default configuration."""
    return Analyzer(Config())


@pytest.fixture(scope="session")
def sample_findings(analyzer):
    """Return the findings produced by scanning the bundled vulnerable sample."""
    return analyzer.analyze_file(SAMPLE_FILE)
