# cryptoanalyzer/loader.py

"""
Helpers for discovering Python source files and parsing them into ASTs,
respecting exclude patterns from configuration.
"""

import os
import glob
import fnmatch
import ast
from typing import List

from cryptoanalyzer.config import Config
from cryptoanalyzer.utils.logger import get_logger
from cryptoanalyzer.utils.file_utils import is_python_file, list_files_with_extension

LOG = get_logger(__name__)


def load_config(config_path: str = None) -> Config:
    """
    Load CryptoAnalyzer configuration from the given path or by discovery.
    """
    LOG.debug("Loading config from %s", config_path)
    return Config.load(config_path)


def discover_source_files(target: str, config: Config = None) -> List[str]:
    """
    Return a sorted list of Python (.py) files under `target`, filtered
    by `config.exclude_patterns`.

    :param target: File path, directory, or glob pattern
    :param config: Config specifying exclude_patterns
    :return: List of .py file paths to analyze
    """
    config = config or load_config()
    excludes = config.exclude_patterns or []
    LOG.debug("Exclude patterns: %s", excludes)

    # 1) Expand glob patterns
    if any(c in target for c in ("*", "?", "[")):
        LOG.debug("Treating target as glob: %s", target)
        paths = glob.glob(target, recursive=True)
    elif is_python_file(target):
        LOG.debug("Target is a single Python file: %s", target)
        paths = [target]
    else:
        # Walk the directory for .py files
        LOG.debug("Walking directory for .py files: %s", target)
        paths = list_files_with_extension(target, ".py", recursive=True, exclude_patterns=excludes)

    # 2) Filter to existing .py files and apply excludes
    result = []
    for p in paths:
        if not is_python_file(p):
            continue
        excluded = any(fnmatch.fnmatch(p, pat) for pat in excludes)
        if excluded:
            LOG.debug("Excluding path (matched pattern): %s", p)
            continue
        result.append(p)

    LOG.debug("Discovered %d Python files", len(result))
    return sorted(result)


def parse_file(file_path: str) -> ast.AST:
    """
    Read and parse a Python source file into an AST.

    :param file_path: Path to a .py file
    :return: Parsed AST
    """
    LOG.debug("Parsing file into AST: %s", file_path)
    with open(file_path, encoding="utf-8") as f:
        source = f.read()
    return ast.parse(source, filename=file_path)
