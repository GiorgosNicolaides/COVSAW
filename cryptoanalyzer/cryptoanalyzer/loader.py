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


def load_config(config_path: str = None) -> Config:
    """
    Load CryptoAnalyzer configuration from path or by discovery.
    """
    return Config.load(config_path)


def discover_source_files(target: str, config: Config = None) -> List[str]:
    """
    Return a sorted list of .py files under `target` (file, dir, or glob),
    filtered by `config.exclude_patterns`.
    """
    config = config or load_config()
    excludes = config.exclude_patterns

    # Expand glob or file/directory
    if any(c in target for c in ("*", "?", "[")):
        paths = glob.glob(target, recursive=True)
    elif os.path.isfile(target):
        paths = [target]
    else:
        paths = []
        for root, _, files in os.walk(target):
            for fn in files:
                if fn.endswith(".py"):
                    paths.append(os.path.join(root, fn))

    def is_excluded(path: str) -> bool:
        return any(fnmatch.fnmatch(path, pat) for pat in excludes)

    return sorted(
        p for p in paths
        if p.endswith(".py") and not is_excluded(p)
    )


def parse_file(file_path: str) -> ast.AST:
    """
    Read and parse a Python file into its AST.
    """
    with open(file_path, encoding="utf-8") as f:
        source = f.read()
    return ast.parse(source, filename=file_path)
