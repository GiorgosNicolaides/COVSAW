"""
Core Analyzer: dynamically loads all Rule subclasses from cryptoanalyzer.rules,
parses source files, and applies each rule to produce Findings.
"""

import os
import pkgutil
import importlib
from typing import List

from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.rules import Rule
from cryptoanalyzer.loader import discover_source_files, parse_file
from cryptoanalyzer.config import Config


class Analyzer:
    def __init__(self, config: Config = None):
        """
        :param config: CryptoAnalyzer Config (for exclude patterns, etc.)
        """
        self.config = config or Config.load()
        self.rules: List[Rule] = self._load_rules()

    def _load_rules(self) -> List[Rule]:
        """
        Recursively walk the cryptoanalyzer.rules package, import every module,
        and instantiate any subclass of Rule.
        """
        rules: List[Rule] = []
        rules_pkg = "cryptoanalyzer.rules"
        rules_path = os.path.join(os.path.dirname(__file__), "rules")

        for finder, full_name, is_pkg in pkgutil.walk_packages(
            [rules_path],
            prefix=rules_pkg + "."
        ):
            if is_pkg:
                continue
            module = importlib.import_module(full_name)
            for obj in vars(module).values():
                if (
                    isinstance(obj, type)
                    and issubclass(obj, Rule)
                    and obj is not Rule
                ):
                    rules.append(obj())

        return rules

    def analyze_file(self, file_path: str) -> List[Finding]:
        """
        Parse a single .py file and run every rule against its AST.
        """
        tree = parse_file(file_path)
        findings: List[Finding] = []
        for rule in self.rules:
            findings.extend(rule.check(tree, file_path))
        return findings

    def analyze_path(self, target: str) -> List[Finding]:
        """
        Discover source files under `target` (file, dir, or glob), then analyze them.
        """
        findings: List[Finding] = []
        files = discover_source_files(target, self.config)
        for path in files:
            findings.extend(self.analyze_file(path))
        return findings
