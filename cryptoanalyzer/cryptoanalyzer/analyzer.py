# cryptoanalyzer/analyzer.py

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
from cryptoanalyzer.loader import parse_file, discover_source_files
from cryptoanalyzer.config import Config
from cryptoanalyzer.utils.logger import get_logger  # -- logger added

LOG = get_logger(__name__)  # -- logger instance for this module


class Analyzer:
    def __init__(self, config: Config = None):
        """
        :param config: CryptoAnalyzer Config (for exclude patterns, etc.)
        """
        self.config = config or Config.load()
        LOG.debug("Initializing Analyzer with config: %s", self.config)  # -- log
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
            LOG.debug("Importing rules module: %s", full_name)  # -- log
            module = importlib.import_module(full_name)
            for obj in vars(module).values():
                if (
                    isinstance(obj, type)
                    and issubclass(obj, Rule)
                    and obj is not Rule
                ):
                    rule_instance = obj()
                    rules.append(rule_instance)
                    LOG.debug("Loaded rule: %s", rule_instance.name)  # -- log

        LOG.info("Total rules loaded: %d", len(rules))  # -- log
        return rules

    def analyze_file(self, file_path: str) -> List[Finding]:
        """
        Parse a single .py file and run every rule against its AST.
        """
        LOG.debug("Parsing file: %s", file_path)  # -- log
        tree = parse_file(file_path)
        findings: List[Finding] = []
        for rule in self.rules:
            rule_findings = rule.check(tree, file_path)
            if rule_findings:
                LOG.debug("Rule '%s' reported %d finding(s) in %s", rule.name, len(rule_findings), file_path)
            findings.extend(rule_findings)
        return findings

    def analyze_path(self, target: str) -> List[Finding]:
        """
        Discover source files under `target` (file, dir, or glob), then analyze them.
        """
        LOG.info("Starting analysis on target: %s", target)  # -- log
        findings: List[Finding] = []
        files = discover_source_files(target, self.config)
        LOG.info("Discovered %d files to analyze", len(files))  # -- log
        for path in files:
            findings.extend(self.analyze_file(path))
        LOG.info("Finished analysis on target: %s", target)  # -- log
        return findings
