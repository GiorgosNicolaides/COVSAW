"""
Module for detecting use of non-cryptographic random number generators.

This rule flags calls to Python's `random` module functions that are
not suitable for security-sensitive purposes:

  - random.random()
  - random.randint()
  - random.randrange()
  - random.choice()
  - random.shuffle()
  - random.sample()

Also catches direct imports such as:
  from random import random, randint, choice, etc.

Findings are tagged with:
  - CWE-330: Use of Insufficiently Random Values
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class InsecureRandomnessRule(Rule):
    @property
    def name(self) -> str:
        return "InsecureRandomness"

    @property
    def description(self) -> str:
        return "Use of non-cryptographic random number generator (Python `random` module)"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-330"]

    # Names of random functions that are insecure for cryptographic use
    _unsafe_funcs = {"random", "randint", "randrange", "choice", "shuffle", "sample"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            # Case A: random.<func>()
            if isinstance(func, ast.Attribute):
                if (
                    isinstance(func.value, ast.Name)
                    and func.value.id == "random"
                    and func.attr in self._unsafe_funcs
                ):
                    findings.append(self._make_finding(node, file_path))
                    continue

            # Case B: direct import: <func>() where func in unsafe set
            if isinstance(func, ast.Name) and func.id in self._unsafe_funcs:
                findings.append(self._make_finding(node, file_path))

        return findings

    def _make_finding(self, node: ast.Call, file_path: str) -> Finding:
        """
        Helper to build a Finding at the node's location.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
