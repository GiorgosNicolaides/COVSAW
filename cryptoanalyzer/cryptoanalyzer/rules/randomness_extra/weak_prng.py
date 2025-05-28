"""
Module for detecting use of cryptographically weak PRNG patterns.

This rule flags:
  1. Seeding the `random` module with a constant literal (e.g., `random.seed(1234)`),
     which makes subsequent outputs predictable.
  2. Instantiation of the non-cryptographic `random.Random` class
     (e.g., `rng = random.Random()` or `from random import Random; rng = Random()`),
     instead of using a secure source like `secrets` or `os.urandom`.

Findings are tagged with:
  - CWE-338: Use of Cryptographically Weak PRNG
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class WeakPrngRule(Rule):
    @property
    def name(self) -> str:
        return "WeakPRNG"

    @property
    def description(self) -> str:
        return (
            "Use of a non-cryptographic PRNG (random.Random) or seeding it with "
            "a constant, leading to predictable values"
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-338"]

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            # CASE A: random.seed(<constant>) or seed(<constant>)
            if isinstance(func, ast.Attribute):
                if (
                    isinstance(func.value, ast.Name)
                    and func.value.id == "random"
                    and func.attr == "seed"
                ):
                    # constant seed makes RNG predictable
                    if node.args and isinstance(node.args[0], ast.Constant):
                        findings.append(self._make_finding(node, file_path))
                        continue

            elif isinstance(func, ast.Name) and func.id == "seed":
                # assume seed() refers to random.seed
                if node.args and isinstance(node.args[0], ast.Constant):
                    findings.append(self._make_finding(node, file_path))
                    continue

            # CASE B: random.Random(...) instantiation
            if isinstance(func, ast.Attribute):
                if (
                    isinstance(func.value, ast.Name)
                    and func.value.id == "random"
                    and func.attr == "Random"
                ):
                    findings.append(self._make_finding(node, file_path))
                    continue

            # CASE C: direct Random(...) if imported via `from random import Random`
            if isinstance(func, ast.Name) and func.id == "Random":
                findings.append(self._make_finding(node, file_path))
                continue

        return findings

    def _make_finding(self, node: ast.Call, file_path: str) -> Finding:
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
