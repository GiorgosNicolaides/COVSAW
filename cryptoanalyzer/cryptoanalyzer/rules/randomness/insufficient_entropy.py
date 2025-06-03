# cryptoanalyzer/rules/randomness/cwe_331_332_insufficient_entropy.py

"""
Rule to detect Insufficient Entropy (CWE-331) and Insufficient Entropy in PRNG (CWE-332).

This rule flags any use of Python’s non‐cryptographic PRNG that is likely seeded
with insufficient entropy. Specifically, it catches:

  1. Calls to `random.seed()` with any argument (literal, variable, or no argument),
     since a missing or predictable seed leads to low initial entropy (CWE-331).
  2. Instantiation of `random.Random()` without explicit seeding from a secure source,
     implying reliance on default seeding (time-based or OS state) which may be insufficient (CWE-332).
  3. Calls to `random.Random(a)` where `a` is any literal or non‐cryptographic source,
     indicating a user-supplied seed that may lack sufficient entropy (CWE-332).

By catching these patterns, we ensure code does not rely on low‐entropy PRNG seeding for
security‐sensitive purposes (e.g., key/IV generation, nonces).
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import get_full_attr_name


class Cwe331Cwe332InsufficientEntropyRule(Rule):
    @property
    def name(self) -> str:
        return "CWE331_CWE332_InsufficientEntropy"

    @property
    def description(self) -> str:
        return (
            "Non‐cryptographic PRNG is seeded with insufficient or predictable entropy, "
            "or `random.Random()` is used without secure seeding."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-331", "CWE-332"]

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # Only inspect call expressions
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            full = get_full_attr_name(func).lower()

            # 1) random.seed(...)
            # Any form of seed() indicates potential low entropy seed
            if full == "random.seed" or full.endswith(".random.seed"):
                # flag regardless of arguments (missing or literal) for CWE-331
                findings.append(self._make_finding(node, file_path))
                continue

            # 2) random.Random(...) instantiation
            # If called without a secure seed, PRNG is seeded with system time or OS state
            if full == "random.random.random" or full.endswith(".random.random"):
                # Catches cases like from random import Random; Random(...)
                findings.append(self._make_finding(node, file_path))
                continue

            # 3) random.Random(a) where a is any argument (literal or non‐crypto source)
            # If full matches random.Random, flag as CWE-332
            if full == "random.random" or full.endswith(".random"):
                # This also catches random.Random(...)
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
