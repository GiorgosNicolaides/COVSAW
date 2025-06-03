# cryptoanalyzer/rules/randomness/cwe_330_insufficient_random.py

"""
Rule to detect Use of Insufficiently Random Values (CWE-330).

This rule flags any usage of Python’s non-cryptographic random functions from the
`random` module when generating values that should be cryptographically secure
(e.g., IVs, nonces, keys, tokens). Patterns include:

  1. Calls to any function in the `random` module (e.g., random.random(),
     random.randint(), random.getrandbits(), random.choice(), random.randbytes(), etc.).
  2. Direct calls to bare names imported from `random` (e.g., `from random import randint;
     randint(...)`).
  3. Assignment of a variable name containing “iv” or “nonce” or “key” to a call
     of a `random` function (e.g., `iv = random.randbytes(16)`).

By catching these patterns, we ensure that cryptographic values are not generated
using predictable, non-cryptographic randomness.
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import get_full_attr_name


class Cwe330InsufficientRandomRule(Rule):
    @property
    def name(self) -> str:
        return "CWE330InsufficientRandom"

    @property
    def description(self) -> str:
        return (
            "Non-cryptographic random values from the `random` module are used for "
            "security-sensitive purposes, leading to predictable values."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-330"]

    # Known random module functions (lowercase) that are not cryptographically secure
    _random_functions = {
        "random", "randint", "randrange", "getrandbits", "randbytes",
        "choice", "choices", "shuffle", "uniform", "triangular",
        "betavariate", "expovariate", "gauss", "lognormvariate",
        "normalvariate", "vonmisesvariate", "paretovariate", "weibullvariate",
        "sample"
    }

    # Variable name fragments indicating a security-sensitive use (e.g., IV, nonce, key, token)
    _sensitive_fragments = {"iv", "nonce", "key", "token", "salt"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # Only inspect function calls
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            # Case A: random.<func>(...)
            if isinstance(func, ast.Attribute):
                full = get_full_attr_name(func).lower()
                # Check if it starts with "random." and ends with a known function
                if full.startswith("random."):
                    func_name = full.split(".", 1)[1]
                    if func_name in self._random_functions:
                        findings.append(self._make_finding(node, file_path))
                        continue

            # Case B: <func>(...) if imported via "from random import <func>"
            if isinstance(func, ast.Name):
                if func.id.lower() in self._random_functions:
                    findings.append(self._make_finding(node, file_path))
                    continue

            # Case C: Assignment of security-sensitive variable to random.* call
            # e.g., iv = random.randbytes(16)
            # We catch this by checking Assign nodes whose value is a random call
            if isinstance(node, ast.Call):
                parent = getattr(node, "parent", None)
                if isinstance(parent, ast.Assign):
                    # Only handle single-target assignments
                    if len(parent.targets) == 1 and isinstance(parent.targets[0], ast.Name):
                        var_name = parent.targets[0].id.lower()
                        # If variable name contains a sensitive fragment and RHS is random.*
                        if any(fragment in var_name for fragment in self._sensitive_fragments):
                            # Check if this call is a random.* call
                            if isinstance(func, ast.Attribute):
                                full = get_full_attr_name(func).lower()
                                if full.startswith("random.") and full.split(".", 1)[1] in self._random_functions:
                                    findings.append(self._make_finding(node, file_path))
                                    continue
                            if isinstance(func, ast.Name) and func.id.lower() in self._random_functions:
                                findings.append(self._make_finding(node, file_path))
                                continue

        return findings

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        """
        Construct a Finding at the call node’s location.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
