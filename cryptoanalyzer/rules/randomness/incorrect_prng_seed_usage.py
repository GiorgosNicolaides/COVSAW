# cryptoanalyzer/rules/randomness/cwe_335_incorrect_prng_seed_usage.py

"""
Rule to detect Incorrect Usage of Seeds in PRNG (CWE-335).

This rule flags any use of Python’s non-cryptographic PRNG (`random`) where:
  1. `random.seed(...)` is called with a constant literal (int, str, bytes).
  2. `random.seed(...)` is called with a call to a time-based function (e.g., `time.time()`,
     `datetime.datetime.now()`, `datetime.now()`), making the seed predictable.
  3. Instantiation `random.Random(<seed>)` or `Random(<seed>)` with a literal or time-based call.
By catching these patterns, we ensure that the PRNG is not seeded in a predictable way,
covering CWE-335 via static analysis.
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import get_full_attr_name, is_string_literal, is_bytes_literal


class Cwe335IncorrectPrngSeedUsageRule(Rule):
    @property
    def name(self) -> str:
        return "CWE335IncorrectPRNGSeedUsage"

    @property
    def description(self) -> str:
        return (
            "The PRNG is seeded with a predictable or constant value (literal or time-based), "
            "leading to insufficient randomness (CWE-335)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-335"]

    # Recognize time-based seeding functions (lowercase full names)
    _time_seed_prefixes = {
        "time.time",
        "datetime.datetime.now",
        "datetime.now",
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        # Walk the AST looking for calls to random.seed(...) or random.Random(...)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            full = get_full_attr_name(func).lower()

            # 1) random.seed(...) or seed(...) if imported directly
            if full == "random.seed" or full.endswith(".random.seed"):
                # If there is at least one argument
                if node.args:
                    arg = node.args[0]
                    # 1a) Literal seed: int, str, bytes
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, (int, str, bytes)):
                        findings.append(self._make_finding(node, file_path))
                        continue
                    # 1b) Time-based seed: e.g., time.time(), datetime.datetime.now()
                    if isinstance(arg, ast.Call):
                        seed_full = get_full_attr_name(arg.func).lower()
                        if any(seed_full.startswith(prefix) for prefix in self._time_seed_prefixes):
                            findings.append(self._make_finding(node, file_path))
                            continue

            # 2) random.Random(<seed>) or Random(<seed>) if imported directly
            # In both cases, full may be "random.random" (module.Class) or just "random" if alias
            if full == "random.random" or full.endswith(".random.random") or func.__class__ is ast.Name and func.id.lower() == "random":
                # Check first argument if present
                if node.args:
                    arg = node.args[0]
                    # 2a) Literal seed
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, (int, str, bytes)):
                        findings.append(self._make_finding(node, file_path))
                        continue
                    # 2b) Time-based seed
                    if isinstance(arg, ast.Call):
                        seed_full = get_full_attr_name(arg.func).lower()
                        if any(seed_full.startswith(prefix) for prefix in self._time_seed_prefixes):
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
