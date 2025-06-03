# cryptoanalyzer/rules/randomness/cwe_333_improper_trng_handling.py

"""
Rule to detect Improper Handling of Insufficient Entropy in TRNG (CWE-333).

This rule flags any use of a true random number generator (TRNG) API (e.g., os.urandom,
secrets.token_bytes, secrets.token_hex) where the call is not wrapped in a try/except
block to catch potential failures (e.g., NotImplementedError, blocking issues). Proper
handling requires catching exceptions or verifying that entropy is available before
using the TRNG. Patterns detected include:

  1. Direct calls to os.urandom(...) outside of any try/except.
  2. Direct calls to secrets.token_bytes(...) or secrets.token_hex(...) outside of try/except.
  3. Instantiating random.SystemRandom() and calling random() or randbytes() outside of try/except.

By catching these patterns, we ensure that code does not assume TRNG calls always succeed,
fulfilling CWE-333 via static analysis.
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import get_full_attr_name


class Cwe333ImproperTrngHandlingRule(Rule):
    @property
    def name(self) -> str:
        return "CWE333ImproperTRNGHandling"

    @property
    def description(self) -> str:
        return (
            "A TRNG call (os.urandom, secrets.token_bytes/hex, SystemRandom) is used without "
            "catching potential exceptions, risking unhandled failures when entropy is insufficient."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-333"]

    # Full dotted names of functions that rely on TRNG
    _trng_calls = {
        "os.urandom",
        "secrets.token_bytes",
        "secrets.token_hex",
    }

    # Method names on random.SystemRandom instances that invoke TRNG
    _system_random_methods = {
        "random", "randbytes"
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        # Attach parent pointers to all nodes so we can detect enclosing Try blocks
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                setattr(child, "parent", node)

        def is_within_try(node: ast.AST) -> bool:
            """
            Return True if the given node is inside a Try block (anywhere up the ancestor chain).
            """
            current = node
            while hasattr(current, "parent"):
                current = current.parent
                if isinstance(current, ast.Try):
                    return True
            return False

        for node in ast.walk(tree):
            # Only inspect Call expressions
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            # Case A: os.urandom(...) or secrets.token_bytes/hex(...)
            if isinstance(func, ast.Attribute):
                full = get_full_attr_name(func).lower()
                if full in self._trng_calls:
                    # If not inside a try/except, flag
                    if not is_within_try(node):
                        findings.append(self._make_finding(node, file_path))
                    continue

                # Case B: SystemRandom().random() or SystemRandom().randbytes()
                # Check if func is an Attribute where base is a SystemRandom instance
                # e.g., random.SystemRandom().random() or sysr.random()
                # We detect by seeing if full name contains "systemrandom.random" or "systemrandom.randbytes"
                if any(full.endswith(f"systemrandom.{method}") for method in self._system_random_methods):
                    if not is_within_try(node):
                        findings.append(self._make_finding(node, file_path))
                    continue

            # Case C: Direct calls to SystemRandom() constructor (without subsequent method call)
            # If someone writes sysr = random.SystemRandom(…); we flag instantiation if not in try
            if isinstance(func, ast.Attribute) and get_full_attr_name(func).lower().endswith("random.systemrandom"):
                if not is_within_try(node):
                    findings.append(self._make_finding(node, file_path))
                continue

            # Case D: Direct calls to SystemRandom() if imported directly: from random import SystemRandom
            if isinstance(func, ast.Name) and func.id == "SystemRandom":
                if not is_within_try(node):
                    findings.append(self._make_finding(node, file_path))
                continue

        return findings

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
