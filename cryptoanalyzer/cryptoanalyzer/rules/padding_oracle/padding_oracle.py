"""
Module for detecting padding‐oracle susceptible exception handling.

This rule flags broad exception handlers around decryption or unpadding calls,
which may swallow padding errors and enable padding oracle attacks.

Specifically, it looks for:
  1. A `try/except` where the `except` clause:
     - Catches all exceptions (no exception type) or catches `Exception`/`BaseException`.
     - Its body is empty or only contains `pass` (i.e., silently ignores errors).
  2. Within that same `try` block, at least one call to:
     - A `.decrypt(...)` method on a cipher object, or
     - A call to `unpad(...)` in `Crypto.Util.Padding`.

Findings are tagged with:
  - CWE-346: Origin Validation Error (Padding Oracle)
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class PaddingOracleSusceptibleRule(Rule):
    @property
    def name(self) -> str:
        return "PaddingOracleSusceptible"

    @property
    def description(self) -> str:
        return (
            "Broad exception handler around decryption/unpadding may enable a padding oracle"
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-346"]

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        # Walk all try statements
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue

            # Check each except handler in the try
            for handler in node.handlers:
                # 1. Broad except: no type or catches Exception/BaseException
                catches_all = (
                    handler.type is None or
                    (isinstance(handler.type, ast.Name) and
                     handler.type.id in ("Exception", "BaseException"))
                )
                # 2. Handler body only contains pass or is empty
                if catches_all and all(isinstance(n, ast.Pass) for n in handler.body):
                    # 3. Ensure try block contains a decrypt() or unpad() call
                    if self._contains_crypto_call(node):
                        findings.append(self._make_finding(handler, file_path))
                        # One finding per handler is sufficient
                        break

        return findings

    def _contains_crypto_call(self, try_node: ast.Try) -> bool:
        """
        Return True if the try block or its nested statements contain:
          - A call to .decrypt(...)
          - A call to unpad(...)
        """
        for sub in ast.walk(try_node):
            if isinstance(sub, ast.Call):
                # Method calls like cipher.decrypt(...)
                if isinstance(sub.func, ast.Attribute) and sub.func.attr.lower() == "decrypt":
                    return True
                # Function calls like unpad(...)
                if isinstance(sub.func, ast.Name) and sub.func.id.lower() == "unpad":
                    return True
        return False

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        """
        Build a Finding at the handler's location.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
