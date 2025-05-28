# cryptoanalyzer/rules/randomness_extra/nonce_reuse.py

"""
Module for detecting reuse of a nonce/IV across multiple encryption operations.

This rule flags cases where a variable assigned a constant (predictable)
nonce or IV literal is reused in two or more calls to a cipher’s .new(...)
method, indicating nonce reuse (CWE-323).

Findings are tagged with:
  - CWE-323: Reusing a Nonce, Key Pair in Encryption
"""

import ast
from typing import List, Dict

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class NonceReuseRule(Rule):
    @property
    def name(self) -> str:
        return "NonceReuse"

    @property
    def description(self) -> str:
        return (
            "A constant or predictable nonce/IV is reused in multiple "
            "encryption operations"
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-323"]

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """
        1) Identify assignments of a literal (bytes or string) to a variable,
           e.g., iv = b'...' or nonce = '...'
        2) Track uses of that variable in .new(..., iv=var) or .new(..., nonce=var)
        3) If any such variable is used in 2+ encryption calls, flag each reuse.
        """
        # Map var name -> assignment node (for location, though we flag call sites)
        literal_vars: Dict[str, ast.Assign] = {}
        # Map var name -> list of call nodes where used as iv/nonce
        uses: Dict[str, List[ast.Call]] = {}

        # First pass: collect literal assignments
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    var = node.targets[0].id
                    val = node.value
                    # constant bytes or string literal
                    if isinstance(val, ast.Constant) and isinstance(val.value, (bytes, str)):
                        literal_vars[var] = node
                        uses[var] = []

        # Second pass: collect uses in cipher instantiations
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # look for .new(...) calls
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "new":
                # check iv= or nonce= keyword
                for kw in node.keywords:
                    if kw.arg in ("iv", "nonce") and isinstance(kw.value, ast.Name):
                        var = kw.value.id
                        if var in literal_vars:
                            uses[var].append(node)

        # Third pass: flag reused nonces
        findings: List[Finding] = []
        for var, calls in uses.items():
            if len(calls) > 1:
                for call in calls:
                    findings.append(self._make_finding(call, file_path))

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
