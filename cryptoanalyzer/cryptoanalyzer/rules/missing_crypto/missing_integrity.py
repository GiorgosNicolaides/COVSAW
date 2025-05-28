"""
Module for detecting missing integrity protection around cryptographic operations.

This rule flags calls to encryption or decryption methods without any accompanying
integrity check (e.g., HMAC, digital signature). Static heuristics:
  - Any invocation of `.encrypt(...)` on a cipher object (e.g., Crypto.Cipher.*)
    without any nearby HMAC/signature API call.
  - Any invocation of `.decrypt(...)` without verifying a MAC or signature.

Findings are tagged with:
  - CWE-353: Missing Support for Integrity Check
  - CWE-354: Improper Validation of Integrity Check Value
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class MissingIntegrityRule(Rule):
    @property
    def name(self) -> str:
        return "MissingIntegrityCheck"

    @property
    def description(self) -> str:
        return (
            "Cryptographic operation without an accompanying integrity check "
            "(e.g. encrypt/decrypt called without HMAC or signature)"
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-353", "CWE-354"]

    # Methods indicating pure encryption/decryption
    _crypto_methods = {"encrypt", "decrypt"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # Look for method calls like cipher.encrypt(data) or cipher.decrypt(data)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                method = node.func.attr.lower()
                if method in self._crypto_methods:
                    # We could enhance by ensuring HMAC or signature calls exist in the same scope,
                    # but as a static heuristic we flag all raw encrypt/decrypt invocations.
                    findings.append(self._make_finding(node, file_path))

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
