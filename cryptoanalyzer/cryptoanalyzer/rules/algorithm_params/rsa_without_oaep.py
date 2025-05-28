
"""
Module for detecting RSA encryption/decryption without OAEP padding.

This rule looks for:
  - Instantiation of the PKCS#1 v1.5 cipher via:
      from Crypto.Cipher import PKCS1_v1_5
      cipher = PKCS1_v1_5.new(key)
  - Any call to <…>.new() where the attribute chain includes "PKCS1_v1_5"
    (i.e. Crypto.Cipher.PKCS1_v1_5.new or direct import).

Findings are tagged with:
  - CWE-780: Use of RSA Algorithm without OAEP
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class RsaNoOaepRule(Rule):
    @property
    def name(self) -> str:
        return "RSAWithoutOAEP"

    @property
    def description(self) -> str:
        return "Use of RSA encryption/decryption without OAEP padding (PKCS#1 v1.5)"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-780"]

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """
        Walk the AST looking for calls to .new() on PKCS1_v1_5 cipher classes.
        """
        findings: List[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            # We're interested in calls like PKCS1_v1_5.new(...)
            if isinstance(func, ast.Attribute) and func.attr == "new":
                full_name = self._get_full_attr_name(func).lower().split(".")
                if "pkcs1_v1_5" in full_name:
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

    def _get_full_attr_name(self, node: ast.Attribute) -> str:
        """
        Reconstruct the full attribute access path as a dotted string.
        e.g. for Crypto.Cipher.PKCS1_v1_5.new it returns "Crypto.Cipher.PKCS1_v1_5.new".
        """
        parts = []
        current = node
        # collect the attribute chain
        while isinstance(current, ast.Attribute):
            parts.insert(0, current.attr)
            current = current.value
        # if the base is a Name, include it
        if isinstance(current, ast.Name):
            parts.insert(0, current.id)
        return ".".join(parts)