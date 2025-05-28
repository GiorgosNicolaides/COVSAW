"""
Module for detecting missing certificate revocation checks (CRL/OCSP).

This rule looks for SSLContext objects created without any subsequent
revocation configuration such as:
  - setting `ctx.verify_flags` to include revocation checks
  - calling `ctx.load_verify_locations(...)`

Findings are tagged with:
  - CWE-299: Improper Check for Certificate Revocation
"""

import ast
from typing import List, Tuple

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class MissingCertificateRevocationCheckRule(Rule):
    @property
    def name(self) -> str:
        return "MissingCertificateRevocationCheck"

    @property
    def description(self) -> str:
        return "No certificate revocation (CRL/OCSP) check configured on SSLContext"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-299"]

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """
        Identify SSLContext creations and ensure each has revocation setup.
        """
        findings: List[Finding] = []
        # Track (var_name, node) for contexts created
        contexts: List[Tuple[str, ast.AST]] = []

        # 1) Collect SSLContext creations:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # e.g. ctx = ssl.create_default_context() or ssl.SSLContext(...)
                if isinstance(node.value, ast.Call):
                    func = node.value.func
                    full_name = self._get_full_attr_name(func).lower()
                    if full_name in {"ssl.createdefaultcontext", "ssl.create_default_context"} \
                       or full_name.endswith("sslcontext"):
                        # Only consider simple assignments to a variable
                        target = node.targets[0]
                        if isinstance(target, ast.Name):
                            contexts.append((target.id, node))

        # 2) For each context var, check for revocation setup
        for var_name, create_node in contexts:
            if not self._has_revocation_setup(tree, var_name):
                findings.append(self._make_finding(create_node, file_path))

        return findings

    def _has_revocation_setup(self, tree: ast.AST, var_name: str) -> bool:
        """
        Search for attribute assignments or calls on var_name indicating
        revocation configuration.
        """
        for node in ast.walk(tree):
            # ctx.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF (or mixed flags)
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Attribute):
                attr = node.targets[0]
                if isinstance(attr.value, ast.Name) and attr.value.id == var_name:
                    if attr.attr == "verify_flags":
                        return True

            # ctx.load_verify_locations(...)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                if isinstance(func.value, ast.Name) and func.value.id == var_name:
                    if func.attr == "load_verify_locations":
                        return True

        return False

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        """
        Create a Finding at the SSLContext creation site.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )

    def _get_full_attr_name(self, fn: ast.AST) -> str:
        """
        Reconstruct the dotted name of an attribute or name node.

        e.g. ssl.create_default_context -> "ssl.create_default_context"
        """
        if isinstance(fn, ast.Name):
            return fn.id
        parts = []
        current = fn
        while isinstance(current, ast.Attribute):
            parts.insert(0, current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.insert(0, current.id)
        return ".".join(parts)
