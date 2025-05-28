"""
Module for detecting improper or disabled certificate validation.

This rule looks for:
  1. SSLContext.verify_mode set to CERT_NONE.
  2. SSLContext.check_hostname set to False.
  3. Use of ssl._create_unverified_context().
  4. HTTP client calls (e.g., requests, urllib3) with verify=False.

Findings are tagged with:
  - CWE-295: Improper Certificate Validation
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class ImproperCertificateValidationRule(Rule):
    @property
    def name(self) -> str:
        return "ImproperCertificateValidation"

    @property
    def description(self) -> str:
        return "SSL/TLS certificate validation is disabled or skipped"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-295"]

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # CASE 1 & 2: ctx.verify_mode = ssl.CERT_NONE or ctx.check_hostname = False
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Attribute):
                attr = node.targets[0].attr
                # e.g. ctx.verify_mode = ssl.CERT_NONE
                if attr == "verify_mode":
                    if (
                        isinstance(node.value, ast.Attribute)
                        and getattr(node.value, "attr", "") == "CERT_NONE"
                    ):
                        findings.append(self._make_finding(node, file_path))
                # e.g. ctx.check_hostname = False
                elif attr == "check_hostname":
                    if isinstance(node.value, ast.Constant) and node.value.value is False:
                        findings.append(self._make_finding(node, file_path))

            # CASE 3: ssl._create_unverified_context()
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                # look for ssl._create_unverified_context()
                full_name = self._get_full_attr_name(node.func)
                if full_name == "ssl._create_unverified_context":
                    findings.append(self._make_finding(node, file_path))

            # CASE 4: HTTP call with verify=False
            elif isinstance(node, ast.Call):
                # check keywords for verify=False
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        findings.append(self._make_finding(node, file_path))
                        break

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

    def _get_full_attr_name(self, node: ast.Attribute) -> str:
        """
        Reconstruct the full dotted path for an Attribute node, e.g.
        ssl._create_unverified_context
        """
        attrs = []
        current = node
        while isinstance(current, ast.Attribute):
            attrs.insert(0, current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            attrs.insert(0, current.id)
        return ".".join(attrs)
