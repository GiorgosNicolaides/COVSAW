"""
Module for detecting hashing operations without an explicit or secure salt.

This rule looks for:
  1. Calls to hashlib.pbkdf2_hmac(...) where the salt argument is a constant literal.
  2. Calls to bcrypt.hashpw(...) where the salt argument is a constant literal.
  3. Direct calls to pbkdf2_hmac(...) or hashpw(...) imported into the namespace,
     similarly with a literal salt argument.

Findings are tagged with:
  - CWE-759: Use of One-Way Hash Without a Salt
  - CWE-760: Use of a One-Way Hash with a Predictable Salt
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class HashWithoutSaltRule(Rule):
    @property
    def name(self) -> str:
        return "HashWithoutSalt"

    @property
    def description(self) -> str:
        return "Hashing without a salt or using a constant/predictable salt"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-759", "CWE-760"]

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # CASE A: hashlib.pbkdf2_hmac(hash_name, password, salt, ...)
            if isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "hashlib"
                    and node.func.attr == "pbkdf2_hmac"
                ):
                    # check positional salt argument
                    if len(node.args) >= 3 and isinstance(node.args[2], ast.Constant):
                        findings.append(self._make_finding(node, file_path))
                        continue
                    # check keyword salt argument
                    for kw in node.keywords:
                        if kw.arg == "salt" and isinstance(kw.value, ast.Constant):
                            findings.append(self._make_finding(node, file_path))
                            break

            # CASE B: bcrypt.hashpw(password, salt)
            elif isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "bcrypt"
                    and node.func.attr == "hashpw"
                ):
                    # check positional salt argument
                    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                        findings.append(self._make_finding(node, file_path))
                        continue
                    # check keyword salt argument
                    for kw in node.keywords:
                        if kw.arg == "salt" and isinstance(kw.value, ast.Constant):
                            findings.append(self._make_finding(node, file_path))
                            break

            # CASE C: direct function calls if imported via `from hashlib import pbkdf2_hmac`
            if isinstance(node.func, ast.Name):
                func_name = node.func.id.lower()
                # pbkdf2_hmac(...)
                if func_name == "pbkdf2_hmac":
                    if len(node.args) >= 3 and isinstance(node.args[2], ast.Constant):
                        findings.append(self._make_finding(node, file_path))
                        continue
                    for kw in node.keywords:
                        if kw.arg == "salt" and isinstance(kw.value, ast.Constant):
                            findings.append(self._make_finding(node, file_path))
                            break
                # hashpw(...)
                if func_name == "hashpw":
                    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                        findings.append(self._make_finding(node, file_path))
                        continue
                    for kw in node.keywords:
                        if kw.arg == "salt" and isinstance(kw.value, ast.Constant):
                            findings.append(self._make_finding(node, file_path))
                            break

        return findings

    def _make_finding(self, node: ast.Call, file_path: str) -> Finding:
        """
        Construct a Finding for the given AST Call node.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
