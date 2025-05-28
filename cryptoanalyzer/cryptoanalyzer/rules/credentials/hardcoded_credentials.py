"""
Module for detecting hard-coded credentials in source code.

This rule flags:
  1. Assignments of string literals to variables whose names suggest credentials
     (e.g., password, token, api_key).
  2. Function parameters with default string literals for credential-like arguments.
  3. Dictionary literals containing credential keys paired with string literals.

Findings are tagged with:
  - CWE-798: Use of Hard-coded Credentials
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class HardcodedCredentialsRule(Rule):
    @property
    def name(self) -> str:
        return "HardcodedCredentials"

    @property
    def description(self) -> str:
        return "Use of hard-coded credentials (username, password, token, API key, etc.)"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-798"]

    # Variable and dict-key names that likely indicate credentials
    _suspect_names = {
        "username", "user",
        "password", "pass",
        "token", "secret",
        "apikey", "api_key",
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # 1) Simple assignment: var = "literal"
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id.lower() in self._suspect_names
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)
                    ):
                        findings.append(self._make_finding(node, file_path))

            # 2) FunctionDef defaults: def fn(..., password="…", ...):
            elif isinstance(node, ast.FunctionDef):
                # align defaults to the last N args
                defaults = node.args.defaults
                args = node.args.args[-len(defaults):] if defaults else []
                for arg, default in zip(args, defaults):
                    if (
                        arg.arg.lower() in self._suspect_names
                        and isinstance(default, ast.Constant)
                        and isinstance(default.value, str)
                    ):
                        findings.append(self._make_finding(default, file_path))

            # 3) Dictionary literals: {"password": "…", ...}
            elif isinstance(node, ast.Dict):
                for key_node, value_node in zip(node.keys, node.values):
                    if (
                        isinstance(key_node, ast.Constant)
                        and isinstance(key_node.value, str)
                        and key_node.value.lower() in self._suspect_names
                        and isinstance(value_node, ast.Constant)
                        and isinstance(value_node.value, str)
                    ):
                        findings.append(self._make_finding(node, file_path))

        return findings

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        """
        Build a Finding at the node's location.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
