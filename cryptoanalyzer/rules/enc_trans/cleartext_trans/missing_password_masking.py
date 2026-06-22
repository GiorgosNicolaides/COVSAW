# cryptoanalyzer/rules/credentials/cwe_549_missing_password_masking.py

"""
Rule to detect Missing Password Field Masking (CWE-549).

This rule flags:
  1. Calls to `input(...)` or `raw_input(...)` where a “password”-like variable
     is assigned, indicating the password is entered in cleartext.
  2. Calls to `input(...)` or `raw_input(...)` with a prompt literal containing
     “password”, even if not assigned, implying unmasked entry.
  3. Logging or printing of a password-like variable (e.g., `print(password)`,
     `logger.info(password)`), exposing the password in cleartext.

By catching these patterns, we ensure that passwords are not read or displayed
without masking.
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    is_string_literal,
    get_constant_value,
    is_name_or_attr,
    get_full_attr_name,
)


class Cwe549MissingPasswordMaskingRule(Rule):
    @property
    def name(self) -> str:
        return "CWE549MissingPasswordMasking"

    @property
    def description(self) -> str:
        return (
            "Password input or output is not masked (e.g., using input() or print/log)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-549"]

    # Variable names indicating password-like data
    _password_vars = {"password", "passwd", "pwd", "pass"}

    # Logging methods to inspect
    _log_methods = {"debug", "info", "warning", "error", "critical", "exception"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # ------------------------------------------------------------
            # 1) Assignment: password = input(...) or raw_input(...)
            # ------------------------------------------------------------
            if isinstance(node, ast.Assign):
                # Single target only
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    tgt = node.targets[0]
                    var_name = tgt.id.lower()
                    if var_name in self._password_vars:
                        # Right side is a Call to input() or raw_input()
                        if isinstance(node.value, ast.Call):
                            func = node.value.func
                            if (
                                isinstance(func, ast.Name)
                                and func.id in {"input", "raw_input"}
                            ):
                                findings.append(self._make_finding(node, file_path))
                                continue
                            # e.g., builtins.input
                            if isinstance(func, ast.Attribute):
                                full = get_full_attr_name(func).lower()
                                if full.endswith(".input") or full.endswith(".raw_input"):
                                    findings.append(self._make_finding(node, file_path))
                                    continue

            # ------------------------------------------------------------
            # 2) Call to input(...) or raw_input(...) with prompt containing “password”
            # ------------------------------------------------------------
            if isinstance(node, ast.Call):
                func = node.func
                is_input_call = False
                if isinstance(func, ast.Name) and func.id in {"input", "raw_input"}:
                    is_input_call = True
                elif isinstance(func, ast.Attribute):
                    full = get_full_attr_name(func).lower()
                    if full.endswith(".input") or full.endswith(".raw_input"):
                        is_input_call = True

                if is_input_call and node.args:
                    # Check if first argument is a string literal containing “password”
                    prompt_node = node.args[0]
                    if is_string_literal(prompt_node):
                        prompt_val = get_constant_value(prompt_node)
                        if isinstance(prompt_val, str) and "password" in prompt_val.lower():
                            findings.append(self._make_finding(node, file_path))
                            continue

            # ------------------------------------------------------------
            # 3) print(password) or logger.info(password) / logging.info(password)
            # ------------------------------------------------------------
            if isinstance(node, ast.Call):
                func = node.func

                # 3a) Direct print(...)
                if isinstance(func, ast.Name) and func.id == "print":
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id.lower() in self._password_vars:
                            findings.append(self._make_finding(node, file_path))
                            break
                    continue

                # 3b) logger.<level>(password) or logging.<level>(password)
                if isinstance(func, ast.Attribute):
                    if func.attr.lower() in self._log_methods:
                        # Identify logger or logging
                        if isinstance(func.value, ast.Name) and func.value.id.lower() in {"logger", "logging"}:
                            for arg in node.args:
                                if isinstance(arg, ast.Name) and arg.id.lower() in self._password_vars:
                                    findings.append(self._make_finding(node, file_path))
                                    break
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
