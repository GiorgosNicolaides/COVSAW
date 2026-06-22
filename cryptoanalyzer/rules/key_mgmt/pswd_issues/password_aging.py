# cryptoanalyzer/rules/credentials/cwe_262_263_password_aging.py

"""
Rule to detect:
  • CWE-262: Not Using Password Aging (password expiration set to 0 days or disabled)
  • CWE-263: Password Aging with Long Expiration (password expiration configured for too many days)

This rule flags any configuration or assignment of a “password_expiration_days”
(or similar) setting as a literal integer that is:
  - Equal to 0 (CWE-262: aging disabled)
  - Greater than 365 (CWE-263: excessively long expiration)

Patterns detected include:
  1. Top-level assignments in code: 
       PASSWORD_EXPIRATION_DAYS = <int_literal>
       PASSWORD_MAX_AGE_DAYS   = <int_literal>
     where <int_literal> == 0 → CWE-262, <int_literal> > 365 → CWE-263.

  2. Configuration parser calls:
       config.set("Section", "password_expiration_days", "<string_int>")
       config.set("Section", "password_max_age_days",   "<string_int>")
     where string_int parses to 0 → CWE-262, > 365 → CWE-263.

  3. Dictionary literals:
       {"password_expiration_days": <int_literal>, ...}
       {"password_max_age_days":   <int_literal>, ...}
     with the same numeric checks.

Any literal integer outside (0, 1–365] is flagged accordingly.
"""

import ast
from typing import List, Optional

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    is_string_literal,
    get_constant_value,
    extract_string_from_dict_key,
    get_full_attr_name,
)


class Cwe262Cwe263PasswordAgingRule(Rule):
    @property
    def name(self) -> str:
        return "CWE262_CWE263_PasswordAging"

    @property
    def description(self) -> str:
        return (
            "Password expiration is disabled (0 days) or set too high (>365 days)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        # Actual CWE tag returned depends on the literal value found
        return ["CWE-262", "CWE-263"]

    # Recognized configuration keys (lowercase)
    _aging_keys = {"password_expiration_days", "password_max_age_days"}

    # Thresholds
    _disabled_value = 0
    _max_days = 365

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # ------------------------------------------------------------
            # 1) Top-level assignment: NAME = <int_literal>
            # ------------------------------------------------------------
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        var_name = tgt.id.lower()
                        if var_name in self._aging_keys:
                            val_node = node.value
                            int_val = self._extract_int_literal(val_node)
                            if int_val is not None:
                                if int_val == self._disabled_value:
                                    findings.append(self._make_finding(node, file_path, "CWE-262"))
                                elif int_val > self._max_days:
                                    findings.append(self._make_finding(node, file_path, "CWE-263"))
                            # If not a literal int, skip
                            break

            # ------------------------------------------------------------
            # 2) config.set("Section", "key", "value")
            # ------------------------------------------------------------
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                if func.attr == "set":
                    # Must have at least 3 positional args: (section, option, value)
                    if len(node.args) >= 3:
                        opt_node = node.args[1]
                        val_node = node.args[2]
                        if is_string_literal(opt_node):
                            key = get_constant_value(opt_node).lower()
                            if key in self._aging_keys:
                                int_val = self._parse_int_string(val_node)
                                if int_val is not None:
                                    if int_val == self._disabled_value:
                                        findings.append(self._make_finding(node, file_path, "CWE-262"))
                                    elif int_val > self._max_days:
                                        findings.append(self._make_finding(node, file_path, "CWE-263"))
                                # If value not a literal or not parseable, skip
                                continue

            # ------------------------------------------------------------
            # 3) Dictionary literal: {"key": <int_literal>, ...}
            # ------------------------------------------------------------
            elif isinstance(node, ast.Dict):
                keys = extract_string_from_dict_key(node)
                for key_str in keys:
                    key_lower = key_str.lower()
                    if key_lower in self._aging_keys:
                        # Find matching value node
                        for k_node, v_node in zip(node.keys, node.values):
                            if (
                                isinstance(k_node, ast.Constant)
                                and isinstance(k_node.value, str)
                                and k_node.value.lower() == key_lower
                            ):
                                int_val = self._extract_int_literal(v_node)
                                if int_val is not None:
                                    if int_val == self._disabled_value:
                                        findings.append(self._make_finding(node, file_path, "CWE-262"))
                                    elif int_val > self._max_days:
                                        findings.append(self._make_finding(node, file_path, "CWE-263"))
                                break
                        break

        return findings

    def _extract_int_literal(self, node: ast.AST) -> Optional[int]:
        """
        If node is an ast.Constant with an int value, return it.
        Otherwise return None.
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        return None

    def _parse_int_string(self, node: ast.AST) -> Optional[int]:
        """
        If node is a string literal representing an integer ("123"), return int.
        Otherwise return None.
        """
        if is_string_literal(node):
            val = get_constant_value(node)
            if isinstance(val, str):
                try:
                    return int(val)
                except ValueError:
                    return None
        return None

    def _make_finding(self, node: ast.AST, file_path: str, cwe_id: str) -> Finding:
        """
        Construct a Finding with the specified CWE (CWE-262 or CWE-263).
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=f"{self.description} ({cwe_id})",
            cwe_ids=[cwe_id],
        )
