# cryptoanalyzer/rules/credentials/cwe_258_260_password_in_config.py

"""
Rule to detect:
  • CWE-258: Empty Password in Configuration File
  • CWE-260: Password in Configuration File

This rule flags any instance where a “password” option/key in a configuration context
is assigned an empty string (CWE-258) or any non-empty literal (CWE-260). Patterns include:

  1. Calls to configparser.ConfigParser().set(section, "password", value):
       - If value is ""             → CWE-258
       - If value is a non-empty literal → CWE-260

  2. Assignments via subscripts, e.g.:
       config["section"]["password"] = ""         → CWE-258
       config["section"]["password"] = "secret"   → CWE-260

  3. Dictionary literals representing a config mapping:
       {"password": ""}        → CWE-258
       {"password": "secret"}  → CWE-260

All detections produce a Finding with the appropriate CWE identifier.
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    is_string_literal,
    get_constant_value,
    extract_string_from_dict_key,
    get_full_attr_name,
)


class Cwe258Cwe260PasswordInConfigRule(Rule):
    @property
    def name(self) -> str:
        return "CWE258_CWE260_PasswordInConfig"

    @property
    def description(self) -> str:
        return (
            "A configuration ‘password’ field is set to an empty string (CWE-258) "
            "or to a non-empty literal (CWE-260)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        # Dynamic: actual CWE depends on value; default to both
        return ["CWE-258", "CWE-260"]

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # ------------------------------------------------------------
            # 1) config.set("section", "password", value)
            # ------------------------------------------------------------
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                full = get_full_attr_name(func).lower()
                # Match calls ending with ".set"
                if func.attr == "set":
                    # Check that the second argument is the string "password"
                    if len(node.args) >= 3:
                        opt_node = node.args[1]
                        val_node = node.args[2]
                        if is_string_literal(opt_node) and get_constant_value(opt_node).lower() == "password":
                            if is_string_literal(val_node):
                                val = get_constant_value(val_node)
                                if isinstance(val, str):
                                    if val == "":
                                        findings.append(self._make_finding(node, file_path, "CWE-258"))
                                    else:
                                        findings.append(self._make_finding(node, file_path, "CWE-260"))
                            # If not a literal, we cannot statically determine; skip
                            continue

            # ------------------------------------------------------------
            # 2) Subscript assignment: config["..."]["password"] = value
            # ------------------------------------------------------------
            if isinstance(node, ast.Assign):
                # Only handle single-target assignments
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Subscript):
                    sub = node.targets[0]
                    # Extract the slice for this subscript
                    slice_node = sub.slice
                    # Handle Python 3.9+: slice_node is directly the index
                    key_node = getattr(slice_node, "value", slice_node)
                    # Check if key_node is literal "password"
                    if is_string_literal(key_node) and get_constant_value(key_node).lower() == "password":
                        # val_node is the right-hand side
                        val_node = node.value
                        if is_string_literal(val_node):
                            val = get_constant_value(val_node)
                            if isinstance(val, str):
                                if val == "":
                                    findings.append(self._make_finding(node, file_path, "CWE-258"))
                                else:
                                    findings.append(self._make_finding(node, file_path, "CWE-260"))
                        continue

            # ------------------------------------------------------------
            # 3) Dictionary literal: {"password": value, ...}
            # ------------------------------------------------------------
            if isinstance(node, ast.Dict):
                keys = extract_string_from_dict_key(node)
                # If a "password" key exists, check its corresponding value
                for key_str in keys:
                    if key_str.lower() == "password":
                        # Find the value node for that key
                        for k_node, v_node in zip(node.keys, node.values):
                            if (
                                isinstance(k_node, ast.Constant)
                                and isinstance(k_node.value, str)
                                and k_node.value.lower() == "password"
                            ):
                                if is_string_literal(v_node):
                                    val = get_constant_value(v_node)
                                    if isinstance(val, str):
                                        if val == "":
                                            findings.append(self._make_finding(node, file_path, "CWE-258"))
                                        else:
                                            findings.append(self._make_finding(node, file_path, "CWE-260"))
                                # For non-literal, skip
                                break
                        break

        return findings

    def _make_finding(self, node: ast.AST, file_path: str, cwe_id: str) -> Finding:
        """
        Construct a Finding at node's location, tagging the specific CWE (258 or 260).
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=f"{self.description} ({cwe_id})",
            cwe_ids=[cwe_id],
        )
