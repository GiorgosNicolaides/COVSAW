# cryptoanalyzer/rules/cleartext/cwe_312_313_314_318_526_cleartext_storage.py

"""
Rule to detect cleartext storage of sensitive information, covering:
  • CWE-312: Cleartext Storage of Sensitive Information
  • CWE-313: Cleartext Storage in a File or on Disk
  • CWE-314: Cleartext Storage in the Registry
  • CWE-318: Cleartext Storage of Sensitive Information in an Executable
  • CWE-526: Cleartext Storage of Sensitive Information in an Environment Variable

Patterns detected include:
  1. Assigning a string literal to a variable whose name implies sensitive data
     (e.g., password, token, secret) → CWE-318.
  2. Writing sensitive data (literal or variable) to a file via open(...).write
     or write()/writelines() → CWE-313.
  3. Dumping a dict literal containing sensitive keys (password, token, etc.)
     → CWE-312.
  4. Setting an environment variable with sensitive key (os.environ["PASSWORD"]=…)
     → CWE-526.
  5. Writing sensitive data to the Windows registry via winreg/_winreg calls
     (e.g., winreg.SetValue, winreg.CreateKey, winreg.SetValueEx) → CWE-314.

Each detected pattern emits a Finding tagged with its specific CWE.
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    is_string_literal,
    is_bytes_literal,
    get_constant_value,
    extract_string_from_dict_key,
    get_full_attr_name,
)


class Cwe312313314318526CleartextStorageRule(Rule):
    @property
    def name(self) -> str:
        return "CWE312_313_314_318_526_CleartextStorage"

    @property
    def description(self) -> str:
        return (
            "Sensitive information is being stored in cleartext "
            "(file, registry, code, or environment variable)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-312", "CWE-313", "CWE-314", "CWE-318", "CWE-526"]

    # Variable or dict‐key names indicating sensitive data
    _sensitive_keys = {
        "password", "passwd", "pwd",
        "token", "secret", "api_key", "apikey",
        "ssn", "credit_card", "ccn"
    }

    # Registry functions to inspect (lowercase full names)
    _registry_funcs = {
        "winreg.setvalue", "winreg.setvalueex",
        "winreg.createkey", "winreg.create_key",
        "_winreg.setvalue", "_winreg.setvalueex",
        "_winreg.createkey", "_winreg.create_key"
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # 1) Assignment of literal to sensitive‐named variable → CWE-318
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        var_name = tgt.id.lower()
                        if any(key in var_name for key in self._sensitive_keys):
                            # If value is a string or bytes literal
                            if is_string_literal(node.value) or is_bytes_literal(node.value):
                                findings.append(self._make_finding(node, file_path, "CWE-318"))
                                break

            # 2) File writes: open(...).write(...) or write()/writelines() → CWE-313
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"write", "writelines"}:
                    for arg in node.args:
                        # literal string/bytes or sensitive variable
                        if is_string_literal(arg) or is_bytes_literal(arg):
                            findings.append(self._make_finding(node, file_path, "CWE-313"))
                            break
                        if isinstance(arg, ast.Name) and arg.id.lower() in self._sensitive_keys:
                            findings.append(self._make_finding(node, file_path, "CWE-313"))
                            break
                    continue

            # 3) Dictionary literal with sensitive key → CWE-312
            if isinstance(node, ast.Dict):
                keys = extract_string_from_dict_key(node)
                for key_str in keys:
                    if key_str.lower() in self._sensitive_keys:
                        # Value node corresponding to the sensitive key
                        for k_node, v_node in zip(node.keys, node.values):
                            if (
                                isinstance(k_node, ast.Constant)
                                and isinstance(k_node.value, str)
                                and k_node.value.lower() == key_str.lower()
                            ):
                                # If value is literal or variable
                                if is_string_literal(v_node) or is_bytes_literal(v_node) or (
                                    isinstance(v_node, ast.Name)
                                    and v_node.id.lower() in self._sensitive_keys
                                ):
                                    findings.append(self._make_finding(node, file_path, "CWE-312"))
                                break
                        break

            # 4) Environment variable assignment: os.environ["KEY"] = value → CWE-526
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Subscript):
                sub = node.targets[0]
                # Check base is os.environ
                if isinstance(sub.value, ast.Attribute):
                    full = get_full_attr_name(sub.value).lower()
                    if full == "os.environ":
                        # Key is literal
                        index = sub.slice
                        key_node = getattr(index, "value", index)
                        if is_string_literal(key_node):
                            key_val = get_constant_value(key_node).lower()
                            if key_val in self._sensitive_keys:
                                rhs = node.value
                                # literal or sensitive var
                                if is_string_literal(rhs) or is_bytes_literal(rhs) or (
                                    isinstance(rhs, ast.Name)
                                    and rhs.id.lower() in self._sensitive_keys
                                ):
                                    findings.append(self._make_finding(node, file_path, "CWE-526"))
                                    continue

            # 5) Registry writes: winreg/_winreg.* → CWE-314
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                full = get_full_attr_name(node.func).lower()
                # Match any function in the registry set/create set
                if any(full.startswith(func_name) for func_name in self._registry_funcs):
                    # Inspect arguments for sensitive data (literal or var)
                    for arg in node.args:
                        if is_string_literal(arg) or is_bytes_literal(arg):
                            findings.append(self._make_finding(node, file_path, "CWE-314"))
                            break
                        if isinstance(arg, ast.Name) and arg.id.lower() in self._sensitive_keys:
                            findings.append(self._make_finding(node, file_path, "CWE-314"))
                            break
                    continue

        return findings

    def _make_finding(self, node: ast.AST, file_path: str, cwe_id: str) -> Finding:
        """
        Construct a Finding at `node`’s location with a single CWE identifier.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=f"{self.description} ({cwe_id})",
            cwe_ids=[cwe_id],
        )
