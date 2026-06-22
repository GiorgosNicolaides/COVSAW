# cryptoanalyzer/rules/randomness/cwe_329_predictable_iv.py

"""
Rule to detect Generation of Predictable IV with CBC Mode (CWE-329).

This rule flags any use of a constant or literal IV when creating a cipher
in CBC mode, which makes ciphertext patterns predictable. Patterns include:

  1. Calls to Crypto.Cipher.<ALG>.new(..., mode=ALG.MODE_CBC, iv=<literal>).
  2. Calls where mode is specified as a string "CBC" and iv is a literal.
  3. Absent IV in CBC mode calls that default to a zero or constant IV (if detectable).

By catching these patterns, we ensure IVs are not hard-coded or predictable
when using CBC mode, covering CWE-329.
"""

import ast
from typing import List, Optional

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    get_full_attr_name,
    is_string_literal,
    is_bytes_literal,
    get_constant_value,
)


class Cwe329PredictableIVRule(Rule):
    @property
    def name(self) -> str:
        return "CWE329PredictableIV"

    @property
    def description(self) -> str:
        return (
            "CBC‐mode cipher is initialized with a predictable or literal IV, "
            "making the encryption vulnerable (CWE-329)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-329"]

    # Recognize CBC mode attributes
    _cbc_mode_names = {"mode_cbc", "cbc"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            # We only care about calls to <CipherClass>.new(...)
            if not isinstance(func, ast.Attribute) or func.attr != "new":
                continue
            full_cipher = get_full_attr_name(func.value).lower()
            # Ensure it’s a PyCrypto/PyCryptodome or similar cipher class
            if "crypto.cipher" not in full_cipher:
                continue

            # Locate mode and iv keywords (if present)
            mode_value = self._get_keyword_arg(node, "mode")
            iv_value = self._get_keyword_arg(node, "iv")

            # If mode is not explicitly CBC, try positional mode (second positional argument)
            if mode_value is None and len(node.args) >= 2:
                mode_value = node.args[1]

            # If mode_value indicates CBC
            if mode_value and self._is_cbc_mode(mode_value):
                # If iv is explicitly provided as a literal
                if iv_value and self._is_literal_iv(iv_value):
                    findings.append(self._make_finding(iv_value, file_path))
                    continue
                # If iv is omitted, many libraries default to all-zero IV
                if iv_value is None:
                    findings.append(self._make_finding(node, file_path))
                    continue

        return findings

    def _get_keyword_arg(self, node: ast.Call, name: str) -> Optional[ast.AST]:
        """
        Return the AST node corresponding to keyword `name` in the call, or None.
        """
        for kw in node.keywords:
            if kw.arg == name:
                return kw.value
        return None

    def _is_cbc_mode(self, node: ast.AST) -> bool:
        """
        Return True if the AST node corresponds to CBC mode, either via an attribute
        like AES.MODE_CBC or a literal string "CBC".
        """
        # Attribute: check full dotted name ends with ".mode_cbc"
        if isinstance(node, ast.Attribute):
            full = get_full_attr_name(node).lower()
            return full.endswith(".mode_cbc")
        # Name: maybe imported as MODE_CBC
        if isinstance(node, ast.Name):
            return node.id.lower() == "mode_cbc"  # e.g., if from AES import MODE_CBC
        # String literal: "CBC"
        if is_string_literal(node):
            val = get_constant_value(node)
            if isinstance(val, str) and val.lower() == "cbc":
                return True
        return False

    def _is_literal_iv(self, node: ast.AST) -> bool:
        """
        Return True if node is a literal IV (string or bytes) or numeric repeating zero.
        """
        # Bytes or string literal
        if is_bytes_literal(node) or is_string_literal(node):
            return True
        # Numeric literal (e.g., 0 indicates single‐byte IV of zero)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return True
        return False

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        """
        Construct a Finding at the node’s location.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
