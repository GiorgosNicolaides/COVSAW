# cryptoanalyzer/rules/plaintext_secrets/cwe_261_weak_encoding.py

"""
Rule to detect Weak Encoding for Password (CWE-261).

This rule flags any instance where a password (literal or variable) is encoded
using a reversible or weak encoding rather than a secure hash (e.g., base64,
hex, or simple reversible transforms). Patterns include:

  1. Calls to base64.b64encode(...) or base64.b85encode(...) where the argument
     is a string/bytes literal or a variable whose name suggests “password” or “pwd”.

  2. Calls to binascii.hexlify(...) or binascii.b2a_hex(...) with a password-like argument.

  3. Calls to codecs.encode(..., "base64"/"hex") or str.encode("hex") on a password.

  4. Calls to .encode("hex") on a bytes/or str object (Python 2 style) or
     usage of password.encode() followed by .hex() (in Python 3) without further hashing.

By catching these patterns, we ensure passwords are not merely encoded but appropriately hashed.
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    get_full_attr_name,
    is_name_or_attr,
    is_string_literal,
    get_constant_value,
)


class Cwe261WeakEncodingRule(Rule):
    @property
    def name(self) -> str:
        return "CWE261WeakEncoding"

    @property
    def description(self) -> str:
        return (
            "Password is being encoded using a reversible or weak encoding "
            "(e.g., base64, hex) instead of a secure hash."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-261"]

    # Keywords indicating a password-like variable name
    _password_var_keywords = {"password", "passwd", "pwd", "pass"}

    # Recognized weak encoding functions and their full module paths (lowercase)
    _encoding_calls = {
        "base64.b64encode",
        "base64.b85encode",
        "binascii.hexlify",
        "binascii.b2a_hex",
        "codecs.encode",
        # In Python 3, str.encode("hex") isn’t built-in, but bytes.hex() is reversible;
        # however, we cannot easily detect .hex() calls on password variables via AST,
        # so we rely on explicit encoding calls.
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # Only inspect calls
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            # 1) Direct calls: base64.b64encode(arg), base64.b85encode(arg)
            if isinstance(func, ast.Attribute):
                full = get_full_attr_name(func).lower()
                if full in {"base64.b64encode", "base64.b85encode"}:
                    # Ensure argument is password-like: literal or variable with “password” in name
                    if node.args:
                        arg0 = node.args[0]
                        if self._is_password_arg(arg0):
                            findings.append(self._make_finding(node, file_path))
                    continue

                # 2) binascii.hexlify(arg) or binascii.b2a_hex(arg)
                if full in {"binascii.hexlify", "binascii.b2a_hex"}:
                    if node.args:
                        arg0 = node.args[0]
                        if self._is_password_arg(arg0):
                            findings.append(self._make_finding(node, file_path))
                    continue

                # 3) codecs.encode(arg, encoding)
                if full == "codecs.encode":
                    # Expect first arg is data, second is encoding string ("base64" or "hex")
                    if len(node.args) >= 2:
                        data_node = node.args[0]
                        enc_node = node.args[1]
                        if is_string_literal(enc_node):
                            enc = get_constant_value(enc_node).lower()
                            if enc in {"base64", "hex"} and self._is_password_arg(data_node):
                                findings.append(self._make_finding(node, file_path))
                    # Also keyword form: codecs.encode(data=data, encoding="base64")
                    for kw in node.keywords:
                        if kw.arg == "encoding" and is_string_literal(kw.value):
                            enc_val = get_constant_value(kw.value).lower()
                            if enc_val in {"base64", "hex"}:
                                # Find data argument
                                for kw2 in node.keywords:
                                    if kw2.arg in {"data", "obj", None}:
                                        if self._is_password_arg(kw2.value):
                                            findings.append(self._make_finding(node, file_path))
                                            break
                    continue

            # 4) Detect calls like password.encode("hex") in Python 2 style or .hex() in Python 3
            #    Python 3: <bytes>.hex() – but requiring type inference is too complex for AST here.
            #    So we focus on calls to .encode("hex") on a password-like Name or literal.
            if isinstance(func, ast.Attribute) and func.attr == "encode":
                # Check if encoding argument is "hex"
                if node.args:
                    enc_arg = node.args[0]
                    if is_string_literal(enc_arg) and get_constant_value(enc_arg).lower() == "hex":
                        receiver = func.value
                        if self._is_password_arg(receiver):
                            findings.append(self._make_finding(node, file_path))
                        continue

            # 5) Direct use of bytes.hex() or str.hex(): if receiver is password var or literal
            if isinstance(func, ast.Attribute) and func.attr == "hex":
                receiver = func.value
                if self._is_password_arg(receiver):
                    findings.append(self._make_finding(node, file_path))
                    continue

        return findings

    def _is_password_arg(self, node: ast.AST) -> bool:
        """
        Return True if the AST node is:
          - A string or bytes literal that looks like a password (non-empty literal),
          - A variable whose name contains any keyword in _password_var_keywords.
        """
        # Literal string or bytes passed directly
        if is_string_literal(node):
            val = get_constant_value(node)
            if isinstance(val, str) and val:
                return True
        if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, bytearray)):
            return True

        # Name or attribute: check if final identifier contains "password", "pwd", etc.
        if isinstance(node, ast.Name):
            return any(kw in node.id.lower() for kw in self._password_var_keywords)
        if isinstance(node, ast.Attribute):
            full = get_full_attr_name(node).lower()
            return any(kw in full for kw in self._password_var_keywords)

        return False

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        """
        Build a Finding pointing to the encoding call.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
