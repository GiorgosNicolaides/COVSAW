# cryptoanalyzer/rules/algorithm_params/cwe_257_recoverable_storage.py

"""
Rule to detect storing passwords in a recoverable (reversible) format (CWE-257).

This rule flags any use of a reversible encryption API (e.g., AES, DES, Fernet)
where the plaintext argument is a “password”-like variable or literal, implying
that the password can be recovered rather than hashed irreversibly.

Patterns detected include:
  1. Calls to Crypto.Cipher.<ALG>.new(...).encrypt(<password_arg>)
  2. Calls to <ALG>.encrypt(<password_arg>) when <ALG> is a known symmetric cipher
     (e.g., AES, DES, ARC4) or Fernet from cryptography.
  3. Direct calls to Fernet.encrypt(<password_arg>).
  4. Calls to any “encrypt” method on an object or class whose dotted name includes
     “Crypto.Cipher” or “cryptography.fernet”.

By catching all these patterns, we ensure no password is stored using a reversible
cipher instead of a one-way hash.
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    get_full_attr_name,
    is_string_literal,
    is_name_or_attr,
)


class Cwe257RecoverableStorageRule(Rule):
    @property
    def name(self) -> str:
        return "CWE257RecoverableStorage"

    @property
    def description(self) -> str:
        return (
            "Password is being encrypted using a reversible cipher (e.g., AES, DES, Fernet), "
            "allowing recovery of the plaintext rather than hashing it irreversibly."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-257"]

    # Variable names that imply password-like data
    _password_vars = {"password", "passwd", "pwd", "pass"}

    # Known reversible cipher module prefixes
    _cipher_prefixes = {
        "crypto.cipher",        # PyCryptodome/PyCrypto
        "cryptography.fernet",   # cryptography.io
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # Only inspect calls to .encrypt(...)
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            # We look for Attribute nodes ending with .encrypt
            if isinstance(func, ast.Attribute) and func.attr.lower() == "encrypt":
                # Reconstruct the full dotted name of the receiver
                full_name = get_full_attr_name(func.value).lower()

                # If the receiver’s module path contains a known reversible cipher prefix
                if any(full_name.startswith(prefix) for prefix in self._cipher_prefixes) or any(
                    prefix in full_name for prefix in ("aes", "des", "arc4", "chacha20", "blowfish")
                ):
                    # Check if the first argument to encrypt() is a password-like variable or literal
                    if node.args:
                        arg0 = node.args[0]
                        # Literal string passed directly to encrypt("mypassword")
                        if is_string_literal(arg0):
                            findings.append(self._make_finding(node, file_path))
                            continue
                        # Variable passed to encrypt, check if its name implies a password
                        if isinstance(arg0, ast.Name) and arg0.id.lower() in self._password_vars:
                            findings.append(self._make_finding(node, file_path))
                            continue

                    # Also consider keyword argument “data=…” or “plaintext=…”
                    for kw in node.keywords:
                        if kw.arg and kw.arg.lower() in {"data", "message", "plaintext"}:
                            value = kw.value
                            if is_string_literal(value):
                                findings.append(self._make_finding(node, file_path))
                                break
                            if isinstance(value, ast.Name) and value.id.lower() in self._password_vars:
                                findings.append(self._make_finding(node, file_path))
                                break

            # Additionally, catch calls like Fernet(<key>).encrypt(<password>)
            # where Fernet is used directly
            if isinstance(func, ast.Attribute) and func.attr.lower() == "encrypt":
                # Check if the base is an instance of Fernet (cryptography.fernet.Fernet)
                full = get_full_attr_name(func.value).lower()
                if "cryptography.fernet.fernet" in full:
                    if node.args:
                        arg0 = node.args[0]
                        if is_string_literal(arg0):
                            findings.append(self._make_finding(node, file_path))
                            continue
                        if isinstance(arg0, ast.Name) and arg0.id.lower() in self._password_vars:
                            findings.append(self._make_finding(node, file_path))
                            continue

        return findings

    def _make_finding(self, node: ast.Call, file_path: str) -> Finding:
        """
        Build a Finding at the call node's location.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
