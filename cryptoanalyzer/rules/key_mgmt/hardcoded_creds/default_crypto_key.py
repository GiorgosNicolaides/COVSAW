# cryptoanalyzer/rules/credentials/cwe_1394_default_crypto_key.py

"""
Rule to detect Use of Default Cryptographic Key (CWE-1394).

This rule flags any use of a known default or placeholder cryptographic key
in source code, including:
  1. Assignments of empty or trivial key literals to variables whose names
     imply a cryptographic key (e.g., “key”, “secret_key”, “enc_key”).
  2. Function parameters with default key-like names set to trivial or known
     default values (e.g., "default_key", "changeme", "", b"\x00...\x00").
  3. Dictionary literals containing key-like keys mapped to trivial or known
     default values.
  4. Passing a trivial or known default literal as the key argument to cipher
     constructors, such as:
       • AES.new(key=b"", ...)
       • DES3.new(key=b"\x00"*8, ...)
       • Fernet(b"")  (empty key)
       • Any use of a literal exactly matching a common default key phrase.
By catching these patterns, we ensure no default or placeholder key remains
in the code, fulfilling CWE-1394.
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


class Cwe1394DefaultCryptoKeyRule(Rule):
    @property
    def name(self) -> str:
        return "CWE1394DefaultCryptoKey"

    @property
    def description(self) -> str:
        return (
            "A cryptographic key is left as a known default or trivial literal "
            "(e.g., empty string/bytes, ‘default_key’, ‘changeme’, zero‐bytes)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-1394"]

    # Fragments in variable or dictionary‐key names that imply a cryptographic key
    _key_name_fragments = {
        "key", "secret_key", "enc_key", "encryption_key",
        "hmac_key", "mac_key", "signing_key", "verify_key", "private_key", "public_key"
    }

    # Known default or trivial key literals (lowercase for strings; bytes tested separately)
    _default_key_literals = {
        "",                # empty string
        "default",         # generic placeholder
        "default_key",
        "changeme",
        "password",
        "passphrase",
        "12345678",        # short trivial key
        "0123456789abcdef",# example placeholder
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # ------------------------------------------------------------
            # 1) Assignment: key_var = "" or "default_key" or b"\x00...\x00"
            # ------------------------------------------------------------
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        var_name = tgt.id.lower()
                        if self._contains_key_fragment(var_name):
                            val_node = node.value
                            if self._is_default_key_node(val_node):
                                findings.append(self._make_finding(node, file_path))
                                break

            # ------------------------------------------------------------
            # 2) FunctionDef defaults: def fn(key="changeme", salt=b"\x00\x00")
            # ------------------------------------------------------------
            elif isinstance(node, ast.FunctionDef):
                defaults = node.args.defaults
                args = node.args.args[-len(defaults):] if defaults else []
                for arg, default in zip(args, defaults):
                    arg_name = arg.arg.lower()
                    if self._contains_key_fragment(arg_name) and self._is_default_key_node(default):
                        findings.append(self._make_finding(default, file_path))

            # ------------------------------------------------------------
            # 3) Dictionary literal: {"encryption_key": "default_key", "iv": b"\x00\x00"}
            # ------------------------------------------------------------
            elif isinstance(node, ast.Dict):
                keys = extract_string_from_dict_key(node)
                for key_str in keys:
                    key_lower = key_str.lower()
                    if self._contains_key_fragment(key_lower):
                        # Find matching value node
                        for k_node, v_node in zip(node.keys, node.values):
                            if (
                                isinstance(k_node, ast.Constant)
                                and isinstance(k_node.value, str)
                                and k_node.value.lower() == key_lower
                            ):
                                if self._is_default_key_node(v_node):
                                    findings.append(self._make_finding(node, file_path))
                                    break
                        break

            # ------------------------------------------------------------
            # 4) Cipher constructors with key=<literal> or positional key
            #    AES.new(key=b"", ...) or Fernet(b"")
            # ------------------------------------------------------------
            elif isinstance(node, ast.Call):
                func = node.func
                full = get_full_attr_name(func).lower()

                # 4a) Fernet(b"") or Fernet("changeme")
                if full == "cryptography.fernet.fernet":
                    if node.args:
                        arg0 = node.args[0]
                        if self._is_default_key_node(arg0):
                            findings.append(self._make_finding(node, file_path))
                            continue

                # 4b) Any cipher.new(...) with key=<literal>
                if full.endswith(".new") and (
                    full.startswith("crypto.cipher.aes")
                    or full.startswith("crypto.cipher.des")
                    or full.startswith("crypto.cipher.des3")
                    or full.startswith("crypto.cipher.arc4")
                    or full.startswith("crypto.cipher.blowfish")
                    or full.startswith("crypto.cipher.cast5")
                    or full.startswith("crypto.cipher.idea")
                    or full.startswith("crypto.cipher.rc2")
                ):
                    for kw in node.keywords:
                        if kw.arg and kw.arg.lower() == "key":
                            v = kw.value
                            if self._is_default_key_node(v):
                                findings.append(self._make_finding(node, file_path))
                                break
                    continue

            # ------------------------------------------------------------
            # 5) Literal default IV or nonce that effectively acts as a trivial key
            #    e.g., AES.new(key=b"\x01\x02...", iv=b"\x00\x00\x00\x00\x00\x00\x00\x00")
            # ------------------------------------------------------------
            # (Optional but covered for thoroughness)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func_full = get_full_attr_name(node.func).lower()
                if func_full.endswith(".new"):
                    for kw in node.keywords:
                        kw_name = kw.arg.lower() if kw.arg else ""
                        if kw_name in {"iv", "nonce", "salt"}:
                            v = kw.value
                            if self._is_default_key_node(v):
                                findings.append(self._make_finding(node, file_path))
                                break

        return findings

    def _contains_key_fragment(self, name: str) -> bool:
        """
        Return True if `name` contains any fragment implying a cryptographic key.
        """
        return any(fragment in name for fragment in self._key_name_fragments)

    def _is_default_key_node(self, node: ast.AST) -> bool:
        """
        Return True if the AST node is a string or bytes literal that matches a known
        default or trivial key, or is an empty or zero-filled byte sequence.
        """
        # String literal: check against known default phrases
        if is_string_literal(node):
            val = get_constant_value(node)
            if isinstance(val, str) and val.lower() in self._default_key_literals:
                return True

        # Bytes literal: empty or repeated zero bytes
        if is_bytes_literal(node):
            val = get_constant_value(node)
            if isinstance(val, (bytes, bytearray)):
                # Empty bytes
                if len(val) == 0:
                    return True
                # All-zero bytes
                if all(b == 0 for b in val):
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
