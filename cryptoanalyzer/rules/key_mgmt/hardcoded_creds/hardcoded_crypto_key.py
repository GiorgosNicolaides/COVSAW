# cryptoanalyzer/rules/credentials/cwe_321_hardcoded_crypto_key.py

"""
Rule to detect Use of Hard-coded Cryptographic Key (CWE-321).

This rule flags any hard-coded cryptographic key literal in source code, including:
  1. Assignments of string or bytes literals to variables whose names suggest a key
     (e.g., “key”, “secret_key”, “enc_key”, “private_key”, “public_key”).
  2. Function parameters with default string/bytes literals for key-like arguments.
  3. Dictionary literals containing “key”-like keys paired with string or bytes literals.
  4. Direct use of literals in cipher constructors, e.g.:
       • AES.new(key=b"...", ...)
       • DES3.new(key=b"...", ...)
       • Fernet(b"...")
  5. Literal key as salt/IV parameters to symmetric ciphers when the parameter name
     signifies a key (to catch misnamed implementations).

By catching these patterns, we ensure no symmetric or asymmetric key is embedded
directly in code.
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


class Cwe321HardcodedCryptoKeyRule(Rule):
    @property
    def name(self) -> str:
        return "CWE321HardcodedCryptoKey"

    @property
    def description(self) -> str:
        return (
            "A cryptographic key is hard-coded in the source (string or bytes literal)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-321"]

    # Variable-name fragments that imply a cryptographic key
    _key_name_fragments = {
        "key", "secret_key", "enc_key", "encryption_key",
        "private_key", "public_key", "hmac_key", "mac_key",
        "signing_key", "verify_key"
    }

    # Common cipher constructors to check for literal key parameters
    _cipher_constructors = {
        # PyCryptodome/PyCrypto
        "crypto.cipher.aes.new",
        "crypto.cipher.des.new",
        "crypto.cipher.des3.new",
        "crypto.cipher.arc4.new",
        "crypto.cipher.blowfish.new",
        "crypto.cipher.cast5.new",
        "crypto.cipher.idea.new",
        "crypto.cipher.rc2.new",
        # cryptography.io Fernet
        "cryptography.fernet.fernet",
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # ------------------------------------------------------------
            # 1) Assignment: key_var = "literal" or b"literal"
            # ------------------------------------------------------------
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if self._contains_key_fragment(var_name):
                            # Value is a string or bytes literal or numeric literal
                            val_node = node.value
                            if is_string_literal(val_node) or is_bytes_literal(val_node):
                                findings.append(self._make_finding(node, file_path))
                                break

            # ------------------------------------------------------------
            # 2) FunctionDef defaults: def fn(key="...", secret_key=b"...")
            # ------------------------------------------------------------
            elif isinstance(node, ast.FunctionDef):
                defaults = node.args.defaults
                args = node.args.args[-len(defaults):] if defaults else []
                for arg, default in zip(args, defaults):
                    arg_name = arg.arg.lower()
                    if self._contains_key_fragment(arg_name):
                        if is_string_literal(default) or is_bytes_literal(default):
                            findings.append(self._make_finding(default, file_path))

            # ------------------------------------------------------------
            # 3) Dictionary literal with “key”-like key and literal value
            # ------------------------------------------------------------
            elif isinstance(node, ast.Dict):
                keys = extract_string_from_dict_key(node)
                for key_str in keys:
                    key_lower = key_str.lower()
                    if self._contains_key_fragment(key_lower):
                        # Find the value node corresponding to that key
                        for k_node, v_node in zip(node.keys, node.values):
                            if (
                                isinstance(k_node, ast.Constant)
                                and isinstance(k_node.value, str)
                                and k_node.value.lower() == key_lower
                            ):
                                if is_string_literal(v_node) or is_bytes_literal(v_node):
                                    findings.append(self._make_finding(node, file_path))
                                    break
                        break

            # ------------------------------------------------------------
            # 4) Literal key in cipher constructors: AES.new(key=b"...", ...), Fernet(b"...")
            # ------------------------------------------------------------
            elif isinstance(node, ast.Call):
                func = node.func
                full = get_full_attr_name(func).lower()

                # 4a) Direct Fernet(b"...")
                if full == "cryptography.fernet.fernet":
                    # First positional arg is the key
                    if node.args:
                        arg0 = node.args[0]
                        if is_string_literal(arg0) or is_bytes_literal(arg0):
                            findings.append(self._make_finding(node, file_path))
                            continue

                # 4b) Any cipher.new(...) with key=literal
                if full in self._cipher_constructors:
                    for kw in node.keywords:
                        if kw.arg and kw.arg.lower() in {"key"}:
                            v = kw.value
                            if is_string_literal(v) or is_bytes_literal(v):
                                findings.append(self._make_finding(node, file_path))
                                break
                    continue

            # ------------------------------------------------------------
            # 5) Literal used as key/iv/nonce to a cipher constructor when name implies a key
            #    e.g., AES.new(..., iv=b"...") but variable name “iv” also signals unpredictability
            # ------------------------------------------------------------
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func_full = get_full_attr_name(node.func).lower()
                # Check if it is a cipher.new call
                if func_full.endswith(".new"):
                    for kw in node.keywords:
                        kw_name = kw.arg.lower() if kw.arg else ""
                        if kw_name in {"iv", "nonce", "salt"}:
                            v = kw.value
                            if is_string_literal(v) or is_bytes_literal(v):
                                findings.append(self._make_finding(node, file_path))
                                break

        return findings

    def _contains_key_fragment(self, name: str) -> bool:
        """
        Return True if any fragment in _key_name_fragments appears in `name`.
        """
        return any(fragment in name for fragment in self._key_name_fragments)

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        """
        Build a Finding at the node’s location.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
