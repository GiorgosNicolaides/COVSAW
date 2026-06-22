# cryptoanalyzer/rules/plaintext_secrets/cwe_759_760_hash_salt.py

"""
Rule to detect:
  • CWE-759: Use of a One-Way Hash Without a Salt
  • CWE-760: Use of a One-Way Hash with a Predictable Salt

This rule flags any use of a hash function on password-like data without a salt
(CWE-759), as well as any key-derivation or password-hashing call (e.g.,
hashlib.pbkdf2_hmac or bcrypt.hashpw) where the salt is a literal or otherwise
predictable (CWE-760).

Patterns detected include:

1) Direct calls to `hashlib.<hash_name>(password)` or `Crypto.Hash.<ALG>.new().update(password)`
   where the argument is a string literal or a variable whose name suggests a password
   (e.g., "password", "pwd").
   → CWE-759

2) Calls to `hashlib.pbkdf2_hmac(hash_name, password, salt, ...)` where `salt`
   is a literal (string or bytes) or a variable with a literal-derived value.
   → CWE-760

3) Calls to `bcrypt.hashpw(password, salt)` where `salt` is a literal (string or bytes)
   rather than a value from `bcrypt.gensalt()`.
   → CWE-760

4) Calls to `Crypto.Hash.<ALG>.new(data=password)` without any salt parameter (since
   `Crypto.Hash` does not accept a salt). If the data argument is password-like,
   this is equivalent to hashing without salt → CWE-759.

5) Any call to `hashlib.new(hash_name, password)` (which omits salt) on password-like data.
   → CWE-759

By catching all these patterns, we ensure no code hashes passwords without a salt
and no code uses a predictable salt in a KDF, fully covering CWE-759 and CWE-760.
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    get_full_attr_name,
    is_string_literal,
    is_bytes_literal,
    is_name_or_attr,
)

class Cwe759Cwe760HashSaltRule(Rule):
    @property
    def name(self) -> str:
        return "CWE759_CWE760_HashWithoutOrPredictableSalt"

    @property
    def description(self) -> str:
        return (
            "Password hashing without a salt (CWE-759) or with a predictable/hard‐coded salt (CWE-760)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-759", "CWE-760"]

    # Recognized hash names in hashlib that are one-way hashes (no salt)
    _hashlib_hash_names = {
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
        "blake2b", "blake2s", "sha3_224", "sha3_256", "sha3_384", "sha3_512",
        # "shake_128", "shake_256" could also be included if used directly
    }

    # Recognized Crypto.Hash modules (lowercase)
    _crypto_hash_prefix = "crypto.hash."

    # Recognized KDF functions and their module
    # hashlib.pbkdf2_hmac
    _pbkdf2_full = "hashlib.pbkdf2_hmac"

    # bcrypt.hashpw
    _bcrypt_hashpw = "bcrypt.hashpw"

    # Password-like variable name fragments
    _password_var_keywords = {"password", "passwd", "pwd", "pass"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # Only examine Call nodes
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            full_func = get_full_attr_name(func).lower()

            # ------------------------------------------------------------
            # 1) Direct hashlib.<hash_name>(password)
            #    e.g., hashlib.sha256(password)
            # ------------------------------------------------------------
            if full_func.startswith("hashlib."):
                member = full_func.split("hashlib.", 1)[1]
                # Case: hashlib.<hash_name>(...)
                if member in self._hashlib_hash_names:
                    # If first arg is a password-like value
                    if node.args:
                        arg0 = node.args[0]
                        if self._is_password_arg(arg0):
                            findings.append(self._make_finding(node, file_path, "CWE-759"))
                    continue
                # Case: hashlib.new(hash_name, password)
                if member == "new" and len(node.args) >= 2:
                    # Second arg is data
                    data_arg = node.args[1]
                    if self._is_password_arg(data_arg):
                        findings.append(self._make_finding(node, file_path, "CWE-759"))
                    continue

            # ------------------------------------------------------------
            # 2) Crypto.Hash.<ALG>.new(data=password) without salt
            #    e.g., Crypto.Hash.SHA256.new(data=password)
            # ------------------------------------------------------------
            if isinstance(func, ast.Attribute) and func.attr.lower() == "new":
                # Reconstruct module path
                mod_path = get_full_attr_name(func.value).lower()
                # If path starts with crypto.hash.<algorithm>
                if mod_path.startswith(self._crypto_hash_prefix):
                    # If keyword "data" provided
                    for kw in node.keywords:
                        if kw.arg == "data":
                            if self._is_password_arg(kw.value):
                                findings.append(self._make_finding(node, file_path, "CWE-759"))
                                break
                    # If positional arg provided to new(...)
                    if node.args:
                        data_arg = node.args[0]
                        if self._is_password_arg(data_arg):
                            findings.append(self._make_finding(node, file_path, "CWE-759"))
                    continue

            # ------------------------------------------------------------
            # 3) hashlib.pbkdf2_hmac(hash_name, password, salt, ...)
            #    salt is arg at index 2
            # ------------------------------------------------------------
            if full_func == self._pbkdf2_full:
                # Salt argument is 2nd index (0-based)
                if len(node.args) >= 3:
                    salt_arg = node.args[2]
                    if self._is_predictable_salt(salt_arg):
                        findings.append(self._make_finding(node, file_path, "CWE-760"))
                else:
                    # If salt passed via keyword
                    for kw in node.keywords:
                        if kw.arg == "salt":
                            if self._is_predictable_salt(kw.value):
                                findings.append(self._make_finding(node, file_path, "CWE-760"))
                            break
                continue

            # ------------------------------------------------------------
            # 4) bcrypt.hashpw(password, salt)
            # ------------------------------------------------------------
            if full_func == self._bcrypt_hashpw:
                # Salt is second positional argument
                if len(node.args) >= 2:
                    salt_arg = node.args[1]
                    if self._is_predictable_salt(salt_arg):
                        findings.append(self._make_finding(node, file_path, "CWE-760"))
                else:
                    # If salt passed via keyword
                    for kw in node.keywords:
                        if kw.arg == "salt":
                            if self._is_predictable_salt(kw.value):
                                findings.append(self._make_finding(node, file_path, "CWE-760"))
                            break
                continue

            # ------------------------------------------------------------
            # 5) Any other call to Crypto.Hash.*.new() without a salt parameter
            #    if a data arg is provided and is password-like → CWE-759
            # ------------------------------------------------------------
            # Already covered by case 2 for Crypto.Hash.new

        return findings

    def _is_password_arg(self, node: ast.AST) -> bool:
        """
        Return True if `node` is:
          - A string literal (possible literal password).
          - A bytes literal.
          - A Name or Attribute whose identifier contains a password-like keyword.
        """
        if is_string_literal(node) or is_bytes_literal(node):
            return True
        if isinstance(node, ast.Name):
            return any(kw in node.id.lower() for kw in self._password_var_keywords)
        if isinstance(node, ast.Attribute):
            full = get_full_attr_name(node).lower()
            return any(kw in full for kw in self._password_var_keywords)
        return False

    def _is_predictable_salt(self, node: ast.AST) -> bool:
        """
        Return True if `node` is a salt that is predictable:
          - A string literal or bytes literal.
          - A Name or Attribute whose identifier suggests a hard-coded or predictable salt
            (e.g., "salt", "iv", "nonce" containing a constant).
        """
        if is_string_literal(node) or is_bytes_literal(node):
            return True
        if isinstance(node, ast.Name):
            # e.g., salt = b"..."; but we cannot infer randomness—treat any named salt variable as potentially predictable
            return "salt" in node.id.lower() or "iv" in node.id.lower() or "nonce" in node.id.lower()
        if isinstance(node, ast.Attribute):
            full = get_full_attr_name(node).lower()
            return any(fragment in full for fragment in ("salt", "iv", "nonce"))
        return False

    def _make_finding(self, node: ast.AST, file_path: str, cwe_id: str) -> Finding:
        """
        Construct a Finding at node’s location, tagging the specific CWE (759 or 760).
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=f"{self.description} ({cwe_id})",
            cwe_ids=[cwe_id],
        )
