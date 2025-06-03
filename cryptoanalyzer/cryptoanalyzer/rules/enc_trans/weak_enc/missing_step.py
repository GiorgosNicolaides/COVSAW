# cryptoanalyzer/rules/algorithm_params/cwe_325_missing_step.py

"""
Rule to detect Missing Required Cryptographic Step (CWE-325).

This rule flags encryption operations (via symmetric ciphers) that do not
perform an accompanying integrity check (e.g., HMAC). In other words, if code
encrypts data with a reversible cipher (AES, DES, etc.) without computing
or verifying an HMAC (or similar MAC) in the same function or module scope,
it is likely missing a required step, resulting in weaker protection.

Patterns detected include:
  1. Any call to Crypto.Cipher.<ALG>.new(...).encrypt(...) or <ALG>.encrypt(...)
     within a function or module, where <ALG> is a known symmetric cipher
     (AES, DES, 3DES, ARC4, Blowfish, CAST5, IDEA, RC2, ChaCha20, etc.).
  2. Absence of any HMAC computation (hmac.new(...)) or Crypto.Hash.HMAC.new(...)
     or cryptography.hazmat.primitives.hmac.HMAC(...) in the *same function
     definition* or in module-top-level code containing the encrypt call.
  3. For ChaCha20-Poly1305 or GCM modes (authenticated ciphers), this rule
     does NOT flag, as integrity is built-in. We identify those by searching
     for “ChaCha20_Poly1305” or “AESGCM” in the constructor chain.

By enforcing this rule, we ensure no encryption step is performed without the
necessary message authentication step (HMAC) at the same scope, thus covering
CWE-325 in the context of missing integrity steps for symmetric encryption.
"""

import ast
from typing import Dict, List, Set, Tuple

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import get_full_attr_name, is_call_to, is_name_or_attr


class Cwe325MissingStepRule(Rule):
    @property
    def name(self) -> str:
        return "CWE325MissingStep"

    @property
    def description(self) -> str:
        return (
            "Encryption performed with a symmetric cipher without a corresponding "
            "integrity (HMAC) step in the same scope (Missing Required Cryptographic Step)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-325"]

    # Recognize symmetric‐cipher constructor chains (lowercase) that imply a reversible cipher
    _symmetric_cipher_prefixes = {
        "crypto.cipher.aes",
        "crypto.cipher.des",
        "crypto.cipher.des3",
        "crypto.cipher.arc4",
        "crypto.cipher.blowfish",
        "crypto.cipher.cast5",
        "crypto.cipher.idea",
        "crypto.cipher.rc2",
        "crypto.cipher.chacha20",    # ChaCha20 (not ChaCha20-Poly1305)
    }

    # Recognize authenticated cipher classes (no need for HMAC)
    _authenticated_cipher_identifiers = {
        "cryptography.hazmat.primitives.ciphers.aead.aesgcm",
        "cryptography.hazmat.primitives.ciphers.aead.chacha20_poly1305",
        "aesgcm", "chacha20poly1305"
    }

    # Identify HMAC‐related constructors or functions
    _hmac_calls = {
        "hmac.new",
        "crypto.hash.hmac.new",  # PyCrypto/PyCryptodome
        "cryptography.hazmat.primitives.hmac.hmac",
        "cryptography.hazmat.primitives.hmac.HMAC"
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """
        For each FunctionDef (or module-level scope), gather all
        symmetric-cipher encrypt calls and check if any HMAC is computed.
        If an encrypt call exists without a corresponding HMAC call,
        flag that encrypt call.
        """
        findings: List[Finding] = []

        # Map each scope (FunctionDef node or top‐level None) to:
        #   • cipher_encrypt_nodes: Set of ast.Call nodes invoking .encrypt(...)
        #   • has_hmac: whether an HMAC‐related call exists in that scope
        scope_data: Dict[ast.AST, Dict[str, object]] = {}

        # Helper to get or create data for a given scope node
        def get_scope(node: ast.AST) -> Dict[str, object]:
            if node not in scope_data:
                scope_data[node] = {
                    "cipher_encrypt_nodes": set(),  # type: Set[ast.Call]
                    "has_hmac": False             # type: bool
                }
            return scope_data[node]

        # First pass: Walk AST and record encrypt/HMAC per scope
        for node in ast.walk(tree):
            # Determine the nearest enclosing scope: FunctionDef or Module
            scope = self._enclosing_scope(node)

            # 1) Detect HMAC calls
            if isinstance(node, ast.Call):
                # Reconstruct the full attribute/name
                func = node.func
                # Using get_full_attr_name to catch attribute chains
                full = get_full_attr_name(func).lower()

                # If call matches any known HMAC pattern → mark scope has_hmac = True
                for hmac_id in self._hmac_calls:
                    if full.startswith(hmac_id):
                        get_scope(scope)["has_hmac"] = True
                        break

            # 2) Detect symmetric cipher encrypt calls
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr.lower() == "encrypt":
                    # Reconstruct receiver’s full name
                    receiver = node.func.value
                    recv_full = get_full_attr_name(receiver).lower()

                    # Skip authenticated ciphers (AESGCM, ChaCha20-Poly1305)
                    if any(auth_id in recv_full for auth_id in self._authenticated_cipher_identifiers):
                        continue

                    # Check if receiver chain includes any symmetric cipher prefix
                    for prefix in self._symmetric_cipher_prefixes:
                        if recv_full.startswith(prefix) or recv_full.endswith(prefix.split(".")[-1]):
                            # Found an encrypt on a reversible cipher
                            get_scope(scope)["cipher_encrypt_nodes"].add(node)
                            break

        # Second pass: For each scope, if encrypt exists without HMAC, flag each encrypt node
        for scope_node, data in scope_data.items():
            if data["cipher_encrypt_nodes"] and not data["has_hmac"]:
                for encrypt_call in data["cipher_encrypt_nodes"]:
                    findings.append(self._make_finding(encrypt_call, file_path))

        return findings

    def _enclosing_scope(self, node: ast.AST) -> ast.AST:
        """
        Walk up parents until we find a FunctionDef or the Module node.
        We attach a parent reference to each node in AST to make this possible.
        If no FunctionDef is found, return a sentinel representing module-level scope.
        """
        current = node
        while hasattr(current, "parent"):
            current = current.parent
            if isinstance(current, ast.FunctionDef):
                return current
        # If we reached the top, use a unique key for module scope
        return None  # None key in scope_data stands for module‐level

    def _make_finding(self, node: ast.Call, file_path: str) -> Finding:
        """
        Build a Finding for a detected missing step at the encrypt call.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
