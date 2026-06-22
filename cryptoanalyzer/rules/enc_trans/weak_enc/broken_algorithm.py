# cryptoanalyzer/rules/algorithm_params/cwe_327_broken_algorithm.py

"""
Rule to detect use of broken or risky cryptographic algorithms (CWE-327).

This rule aggressively flags any invocation of known-weak or broken algorithms, including:
  1. Calls to hashlib.md5(...) or hashlib.sha1(...).
  2. Calls to Crypto.Hash.MD5.new(...) or Crypto.Hash.SHA1.new(...).
  3. Instantiations of weak ciphers via Crypto.Cipher.<ALG>.new(...), where <ALG> is one of:
       DES, DES3, ARC4, Blowfish, CAST5, IDEA, RC2.
  4. Direct calls to md5(...) or sha1(...) if imported with `from hashlib import md5, sha1`.
  5. Any reference to “MD5” or “SHA1” in a digest-selecting position (e.g., HMAC using “MD5”).

By catching all these patterns, we ensure no code scanned can silently invoke a broken
hash or cipher without raising a finding for CWE-327.
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    get_full_attr_name,
    is_call_to,
    is_string_literal,
    is_name_or_attr,
)


class Cwe327BrokenAlgorithmRule(Rule):
    @property
    def name(self) -> str:
        return "CWE327BrokenAlgorithm"

    @property
    def description(self) -> str:
        return (
            "Use of a broken or risky cryptographic algorithm "
            "(e.g., MD5, SHA-1, DES, ARC4, Blowfish, CAST5, IDEA, RC2)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-327"]

    # Weak hash function names (lowercase)
    _weak_hashes = {"md5", "sha1"}

    # Weak cipher class names (lowercase)
    _weak_ciphers = {"des", "des3", "arc4", "blowfish", "cast5", "idea", "rc2"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # Only interested in call expressions
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            # --- 1) hashlib.md5(...) or hashlib.sha1(...) ---
            if is_call_to(node, "hashlib", "md5") or is_call_to(node, "hashlib", "sha1"):
                findings.append(self._make_finding(node, file_path))
                continue

            # --- 2) direct md5(...) or sha1(...) if imported via `from hashlib import md5, sha1` ---
            if isinstance(func, ast.Name) and func.id.lower() in self._weak_hashes:
                findings.append(self._make_finding(node, file_path))
                continue

            # --- 3) Crypto.Hash.MD5.new(...) or Crypto.Hash.SHA1.new(...) ---
            # and similar patterns where the module path ends in “.md5” or “.sha1”
            if isinstance(func, ast.Attribute) and func.attr == "new":
                full = get_full_attr_name(func.value).lower()
                # e.g. "crypto.hash.md5"
                for weak in self._weak_hashes:
                    if full.endswith(f"crypto.hash.{weak}"):
                        findings.append(self._make_finding(node, file_path))
                        break
                else:
                    # also catching direct imports: from Crypto.Hash.MD5 import new
                    parts = full.split(".")
                    if any(part == weak for weak in self._weak_hashes for part in parts):
                        findings.append(self._make_finding(node, file_path))
                continue

            # --- 4) Crypto.Cipher.<ALG>.new(...) or <ALG>.new(...) for weak ciphers ---
            if isinstance(func, ast.Attribute) and func.attr == "new":
                full = get_full_attr_name(func.value).lower()
                # Check if any weak cipher name is in the attribute chain
                for cipher in self._weak_ciphers:
                    if full.endswith(f"crypto.cipher.{cipher}") or full.split(".")[-1] == cipher:
                        findings.append(self._make_finding(node, file_path))
                        break
                continue

            # --- 5) HMAC or similar using a weak digest explicitly ---
            # For example: hmac.new(key, msg, hashlib.md5) or hmac.new(key, msg, "md5")
            if is_call_to(node, "hmac", "new"):
                # Check positional 3rd argument
                if len(node.args) >= 3:
                    arg2 = node.args[2]
                    if self._is_weak_digest_node(arg2):
                        findings.append(self._make_finding(node, file_path))
                        continue
                # Check keyword digestmod
                for kw in node.keywords:
                    if kw.arg == "digestmod" and self._is_weak_digest_node(kw.value):
                        findings.append(self._make_finding(node, file_path))
                        break

        return findings

    def _is_weak_digest_node(self, node: ast.AST) -> bool:
        """
        Return True if the AST node indicates a weak digest:
          - Name node: md5, sha1
          - Attribute node: hashlib.md5, Crypto.Hash.MD5, etc.
          - String literal: "md5", "sha1"
        """
        # literal string
        if is_string_literal(node):
            val = get_full_attr_name(node).lower() if isinstance(node, ast.Attribute) else node.value.lower()
            return val in self._weak_hashes

        # name or attribute
        if isinstance(node, ast.Name):
            return node.id.lower() in self._weak_hashes
        if isinstance(node, ast.Attribute):
            full = get_full_attr_name(node).lower()
            return any(full.endswith(f".{weak}") for weak in self._weak_hashes)

        return False

    def _make_finding(self, node: ast.Call, file_path: str) -> Finding:
        """
        Construct a Finding at the node's location.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
