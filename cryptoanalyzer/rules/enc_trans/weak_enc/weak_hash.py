# cryptoanalyzer/rules/algorithm_params/cwe_328_weak_hash.py

"""
Rule to detect use of weak hash algorithms (CWE-328).

This rule flags any invocation of a known-weak hashing primitive, including:
  1. Calls to hashlib.md5(...) or hashlib.sha1(...).
  2. Direct calls to md5(...) or sha1(...) if imported via `from hashlib import md5, sha1`.
  3. Calls to Crypto.Hash.MD5.new(...) or Crypto.Hash.SHA1.new(...).
  4. HMAC constructions that:
       a) Default to MD5 when digestmod is omitted.
       b) Explicitly specify a weak digest like MD5 or SHA-1 as digestmod (positional or keyword).
  5. Any call to hmac.new(...) where the digest algorithm can be inferred as MD5 or SHA-1.

By catching all these patterns, we ensure no code scanned can silently invoke a weak
hash function without raising a finding for CWE-328.
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


class Cwe328WeakHashRule(Rule):
    @property
    def name(self) -> str:
        return "CWE328WeakHash"

    @property
    def description(self) -> str:
        return (
            "Use of a weak or broken hash algorithm (MD5, SHA-1) or HMAC defaulting to MD5."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-328"]

    # Known weak hash function names
    _weak_hashes = {"md5", "sha1"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # Only inspect call expressions
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
            if isinstance(func, ast.Attribute) and func.attr == "new":
                full = get_full_attr_name(func.value).lower()
                # e.g. "crypto.hash.md5"
                for weak in self._weak_hashes:
                    if full.endswith(f"crypto.hash.{weak}") or full.endswith(f"{weak}"):
                        findings.append(self._make_finding(node, file_path))
                        break
                continue

            # --- 4) HMAC cases: hmac.new(...) without secure digestmod or with weak digest ---
            if is_call_to(node, "hmac", "new"):
                # 4a) Default MD5: fewer than 3 positional args AND no digestmod keyword
                pos_args = node.args
                has_digest_kw = any(kw.arg == "digestmod" for kw in node.keywords)
                if len(pos_args) < 3 and not has_digest_kw:
                    findings.append(self._make_finding(node, file_path))
                    continue

                # 4b) Explicit weak digest: positional third argument or digestmod keyword
                explicit_weak = False
                if len(pos_args) >= 3:
                    arg2 = pos_args[2]
                    if self._is_weak_digest_node(arg2):
                        explicit_weak = True

                for kw in node.keywords:
                    if kw.arg == "digestmod" and self._is_weak_digest_node(kw.value):
                        explicit_weak = True
                        break

                if explicit_weak:
                    findings.append(self._make_finding(node, file_path))
                    continue

        return findings

    def _is_weak_digest_node(self, node: ast.AST) -> bool:
        """
        Return True if the AST node indicates a weak digest:
          - Name node: md5, sha1
          - Attribute node: hashlib.md5, Crypto.Hash.MD5, etc.
          - String literal: "md5", "sha1"
        """
        # String literal: "md5" or "sha1"
        if is_string_literal(node):
            value = node.value.lower()
            return value in self._weak_hashes

        # Name: md5, sha1
        if isinstance(node, ast.Name):
            return node.id.lower() in self._weak_hashes

        # Attribute: hashlib.md5 or Crypto.Hash.MD5
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
