
"""
Module for detecting HMAC misuse: defaulting to MD5 and explicit use of weak digestmods.

This rule looks for calls to hmac.new() where:
  1) No digestmod is provided (defaults to MD5), or
  2) A known-weak algorithm (MD5 or SHA-1) is passed as digestmod,
     either positionally or via the `digestmod` keyword.

Findings are tagged with:
  - CWE-328: Use of a Broken or Risky Cryptographic Algorithm
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class HmacDefaultMd5Rule(Rule):
    @property
    def name(self) -> str:
        return "HmacWeakDefault"

    @property
    def description(self) -> str:
        return (
            "Call to hmac.new() without a secure digestmod "
            "(defaults to MD5) or with an explicitly weak digest (MD5/SHA-1)"
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-328"]

    # Digest algorithms we consider “broken” for HMAC
    _weak_algos = {"md5", "sha1"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            # Identify hmac.new(...) calls
            is_hmac_new = (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "hmac"
                and func.attr == "new"
            ) or (
                isinstance(func, ast.Name)
                and func.id == "new"  # assume imported via `from hmac import new`
            )
            if not is_hmac_new:
                continue

            # Did they supply a digestmod at all?
            has_digest_kw = any(kw.arg == "digestmod" for kw in node.keywords)
            pos_args = node.args

            # 1) Default‐MD5 case: fewer than 3 positional args AND no digestmod keyword
            default_md5 = len(pos_args) < 3 and not has_digest_kw

            # 2) Explicit weak‐algo case: check the 3rd positional or keyword digestmod
            explicit_weak = False
            # positional third argument
            if len(pos_args) >= 3:
                explicit_weak = self._is_weak_algo_node(pos_args[2])
            # digestmod=... keyword
            for kw in node.keywords:
                if kw.arg == "digestmod" and self._is_weak_algo_node(kw.value):
                    explicit_weak = True
                    break

            if default_md5 or explicit_weak:
                findings.append(self._make_finding(node, file_path))

        return findings

    def _is_weak_algo_node(self, node: ast.AST) -> bool:
        """
        Return True if this AST node refers to a known-weak algo:
          - Name: md5, sha1
          - Attribute: hashlib.md5, Crypto.Hash.MD5, etc.
          - Constant string: "md5", "sha1"
        """
        # direct string literal
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value.lower() in self._weak_algos

        # names like md5(), sha1()
        if isinstance(node, ast.Name):
            return node.id.lower() in self._weak_algos

        # attribute like hashlib.md5 or Crypto.Hash.SHA1
        if isinstance(node, ast.Attribute):
            attr = node.attr.lower()
            return attr in self._weak_algos

        return False

    def _make_finding(self, node: ast.Call, file_path: str) -> Finding:
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
