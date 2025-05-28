"""
Module for detecting broken or weak cryptographic algorithm usage.

This rule looks for:
  - Use of insecure hash functions (MD5, SHA-1) via the `hashlib` module,
    direct imports (e.g., `from hashlib import md5`), or the PyCryptodome
    `Crypto.Hash` API.
  - Instantiation of weak block or stream ciphers (DES, 3DES, RC4, Blowfish,
    CAST5, IDEA, RC2) via the PyCryptodome `Crypto.Cipher` API.

Findings are tagged with:
  - CWE-327: Use of a Broken or Risky Cryptographic Algorithm
  - CWE-328: Use of a Weak Hash
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class BrokenOrWeakAlgorithmRule(Rule):
    @property
    def name(self) -> str:
        return "BrokenOrWeakAlgorithm"

    @property
    def description(self) -> str:
        return (
            "Use of a broken or weak cryptographic algorithm "
            "(e.g., MD5, SHA-1, DES, RC4, etc.)"
        )

    @property
    def cwe_ids(self) -> List[str]:
        # CWE-327 covers broken/risks; CWE-328 covers weak hashes
        return ["CWE-327", "CWE-328"]

    # Lowercase names of known-weak hash algorithms
    _weak_hashes = {"md5", "sha1"}

    # Lowercase names of known-weak cipher algorithms
    _weak_ciphers = {"des", "des3", "rc4", "blowfish", "cast5", "idea", "rc2"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """
        Walk the AST of a module, looking for:
          1) Calls to hashlib.<hash>() or direct md5(data), sha1(data).
          2) Calls to Crypto.Hash.<HASH>.new(...) for weak hashes.
          3) Calls to <Cipher>.new(...) or Crypto.Cipher.<CIPHER>.new(...) for weak ciphers.
        """
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # Only interested in function or constructor calls
            if not isinstance(node, ast.Call):
                continue

            # CASE A: hashlib.md5(...) or hashlib.sha1(...)
            if isinstance(node.func, ast.Attribute):
                # e.g. hashlib.md5, hashlib.sha1
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "hashlib"
                    and node.func.attr.lower() in self._weak_hashes
                ):
                    findings.append(self._make_finding(node, file_path))
                    continue

                # e.g. Crypto.Hash.MD5.new(...) or Crypto.Hash.SHA1.new(...)
                full_name = self._get_full_attr_name(node.func)
                parts = full_name.lower().split(".")
                # look for pattern ['crypto', 'hash', '<hash>', 'new']
                if (
                    len(parts) >= 4
                    and parts[0] == "crypto"
                    and parts[1] == "hash"
                    and parts[-1] == "new"
                    and parts[-2] in self._weak_hashes
                ):
                    findings.append(self._make_finding(node, file_path))
                    continue

                # CASE B: Crypto.Cipher.DES.new(...) or DES.new(...)
                if node.func.attr == "new":
                    # target may be ast.Attribute or ast.Name
                    # e.g. Crypto.Cipher.DES.new(...)
                    target = node.func.value
                    algo_name = None
                    if isinstance(target, ast.Attribute):
                        # extract last part, e.g. DES from Crypto.Cipher.DES
                        algo_name = target.attr.lower()
                    elif isinstance(target, ast.Name):
                        # direct import: DES.new(...)
                        algo_name = target.id.lower()

                    if algo_name in self._weak_ciphers:
                        findings.append(self._make_finding(node, file_path))
                        continue

            # CASE C: direct md5(...) or sha1(...) if imported with `from hashlib import md5`
            elif isinstance(node.func, ast.Name):
                if node.func.id.lower() in self._weak_hashes:
                    findings.append(self._make_finding(node, file_path))
                    continue

        return findings

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        """
        Helper to build a Finding instance at the node's location.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )

    def _get_full_attr_name(self, node: ast.Attribute) -> str:
        """
        Reconstruct the full attribute access path as a dotted string.

        e.g., for Crypto.Hash.MD5.new it returns "Crypto.Hash.MD5.new".
        """
        attrs = []
        current = node
        # collect attribute names
        while isinstance(current, ast.Attribute):
            attrs.insert(0, current.attr)
            current = current.value
        # if base is a Name, include it
        if isinstance(current, ast.Name):
            attrs.insert(0, current.id)
        return ".".join(attrs)
