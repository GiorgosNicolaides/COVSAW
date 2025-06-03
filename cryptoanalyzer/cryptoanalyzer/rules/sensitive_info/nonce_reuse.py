# cryptoanalyzer/rules/randomness_extra/cwe_323_nonce_reuse.py

"""
Rule to detect Reusing a Nonce or IV in Encryption (CWE-323).

This rule flags any use of the same nonce or IV value more than once in separate
encryption initializations, since nonce/IV reuse can break confidentiality.

Patterns detected include:
  1. Calls to Crypto.Cipher.<ALG>.new(..., iv=<expr> or nonce=<expr>) where the same
     <expr> (literal or variable/attribute) appears in more than one call.
  2. Calls to cryptography.hazmat.primitives.ciphers.Cipher(..., modes.CBC(iv=<expr>)) or
     modes.GCM(nonce=<expr>) where <expr> is reused.
  3. Any keyword argument named “iv” or “nonce” passed to an encryption constructor
     with a repeated value.

By collecting all “iv”/“nonce” arguments across encryption initializations and then
flagging any that occur more than once, we ensure no nonce/IV value is reused.
"""

import ast
from collections import defaultdict
from typing import Dict, List, Tuple

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import get_full_attr_name, is_string_literal, is_bytes_literal


class Cwe323NonceReuseRule(Rule):
    @property
    def name(self) -> str:
        return "CWE323NonceReuse"

    @property
    def description(self) -> str:
        return (
            "The same nonce or IV value is reused in multiple encryption initializations, "
            "breaking cryptographic security (CWE-323)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-323"]

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        # Map from nonce/iv “key” to list of (node, literal_flag) for all occurrences
        # The “key” is a string representing the value: for literals, repr; for names/attributes, full name
        nonce_map: Dict[str, List[ast.Call]] = defaultdict(list)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            # We look for two broad patterns:
            #  A) Crypto.Cipher.<ALG>.new(..., iv=<expr> or nonce=<expr>)
            #  B) cryptography.hazmat.primitives.ciphers.Cipher(..., modes.<MODE>(iv=<expr> or nonce=<expr>))

            # Pattern (A): func is an Attribute with attr “new” and module path contains “crypto.cipher”
            if isinstance(func, ast.Attribute) and func.attr == "new":
                parent_path = get_full_attr_name(func.value).lower()
                if "crypto.cipher" in parent_path:
                    for kw in node.keywords:
                        if kw.arg in {"iv", "nonce"}:
                            key = self._expr_key(kw.value)
                            if key is not None:
                                nonce_map[key].append(node)
                    continue

            # Pattern (B): func is “Cipher” constructor in cryptography
            if isinstance(func, ast.Name) and func.id == "Cipher":
                # Check if imported from cryptography.hazmat.primitives.ciphers
                # We conservatively assume any “Cipher” refers to Crypto or cryptography; so inspect keywords
                for kw in node.keywords:
                    if kw.arg in {"mode"} and isinstance(kw.value, ast.Call):
                        mode_call = kw.value
                        mode_func = mode_call.func
                        mode_full = get_full_attr_name(mode_func).lower()
                        # For CBC: modes.cbc(iv=<expr>)
                        # For GCM: modes.gcm(nonce=<expr>)
                        if ".modes.cbc" in mode_full or mode_full.endswith("cbc"):
                            for m_kw in mode_call.keywords:
                                if m_kw.arg == "iv":
                                    key = self._expr_key(m_kw.value)
                                    if key is not None:
                                        nonce_map[key].append(mode_call)
                            continue
                        if ".modes.gcm" in mode_full or mode_full.endswith("gcm"):
                            for m_kw in mode_call.keywords:
                                if m_kw.arg == "nonce":
                                    key = self._expr_key(m_kw.value)
                                    if key is not None:
                                        nonce_map[key].append(mode_call)
                            continue

            # Pattern (B-alt): func is an Attribute ending with “Cipher” (e.g., ciphers.Cipher)
            if isinstance(func, ast.Attribute) and func.attr == "Cipher":
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Call):
                        mode_call = kw.value
                        mode_func = mode_call.func
                        mode_full = get_full_attr_name(mode_func).lower()
                        if ".modes.cbc" in mode_full or mode_full.endswith("cbc"):
                            for m_kw in mode_call.keywords:
                                if m_kw.arg == "iv":
                                    key = self._expr_key(m_kw.value)
                                    if key is not None:
                                        nonce_map[key].append(mode_call)
                            continue
                        if ".modes.gcm" in mode_full or mode_full.endswith("gcm"):
                            for m_kw in mode_call.keywords:
                                if m_kw.arg == "nonce":
                                    key = self._expr_key(m_kw.value)
                                    if key is not None:
                                        nonce_map[key].append(mode_call)
                            continue

        findings: List[Finding] = []
        # Now flag any key with more than one occurrence
        for key, nodes in nonce_map.items():
            if len(nodes) > 1:
                for call_node in nodes:
                    findings.append(self._make_finding(call_node, file_path))

        return findings

    def _expr_key(self, node: ast.AST) -> str:
        """
        Construct a string key for the expression used as nonce/iv:
          - If literal (string or bytes or numeric), return repr(value).
          - If Name or Attribute, return its full dotted name.
          - Otherwise, return None to skip (e.g., complex expression).
        """
        # String literal
        if is_string_literal(node):
            val = get_constant_value(node)
            return repr(val)
        # Bytes literal
        if is_bytes_literal(node):
            val = get_constant_value(node)
            return repr(val)
        # Numeric literal
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return repr(node.value)
        # Name or attribute: use full attribute/name
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return get_full_attr_name(node)
        return None

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
