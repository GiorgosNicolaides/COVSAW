"""
Module for detecting predictable IV/nonces used in encryption operations.

This rule flags cases where a variable named like “iv” or “nonce” is assigned
a value that is predictably constant or generated with a non‐cryptographic source:

  - Literal bytes (e.g. iv = b'\\x00\\x00...').
  - Zero-initialized buffers (iv = bytes(16), bytearray(16)).
  - Repetition of a literal via multiplication (b'\\x00' * 16).
  - Calls to random.randbytes(...) (Python 3.9+), which uses the non‐cryptographic RNG.

Findings are tagged with:
  - CWE-329: Generation of Predictable IV with CBC Mode
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class PredictableIVRule(Rule):
    @property
    def name(self) -> str:
        return "PredictableIV"

    @property
    def description(self) -> str:
        return "Predictable or non‐cryptographic IV/nonce generation"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-329"]

    # Variable names to consider as IV/nonce holders
    _suspect_vars = {"iv", "nonce"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # Look for assignments like iv = <value> or nonce = <value>
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.lower() in self._suspect_vars:
                        val = node.value
                        if self._is_predictable(val):
                            findings.append(self._make_finding(node, file_path))
        return findings

    def _is_predictable(self, node: ast.AST) -> bool:
        """
        Heuristics for predictability:
          - Constant bytes literal (e.g., b'\\x00...').
          - bytes(N) or bytearray(N) → zero‐filled buffer.
          - Literal * repeat (BinOp with Mult) where one operand is a bytes Constant.
          - random.randbytes(...) calls (non‐crypto RNG).
        """
        # 1) Constant bytes literal
        if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, bytearray)):
            return True

        # 2) Zero‐filled buffer: bytes(N) or bytearray(N)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"bytes", "bytearray"}
            and len(node.args) >= 1
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, int)
        ):
            return True

        # 3) Literal repetition: b'\x00' * N or similar
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            # one side is Constant bytes, other is int
            left, right = node.left, node.right
            if (
                (isinstance(left, ast.Constant) and isinstance(left.value, (bytes, bytearray)))
                and isinstance(right, ast.Constant) and isinstance(right.value, int)
            ) or (
                (isinstance(right, ast.Constant) and isinstance(right.value, (bytes, bytearray)))
                and isinstance(left, ast.Constant) and isinstance(left.value, int)
            ):
                return True

        # 4) random.randbytes(...) (Python 3.9+ non‐crypto RNG)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "random"
            and node.func.attr == "randbytes"
        ):
            return True

        return False

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
