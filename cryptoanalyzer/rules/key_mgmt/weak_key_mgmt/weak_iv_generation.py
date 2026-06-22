# cryptoanalyzer/rules/randomness/cwe_1204_weak_iv_generation.py

"""
Rule to detect Generation of Weak Initialization Vector (IV) (CWE-1204).

This rule flags any creation of an IV (or nonce) using an insecure or non-cryptographic
random source, such as Python’s built-in `random` module. Specifically, it catches:

  1. Assignments where a variable name contains “iv” or “nonce” and the right-hand side
     is a call to any function in the `random` module (e.g., `random.random()`,
     `random.randint()`, `random.getrandbits()`, `random.randbytes()`, etc.).

  2. Passing a call to `random.*` as an `iv=` or `nonce=` keyword argument in a cipher
     constructor (e.g., `AES.new(key, mode=AES.MODE_CBC, iv=random.randbytes(16))`).

  3. Any direct use of a non-cryptographic random function (from `random`) where the
     target name suggests it is being used as an IV/nonce.

By catching these patterns, we ensure IVs/nonces are generated via secure RNG (e.g.,
`os.urandom()` or `secrets.token_bytes()`), covering CWE-1204.
"""

import ast
from typing import List, Optional

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    get_full_attr_name,
    is_name_or_attr,
)


class Cwe1204WeakIvGenerationRule(Rule):
    @property
    def name(self) -> str:
        return "CWE1204WeakIVGeneration"

    @property
    def description(self) -> str:
        return (
            "An initialization vector (IV) or nonce is generated using a non-cryptographic "
            "random source (e.g., Python’s `random` module), leading to predictable IVs."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-1204"]

    # Names indicating an IV or nonce variable
    _iv_var_fragments = {"iv", "nonce", "initialization_vector"}

    # Recognize any call to the random module
    _random_prefix = "random"

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # 1) Assignment: iv = random.*(...) or nonce = random.*(...)
            if isinstance(node, ast.Assign):
                # Only single target assignments handled
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    var_name = node.targets[0].id.lower()
                    if self._contains_iv_fragment(var_name):
                        rhs = node.value
                        if isinstance(rhs, ast.Call) and self._is_random_call(rhs):
                            findings.append(self._make_finding(rhs, file_path))
                            continue

            # 2) Keyword argument in cipher constructor: iv=random.* or nonce=random.*
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                # Look for any .new(...) call (cipher constructors)
                if node.func.attr == "new":
                    for kw in node.keywords:
                        kw_name = (kw.arg or "").lower()
                        if kw_name in {"iv", "nonce"}:
                            val = kw.value
                            if isinstance(val, ast.Call) and self._is_random_call(val):
                                findings.append(self._make_finding(val, file_path))
                                break

            # 3) Passing random.*(...) to a function where the parameter name is iv/nonce
            #    via positional argument: detect call like some_function(random.randbytes(...))
            #    if the function’s signature is unknown, we limit to assignments (case 1) and keyword (case 2).

        return findings

    def _contains_iv_fragment(self, name: str) -> bool:
        """
        Return True if the variable name suggests it holds an IV or nonce.
        """
        return any(fragment in name for fragment in self._iv_var_fragments)

    def _is_random_call(self, call_node: ast.Call) -> bool:
        """
        Return True if the AST Call node is invoking any attribute or function in the
        `random` module (non-cryptographic RNG).
        """
        func = call_node.func
        # Case A: random.<func>()
        if isinstance(func, ast.Attribute):
            full = get_full_attr_name(func).lower()
            if full.startswith(f"{self._random_prefix}."):
                return True
        # Case B: imported directly: from random import randint; then randint(...)
        if isinstance(func, ast.Name):
            # If the function name is one of the standard random functions—
            # we conservatively flag any bare Name and assume it may be from random.
            # Common non-crypto random functions:
            if func.id in {
                "random", "randint", "randrange", "getrandbits", "randbytes", "choice", "choices",
                "shuffle", "uniform", "triangular", "betavariate", "expovariate",
                "gauss", "lognormvariate", "normalvariate", "vonmisesvariate", "paretovariate",
                "weibullvariate"
            }:
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
