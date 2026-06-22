# cryptoanalyzer/rules/misuse/cwe_322_key_exchange_no_entity_auth.py

"""
Rule to detect Key Exchange Without Entity Authentication (CWE-322).

This rule flags any Diffie–Hellman (DH) or Elliptic Curve Diffie–Hellman (ECDH)
key exchange operations in code that do not include any accompanying entity
authentication (e.g., signing or certificate verification) in the same scope.

Patterns detected include:
  1. Calls to DH parameter or key generation functions such as:
       • cryptography.hazmat.primitives.asymmetric.dh.generate_parameters
       • cryptography.hazmat.primitives.asymmetric.dh.generate_private_key
       • Crypto.PublicKey.DH.generate
  2. Calls to ECDH key generation such as:
       • cryptography.hazmat.primitives.asymmetric.ec.generate_private_key
       • Crypto.PublicKey.ECC.generate
  3. In the same function or module scope, absence of any calls to signature or certificate
     routines (e.g., “sign”, “verify”, certificate loading or validation functions).
By catching these patterns, we ensure that any key exchange is paired with proper
entity authentication, covering CWE-322 via static analysis.
"""

import ast
from typing import Dict, List, Set

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import get_full_attr_name


class Cwe322KeyExchangeWithoutAuthRule(Rule):
    @property
    def name(self) -> str:
        return "CWE322KeyExchangeNoEntityAuth"

    @property
    def description(self) -> str:
        return (
            "Diffie–Hellman or ECDH key exchange is performed without accompanying "
            "entity authentication (no signing or certificate validation)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-322"]

    # Functions that initiate DH key exchange
    _dh_functions = {
        "cryptography.hazmat.primitives.asymmetric.dh.generate_parameters",
        "cryptography.hazmat.primitives.asymmetric.dh.generate_private_key",
        "crypto.publickey.dh.generate",
    }

    # Functions that initiate ECDH key exchange
    _ecdh_functions = {
        "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key",
        "crypto.publickey.ecc.generate",
    }

    # Attribute names or full names indicating authentication routines
    _auth_functions = {
        # Signature methods
        "sign", "verify", 
        # Certificate-related utilities
        "load_pem_private_key", "load_pem_public_key",
        "load_certificate", "x509", "certificate",
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """
        Traverse the AST, grouping nodes by their enclosing scope (FunctionDef or module-level).
        For each scope, if any DH/ECDH call exists without any authentication call, flag each DH/ECDH call.
        """
        findings: List[Finding] = []
        scope_data: Dict[ast.AST, Dict[str, Set[ast.Call]]] = {}

        # Helper to attach parent pointers if not already done
        def _attach_parents(node: ast.AST, parent: ast.AST = None):
            for child in ast.iter_child_nodes(node):
                setattr(child, "parent", node)
                _attach_parents(child, child)

        _attach_parents(tree)

        # Helper to get the nearest enclosing FunctionDef or module (None for module-level)
        def _get_scope(node: ast.AST):
            current = node
            while hasattr(current, "parent"):
                current = current.parent
                if isinstance(current, ast.FunctionDef):
                    return current
            return None  # module-level scope

        # Initialize scope_data entries
        for node in ast.walk(tree):
            scope = _get_scope(node)
            if scope not in scope_data:
                scope_data[scope] = {
                    "key_exchange_calls": set(),
                    "auth_calls": set(),
                }

        # First pass: record DH/ECDH and auth calls per scope
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            scope = _get_scope(node)

            # Record DH key exchange calls
            func = node.func
            full = get_full_attr_name(func).lower()
            if full in self._dh_functions or full in self._ecdh_functions:
                scope_data[scope]["key_exchange_calls"].add(node)
                continue

            # Record authentication calls by attribute name or full name
            # E.g., obj.sign(...), obj.verify(...), x509.load_certificate(...)
            if isinstance(func, ast.Attribute):
                attr = func.attr.lower()
                if attr in self._auth_functions:
                    scope_data[scope]["auth_calls"].add(node)
                    continue
                # Also catch x509 methods: full names containing ".x509."
                if "x509" in full or "certificate" in full:
                    scope_data[scope]["auth_calls"].add(node)
                    continue

            # Record calls to top-level auth functions if needed
            if isinstance(func, ast.Name):
                name = func.id.lower()
                if name in {"sign", "verify", "load_certificate", "load_pem_private_key", "load_pem_public_key"}:
                    scope_data[scope]["auth_calls"].add(node)
                    continue

        # Second pass: for each scope, if key_exchange exists with no auth, flag
        for scope, data in scope_data.items():
            if data["key_exchange_calls"] and not data["auth_calls"]:
                for ke_call in data["key_exchange_calls"]:
                    findings.append(self._make_finding(ke_call, file_path))

        return findings

    def _make_finding(self, node: ast.Call, file_path: str) -> Finding:
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
