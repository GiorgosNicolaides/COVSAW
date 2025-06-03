# cryptoanalyzer/rules/certificate/cwe_370_missing_revocation_after_initial_check.py

"""
Rule to detect Missing Check for Certificate Revocation After Initial Check (CWE-370).

This rule flags any SSL/TLS context or connection setup where:
  1. An SSLContext is created (e.g., via ssl.create_default_context() or ssl.SSLContext())
     and certificate verification is enabled (verify_mode != CERT_NONE), but
  2. No subsequent certificate revocation check is configured (no CRL or OCSP),
     such as setting `ctx.verify_flags` to include revocation or calling `ctx.load_verify_locations()`.

Patterns detected include:
  - ctx = ssl.create_default_context(); (no ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF)
  - ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); (no revocation setup afterward)
  - Any use of `ssl.wrap_socket(..., cert_reqs=ssl.CERT_REQUIRED)` without any
    `verify_flags` or OCSP/CRL configuration after.

By catching these patterns, we ensure that after an initial certificate chain
validation, the code does not skip checking for revocation, covering CWE-370.
"""

import ast
from typing import List, Tuple

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import get_full_attr_name


class Cwe370MissingRevocationAfterInitialCheckRule(Rule):
    @property
    def name(self) -> str:
        return "CWE370MissingRevocationAfterInitialCheck"

    @property
    def description(self) -> str:
        return (
            "SSL/TLS context is created with certificate verification enabled, "
            "but no certificate revocation check (CRL/OCSP) is configured afterward."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-370"]

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """
        Find SSLContext creations where verify_mode is not CERT_NONE (i.e., verification is on)
        and no revocation check (verify_flags or load_verify_locations) follows in the same scope.
        """

        findings: List[Finding] = []
        # Track contexts created: var_name -> (node, verify_mode_checked)
        contexts: List[Tuple[str, ast.AST, bool]] = []  # (var_name, creation_node, verified_flag)

        # 1) Collect SSLContext creations with cert_reqs or default that implies verification
        for node in ast.walk(tree):
            # Assignments: ctx = ssl.create_default_context(...) or ssl.SSLContext(...)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                func = node.value.func
                full_name = get_full_attr_name(func).lower()
                # ssl.create_default_context() defaults to verify_mode=CERT_REQUIRED
                if full_name in {"ssl.createdefaultcontext", "ssl.create_default_context"}:
                    target = node.targets[0]
                    if isinstance(target, ast.Name):
                        contexts.append((target.id, node, True))
                # ssl.SSLContext(protocol) – need to check default verify_mode
                elif full_name.endswith("sslcontext"):
                    # If created with PROTOCOL_TLS_CLIENT, verify_mode defaults to CERT_REQUIRED
                    # Even if protocol is unspecified, assume verify_mode may need explicit check
                    target = node.targets[0]
                    if isinstance(target, ast.Name):
                        # Mark as needing a revocation check if verify_mode explicitly set later
                        contexts.append((target.id, node, True))

            # 2) wrap_socket with cert_reqs=ssl.CERT_REQUIRED
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                full = get_full_attr_name(node.func).lower()
                if full.endswith("ssl.wrap_socket"):
                    # If cert_reqs keyword is set to CERT_REQUIRED or positional second arg
                    for kw in node.keywords:
                        if kw.arg == "cert_reqs" and getattr(kw.value, "attr", "").upper() == "CERT_REQUIRED":
                            # flag immediate finding since wrap_socket won’t check revocation
                            findings.append(self._make_finding(node, file_path))
                            break
                    else:
                        # Check positional: wrap_socket(sock, ssl.CERT_REQUIRED, ...)
                        if len(node.args) >= 2:
                            second = node.args[1]
                            if isinstance(second, ast.Attribute) and second.attr.upper() == "CERT_REQUIRED":
                                findings.append(self._make_finding(node, file_path))

        # 3) For each context var, ensure existence of revocation setup in same scope
        for var_name, create_node, _ in contexts:
            if not self._has_revocation_setup(tree, var_name):
                findings.append(self._make_finding(create_node, file_path))

        return findings

    def _has_revocation_setup(self, tree: ast.AST, var_name: str) -> bool:
        """
        Search for attribute assignments or calls on var_name indicating
        revocation configuration, such as:
          - ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
          - ctx.load_verify_locations(...)
          - ctx.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF
        """
        for node in ast.walk(tree):
            # ctx.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF or |=
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Attribute):
                attr = node.targets[0]
                if isinstance(attr.value, ast.Name) and attr.value.id == var_name:
                    if attr.attr == "verify_flags":
                        return True

            if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Attribute):
                attr = node.target
                if isinstance(attr.value, ast.Name) and attr.value.id == var_name:
                    if attr.attr == "verify_flags":
                        return True

            # ctx.load_verify_locations(...)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                if isinstance(func.value, ast.Name) and func.value.id == var_name:
                    if func.attr == "load_verify_locations":
                        return True

            # Any OCSP/CRL specific calls: context.set_ocsp_server_callback, etc.
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                if isinstance(func.value, ast.Name) and func.value.id == var_name:
                    if func.attr.lower().startswith("set_ocsp") or func.attr.lower().startswith("check_ocsp"):
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
