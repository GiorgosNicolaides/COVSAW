"""
Module for detecting sensitive data sent or stored without encryption.

This rule flags:
  1. File writes (open in write/append mode or file.write()) of variables
     whose names suggest sensitive data (e.g., password, ssn, token).
  2. Socket send/sendall calls sending sensitive variables.
  3. HTTP client calls (requests, httpx, urllib3) sending sensitive values
     in `data` or `json` parameters without obvious encryption.

Findings are tagged with:
  - CWE-311: Missing Encryption of Sensitive Data
"""

import ast
from typing import List, Set

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class MissingEncryptionRule(Rule):
    @property
    def name(self) -> str:
        return "MissingEncryption"

    @property
    def description(self) -> str:
        return "Sensitive data is written or transmitted without encryption"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-311"]

    # Names of variables likely holding sensitive data
    _sensitive_vars: Set[str] = {
        "password", "pass", "token", "secret", "ssn", "credit_card",
        "apikey", "api_key", "ssn", "dob", "pin"
    }

    # HTTP libraries and their common send methods
    _http_libs = {"requests", "httpx", "urllib3"}
    _http_methods = {"get", "post", "put", "delete", "patch", "request"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # Only consider function/method calls
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            # 1) open(..., mode='w'|'a'|'+') or file.write(...)
            if isinstance(func, ast.Name) and func.id == "open":
                mode = None
                # positional mode argument
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                    mode = node.args[1].value
                # keyword mode argument
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = kw.value.value
                if isinstance(mode, str) and any(m in mode for m in ("w", "a", "+")):
                    findings.append(self._make_finding(node, file_path))
                    continue

            # file_handle.write(...) or writelines(...)
            if isinstance(func, ast.Attribute) and func.attr in {"write", "writelines"}:
                # check each argument: if it's a Name and matches sensitive var -> flag
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id.lower() in self._sensitive_vars:
                        findings.append(self._make_finding(node, file_path))
                        break
                continue

            # 2) socket.send/sendall
            if isinstance(func, ast.Attribute) and func.attr in {"send", "sendall"}:
                # sending a variable? flag any send of a Name matching sensitive
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id.lower() in self._sensitive_vars:
                        findings.append(self._make_finding(node, file_path))
                        break
                continue

            # 3) HTTP client calls sending sensitive data
            if isinstance(func, ast.Attribute):
                # e.g. requests.post, httpx.put, urllib3.request
                if isinstance(func.value, ast.Name) and func.value.id in self._http_libs and func.attr in self._http_methods:
                    # check keywords 'data' and 'json'
                    for kw in node.keywords:
                        if kw.arg in {"data", "json", "params"}:
                            # if the value is a Name matching sensitive -> flag
                            if isinstance(kw.value, ast.Name) and kw.value.id.lower() in self._sensitive_vars:
                                findings.append(self._make_finding(node, file_path))
                                break
                            # if it's a dict literal containing sensitive keys
                            if isinstance(kw.value, ast.Dict):
                                for key in kw.value.keys:
                                    if (
                                        isinstance(key, ast.Constant)
                                        and isinstance(key.value, str)
                                        and key.value.lower() in self._sensitive_vars
                                    ):
                                        findings.append(self._make_finding(node, file_path))
                                        break
                                break
                    continue

        return findings

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        """
        Create a Finding at the node's location.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
