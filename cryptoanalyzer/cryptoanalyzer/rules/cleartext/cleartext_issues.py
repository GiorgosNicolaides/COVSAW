"""
Module for detecting cleartext transmission and storage of sensitive data.

1) CleartextTransmissionRule
   - CWE-319: Cleartext Transmission of Sensitive Information
   - Flags:
     • socket.send/sendall
     • requests/httpx/urllib3 calls over “http://” or “ws://”
     • HTTP calls with verify=False or missing verify
2) CleartextStorageRule
   - CWE-312-318: Cleartext Storage in various forms
   - Flags:
     • open(..., mode='w|a|+') or handle.write(…) of sensitive vars or long literals
     • json.dump(sensitive_dict, …) or yaml.dump(...)
     • logger.info/debug/etc. called with sensitive variables
"""

import ast
from typing import List, Set

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class CleartextTransmissionRule(Rule):
    @property
    def name(self) -> str:
        return "CleartextTransmission"

    @property
    def description(self) -> str:
        return "Sending sensitive data in cleartext over network"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-319"]

    _clear_schemes = ("http://", "ws://")
    _http_methods = {
        "get", "post", "put", "delete", "patch", "head", "options", "request"
    }
    _http_libs = {"requests", "httpx", "urllib3"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            # --- A) raw socket sends ---
            if isinstance(func, ast.Attribute) and func.attr in {"send", "sendall"}:
                findings.append(self._make_finding(node, file_path))
                continue

            # --- B) HTTP client usage ---
            if isinstance(func, ast.Attribute):
                # detect e.g. requests.get(...)
                if isinstance(func.value, ast.Name) and func.value.id in self._http_libs:
                    if func.attr in self._http_methods:
                        # 1) cleartext URL literal?
                        url_node = None
                        if node.args:
                            url_node = node.args[0]
                        for kw in node.keywords:
                            if kw.arg in ("url", "uri"):
                                url_node = kw.value
                        if (
                            isinstance(url_node, ast.Constant)
                            and isinstance(url_node.value, str)
                            and any(
                                url_node.value.lower().startswith(scheme)
                                for scheme in self._clear_schemes
                            )
                        ):
                            findings.append(self._make_finding(node, file_path))
                            continue

                        # 2) verify=False or missing verify
                        has_verify_kw = False
                        for kw in node.keywords:
                            if kw.arg == "verify":
                                has_verify_kw = True
                                if (
                                    isinstance(kw.value, ast.Constant)
                                    and kw.value.value is False
                                ):
                                    findings.append(self._make_finding(node, file_path))
                                break

                        if not has_verify_kw:
                            # no verify provided → could be defaulting to True or False, flag to be safe
                            findings.append(self._make_finding(node, file_path))
                        continue

        return findings

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )


class CleartextStorageRule(Rule):
    @property
    def name(self) -> str:
        return "CleartextStorage"

    @property
    def description(self) -> str:
        return "Storing sensitive data in cleartext on disk or memory"

    @property
    def cwe_ids(self) -> List[str]:
        return [
            "CWE-312",  # Cleartext Storage in Files
            "CWE-313",  # Cleartext Storage in Database
            "CWE-314",  # Cleartext Storage in the Registry
            "CWE-315",  # Cleartext Storage in Memory
            "CWE-316",  # Cleartext Storage in Cookies
            "CWE-317",  # Cleartext Storage in HTTP Cookies
            "CWE-318",  # Cleartext Storage in Executables and Libraries
        ]

    _sensitive_vars: Set[str] = {
        "password", "pass", "secret", "token", "ssn",
        "credit_card", "apikey", "api_key"
    }
    _logging_methods = {"debug", "info", "warning", "error", "critical", "exception"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            # --- A) open(..., mode='w'|'a'|'+') ---
            if isinstance(func, ast.Name) and func.id == "open":
                mode = None
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                    mode = node.args[1].value
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = kw.value.value
                if isinstance(mode, str) and any(m in mode for m in ("w", "a", "+")):
                    findings.append(self._make_finding(node, file_path))
                    continue

            # --- B) file_handle.write(...) ---
            if isinstance(func, ast.Attribute) and func.attr in {"write", "writelines"}:
                # writing a sensitive variable?
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id.lower() in self._sensitive_vars:
                        findings.append(self._make_finding(node, file_path))
                        break
                else:
                    # or writing a long literal (likely secret)
                    for arg in node.args:
                        if (
                            isinstance(arg, ast.Constant)
                            and isinstance(arg.value, str)
                            and len(arg.value) > 20
                        ):
                            findings.append(self._make_finding(node, file_path))
                            break
                continue

            # --- C) json.dump/dumps and yaml.dump --- 
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id in ("json", "yaml") and func.attr in ("dump", "dumps", "safe_dump"):
                    if node.args:
                        obj = node.args[0]
                        if isinstance(obj, ast.Dict):
                            # if any dict key is a sensitive literal
                            for key in obj.keys:
                                if (
                                    isinstance(key, ast.Constant)
                                    and isinstance(key.value, str)
                                    and key.value.lower() in self._sensitive_vars
                                ):
                                    findings.append(self._make_finding(node, file_path))
                                    break
                    continue

            # --- D) logger.<level>(sensitive_var) ---
            if isinstance(func, ast.Attribute) and func.attr in self._logging_methods:
                if isinstance(func.value, ast.Name) and func.value.id in ("logger", "logging"):
                    for arg in node.args:
                        if (
                            isinstance(arg, ast.Name)
                            and arg.id.lower() in self._sensitive_vars
                        ) or (
                            isinstance(arg, ast.Attribute)
                            and arg.attr.lower() in self._sensitive_vars
                        ):
                            findings.append(self._make_finding(node, file_path))
                            break

        return findings

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
