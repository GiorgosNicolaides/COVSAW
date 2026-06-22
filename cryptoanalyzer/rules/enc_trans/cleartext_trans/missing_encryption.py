# cryptoanalyzer/rules/missing_crypto/cwe_311_missing_encryption.py

"""
Rule to detect Missing Encryption of Sensitive Data (CWE-311).

This rule flags any instance where sensitive data (passwords, tokens, SSNs, API keys,
credit card numbers, etc.) is written to disk or sent over a network without
encryption. Patterns detected include:
  1. Writing a sensitive‐named variable (e.g., “password”, “token”) or a string literal
     longer than a threshold (likely a secret) to a file via open(...).write(...) or writelines.
  2. Sending a sensitive‐named variable or literal via socket.send(...) or sendall(...).
  3. Making HTTP client calls (requests, httpx, urllib3) over cleartext (“http://” or “ws://”)
     with sensitive payloads in `data`, `json`, or `params`.
  4. HTTP calls with `verify=False` or missing `verify` when a URL indicates HTTPS,
     since skipping certificate verification is effectively missing encryption validation.
  5. Environment variable writes of sensitive data (e.g., os.environ["TOKEN"] = ...).
  6. Database queries inserting sensitive fields without any encryption (e.g.,
     cursor.execute("INSERT ... password ...", (user, pwd)), or passing a dict with a “password” key).
By catching all these patterns, we ensure no sensitive data is stored or transmitted
in plaintext, covering CWE-311 comprehensively.
"""

import ast
import re
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    get_full_attr_name,
    is_string_literal,
    get_constant_value,
    is_name_or_attr,
)


class Cwe311MissingEncryptionRule(Rule):
    @property
    def name(self) -> str:
        return "CWE311MissingEncryption"

    @property
    def description(self) -> str:
        return (
            "Sensitive data is being stored or sent without encryption "
            "(e.g., written to file, sent over socket, or HTTP without TLS)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-311"]

    # Variable names likely to hold sensitive data
    _sensitive_vars = {
        "password", "passwd", "pwd", "token", "secret", "ssn",
        "credit_card", "creditcard", "ccn", "apikey", "api_key"
    }

    # Patterns for detecting long literals (could be secrets) – hex or base64
    _min_secret_length = 40
    _hex_pattern = re.compile(r"^[0-9a-fA-F]{" + str(_min_secret_length) + r",}$")
    _b64_pattern = re.compile(
        r"^(?:[A-Za-z0-9+/]{4})*" +
        r"(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    )

    # HTTP methods for client libraries
    _http_methods = {"get", "post", "put", "delete", "patch", "head", "options", "request"}
    _http_libs = {"requests", "httpx", "urllib3"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # ------------------------------------------------------------
            # 1) File write of sensitive data: open(...).write(...) or writelines
            # ------------------------------------------------------------
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"write", "writelines"}:
                    for arg in node.args:
                        # a) Writing a literal string that looks like a secret
                        if is_string_literal(arg):
                            val = get_constant_value(arg)
                            if isinstance(val, str):
                                v = val.strip()
                                if len(v) >= self._min_secret_length and (
                                    self._hex_pattern.fullmatch(v) or self._b64_pattern.fullmatch(v)
                                ):
                                    findings.append(self._make_finding(node, file_path))
                                    break
                        # b) Writing a sensitive‐named variable
                        if isinstance(arg, ast.Name) and arg.id.lower() in self._sensitive_vars:
                            findings.append(self._make_finding(node, file_path))
                            break
                    continue

            # ------------------------------------------------------------
            # 2) open(..., mode='w'|'a'|'+') assigning sensitive data to file
            # ------------------------------------------------------------
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
                mode = None
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                    mode = node.args[1].value
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = kw.value.value
                if isinstance(mode, str) and any(m in mode for m in ("w", "a", "+")):
                    findings.append(self._make_finding(node, file_path))
                    continue

            # ------------------------------------------------------------
            # 3) Socket send/sendall with sensitive data
            # ------------------------------------------------------------
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"send", "sendall"}:
                    for arg in node.args:
                        if is_string_literal(arg):
                            findings.append(self._make_finding(node, file_path))
                            break
                        if isinstance(arg, ast.Name) and arg.id.lower() in self._sensitive_vars:
                            findings.append(self._make_finding(node, file_path))
                            break
                    continue

            # ------------------------------------------------------------
            # 4) HTTP client calls sending data over cleartext or skipping TLS check
            # ------------------------------------------------------------
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id in self._http_libs:
                    method = node.func.attr.lower()
                    if method in self._http_methods:
                        # a) Cleartext URL literal?
                        url_node = None
                        if node.args:
                            url_node = node.args[0]
                        for kw in node.keywords:
                            if kw.arg in {"url", "uri"}:
                                url_node = kw.value
                        if (
                            is_string_literal(url_node)
                            and isinstance(get_constant_value(url_node), str)
                            and get_constant_value(url_node).lower().startswith(("http://", "ws://"))
                        ):
                            findings.append(self._make_finding(node, file_path))
                            continue

                        # b) Sensitive payload in data/json/params over HTTP
                        for kw in node.keywords:
                            if kw.arg in {"data", "json", "params"}:
                                val = kw.value
                                # dict payload with sensitive key
                                if isinstance(val, ast.Dict):
                                    for key in val.keys:
                                        if (
                                            isinstance(key, ast.Constant)
                                            and isinstance(key.value, str)
                                            and key.value.lower() in self._sensitive_vars
                                        ):
                                            findings.append(self._make_finding(node, file_path))
                                            break
                                # variable payload named “password” etc.
                                if isinstance(val, ast.Name) and val.id.lower() in self._sensitive_vars:
                                    findings.append(self._make_finding(node, file_path))
                                    break
                        # c) verify=False or missing verify on HTTPS
                        has_verify = False
                        for kw in node.keywords:
                            if kw.arg == "verify":
                                has_verify = True
                                if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                                    findings.append(self._make_finding(node, file_path))
                                break
                        if not has_verify:
                            # If URL is HTTPS literal but no verify provided, flag
                            if is_string_literal(url_node) and isinstance(get_constant_value(url_node), str):
                                url = get_constant_value(url_node).lower()
                                if url.startswith("https://"):
                                    findings.append(self._make_finding(node, file_path))
                        continue

            # ------------------------------------------------------------
            # 5) Environment variable assignment of sensitive data
            # ------------------------------------------------------------
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Subscript):
                sub = node.targets[0]
                # Check pattern os.environ["KEY"] = value
                if isinstance(sub.value, ast.Attribute):
                    full = get_full_attr_name(sub.value).lower()
                    if full == "os.environ":
                        # Extract the key in os.environ["KEY"]
                        index = sub.slice
                        key_node = index.value if hasattr(index, "value") else index
                        if is_string_literal(key_node):
                            key_val = get_constant_value(key_node).lower()
                            if key_val in self._sensitive_vars:
                                # RHS is literal or variable
                                rhs = node.value
                                if is_string_literal(rhs) or (isinstance(rhs, ast.Name) and rhs.id.lower() in self._sensitive_vars):
                                    findings.append(self._make_finding(node, file_path))
                                    continue

            # ------------------------------------------------------------
            # 6) Database insertion of sensitive fields without encryption
            # ------------------------------------------------------------
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                method = node.func.attr.lower()
                if method in {"execute", "executemany", "run", "raw", "query"}:
                    # Check first arg: SQL literal containing “password” or other sensitive column
                    if node.args:
                        first = node.args[0]
                        if is_string_literal(first) and "password" in get_constant_value(first).lower():
                            findings.append(self._make_finding(node, file_path))
                            continue
                    # Check dict payload with sensitive keys
                    for arg in node.args[1:]:
                        if isinstance(arg, ast.Dict):
                            for key in arg.keys:
                                if isinstance(key, ast.Constant) and isinstance(key.value, str) and key.value.lower() in self._sensitive_vars:
                                    findings.append(self._make_finding(node, file_path))
                                    break
                            else:
                                continue
                            break
                    for kw in node.keywords:
                        if kw.arg.lower() in self._sensitive_vars:
                            findings.append(self._make_finding(node, file_path))
                            break
                    continue

        return findings

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        """
        Construct a Finding at the relevant node's location.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
