# cryptoanalyzer/rules/cleartext/cwe_319_cleartext_transmission.py

"""
Rule to detect Cleartext Transmission of Sensitive Information (CWE-319).

This rule flags any network send over unencrypted channels or HTTP/WS endpoints:
  1. socket.send(...) or socket.sendall(...) of string literals or sensitive variables.
  2. HTTP client calls (requests, httpx, urllib3) to URLs starting with "http://" or "ws://".
  3. urllib.request.urlopen(...) or urllib.request.Request(...) to "http://" or "ws://".
  4. websockets.connect(...) or websockets.create_connection(...) with "ws://" URLs.

By catching these patterns, we ensure no sensitive data is transmitted in plaintext.
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    is_string_literal,
    get_constant_value,
    get_full_attr_name,
    is_call_to,
)

class Cwe319CleartextTransmissionRule(Rule):
    @property
    def name(self) -> str:
        return "CWE319CleartextTransmission"

    @property
    def description(self) -> str:
        return (
            "Sensitive data is being transmitted without encryption "
            "(e.g., socket.send, HTTP/WS over cleartext)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-319"]

    # HTTP libraries and their common methods
    _http_libs = {"requests", "httpx", "urllib3"}
    _http_methods = {"get", "post", "put", "delete", "patch", "head", "options", "request"}

    # Websocket libraries/methods
    _ws_libs = {"websockets"}
    _ws_methods = {"connect", "create_connection"}

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # Only examine call expressions
            if not isinstance(node, ast.Call):
                continue
            func = node.func

            # ----------------------------------------
            # 1) socket.send(...) or socket.sendall(...)
            # ----------------------------------------
            if isinstance(func, ast.Attribute):
                if func.attr in {"send", "sendall"}:
                    # Check if receiver is socket module or socket instance.
                    # We can't reliably know if it's SSLSocket, so flag any socket.send or sendall.
                    # Now check argument: literal or any variable (conservative).
                    findings.append(self._make_finding(node, file_path))
                    continue

            # ----------------------------------------
            # 2) HTTP client calls: requests/httpx/urllib3
            # ----------------------------------------
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                lib_name = func.value.id
                method_name = func.attr.lower()
                if lib_name in self._http_libs and method_name in self._http_methods:
                    # Determine URL argument: first positional or keyword "url" or "uri"
                    url_node = None
                    if node.args:
                        url_node = node.args[0]
                    for kw in node.keywords:
                        if kw.arg in {"url", "uri"}:
                            url_node = kw.value
                    if is_string_literal(url_node):
                        url = get_constant_value(url_node)
                        if isinstance(url, str) and url.lower().startswith(("http://", "ws://")):
                            findings.append(self._make_finding(node, file_path))
                            continue

            # ----------------------------------------
            # 3) urllib.request.urlopen(...) or Request(...)
            # ----------------------------------------
            # match both urllib.request.urlopen and urllib.request.Request
            if isinstance(func, ast.Attribute):
                full = get_full_attr_name(func).lower()
                if full in {"urllib.request.urlopen", "urllib.request.request"}:
                    # first arg is URL node
                    if node.args:
                        url_node = node.args[0]
                    else:
                        url_node = None
                    for kw in node.keywords:
                        if kw.arg in {"url", "uri"}:
                            url_node = kw.value
                    if is_string_literal(url_node):
                        url = get_constant_value(url_node)
                        if isinstance(url, str) and url.lower().startswith(("http://", "ws://")):
                            findings.append(self._make_finding(node, file_path))
                            continue

            # ----------------------------------------
            # 4) websockets.connect(...) or create_connection(...)
            # ----------------------------------------
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                lib_name = func.value.id
                method_name = func.attr.lower()
                if lib_name in self._ws_libs and method_name in self._ws_methods:
                    # first positional argument is URL
                    if node.args:
                        url_node = node.args[0]
                    else:
                        url_node = None
                    for kw in node.keywords:
                        if kw.arg in {"uri", "url"}:
                            url_node = kw.value
                    if is_string_literal(url_node):
                        url = get_constant_value(url_node)
                        if isinstance(url, str) and url.lower().startswith("ws://"):
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
