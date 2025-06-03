# cryptoanalyzer/rules/cleartext/cwe_523_unprotected_transport.py

"""
Rule to detect Unprotected Transport of Credentials (CWE-523).

This rule flags any transmission of credentials (username/password, tokens, API keys)
over an unencrypted channel (e.g., HTTP or WS). Patterns detected include:

  1. HTTP client calls (requests, httpx, urllib3) to URLs starting with "http://"
     or "ws://" that include:
       a) an `auth=(username, password)` keyword argument, or
       b) credentials in `data`, `json`, or `params` payload (keys "username", "password", "token", "api_key"), or
       c) credentials embedded in the URL (e.g., "http://user:pass@host/...").

  2. urllib.request.Request or urlopen calls to "http://user:pass@..." style URLs.

  3. Any socket.send/sendall of a string literal that contains credential-like substrings
     ("Authorization:", "Basic ", "Bearer ", "username=", "password=") detected on unencrypted connections.

By catching these patterns, we ensure no credentials are transported in cleartext.
"""

import ast
from typing import List, Optional

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    is_string_literal,
    get_constant_value,
    get_full_attr_name,
)


class Cwe523UnprotectedTransportRule(Rule):
    @property
    def name(self) -> str:
        return "CWE523UnprotectedTransport"

    @property
    def description(self) -> str:
        return (
            "Credentials are being sent over an unencrypted channel "
            "(e.g., HTTP or WS without TLS), exposing them to eavesdropping."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-523"]

    # HTTP libraries and their methods
    _http_libs = {"requests", "httpx", "urllib3"}
    _http_methods = {"get", "post", "put", "delete", "patch", "head", "options", "request"}

    # urllib functions
    _urllib_funcs = {"urllib.request.urlopen", "urllib.request.Request"}

    # Socket send methods
    _socket_methods = {"send", "sendall"}

    # Credential-like payload keys
    _cred_keys = {"username", "user", "password", "passwd", "pwd", "token", "api_key", "apikey"}

    # Credential substrings in headers or data
    _cred_substrings = ("Authorization:", "Basic ", "Bearer ", "username=", "password=", "token=", "api_key=")

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # Only inspect Call nodes
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            # ----------------------------------------
            # 1) HTTP client calls over cleartext
            # ----------------------------------------
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                lib = func.value.id
                method = func.attr.lower()
                if lib in self._http_libs and method in self._http_methods:
                    url_node = self._extract_url_node(node)
                    if url_node is None:
                        continue

                    if is_string_literal(url_node):
                        url = get_constant_value(url_node)
                        if isinstance(url, str) and url.lower().startswith(("http://", "ws://")):
                            # a) auth=keyword
                            for kw in node.keywords:
                                if kw.arg == "auth":
                                    findings.append(self._make_finding(node, file_path))
                                    break
                            else:
                                # b) credentials in data/json/params
                                for kw in node.keywords:
                                    if kw.arg in {"data", "json", "params"}:
                                        if self._contains_cred_in_payload(kw.value):
                                            findings.append(self._make_finding(node, file_path))
                                            break
                                else:
                                    # c) credentials embedded in URL (http://user:pass@...)
                                    if "@" in url and url.split("://", 1)[1].count("@") == 1:
                                        # user:pass@host pattern
                                        findings.append(self._make_finding(node, file_path))
                            continue

            # ----------------------------------------
            # 2) urllib.request calls over cleartext with embedded credentials
            # ----------------------------------------
            if isinstance(func, ast.Attribute) or isinstance(func, ast.Name):
                full = get_full_attr_name(func).lower()
                if full in self._urllib_funcs:
                    # First argument is URL or Request object
                    url_node = node.args[0] if node.args else None
                    if is_string_literal(url_node):
                        url = get_constant_value(url_node)
                        if isinstance(url, str) and url.lower().startswith("http://"):
                            # Check for embedded credentials: user:pass@
                            if "@" in url and url.split("://", 1)[1].count("@") == 1:
                                findings.append(self._make_finding(node, file_path))
                                continue

            # ----------------------------------------
            # 3) Socket send/sendall of credential-like strings
            # ----------------------------------------
            if isinstance(func, ast.Attribute) and func.attr in self._socket_methods:
                # We conservatively treat any send/sendall on string literals containing credential substrings
                for arg in node.args:
                    if is_string_literal(arg):
                        text = get_constant_value(arg)
                        if isinstance(text, str):
                            txt_lower = text.lower()
                            for substr in self._cred_substrings:
                                if substr.lower() in txt_lower:
                                    findings.append(self._make_finding(node, file_path))
                                    break
                            else:
                                continue
                            break
                continue

        return findings

    def _extract_url_node(self, node: ast.Call) -> Optional[ast.AST]:
        """
        Return the AST node corresponding to the URL argument:
          - First positional argument, if present.
          - Otherwise, keyword "url" or "uri", if provided.
          - Else, None.
        """
        if node.args:
            return node.args[0]
        for kw in node.keywords:
            if kw.arg in {"url", "uri"}:
                return kw.value
        return None

    def _contains_cred_in_payload(self, payload_node: ast.AST) -> bool:
        """
        Inspect a payload (could be Dict, Name, or Constant) for credential keys:

        - If Dict literal, check keys against _cred_keys.
        - If Name (variable), conservatively assume it may contain credentials.
        - If string literal containing "username=" or "password=", flag it.
        """
        # Dict literal
        if isinstance(payload_node, ast.Dict):
            for key in payload_node.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if key.value.lower() in self._cred_keys:
                        return True
        # Variable name: pass through (could be anything)
        if isinstance(payload_node, ast.Name):
            return True
        # String literal
        if is_string_literal(payload_node):
            val = get_constant_value(payload_node)
            if isinstance(val, str):
                v_lower = val.lower()
                for cred_key in self._cred_keys:
                    if f"{cred_key}=" in v_lower:
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
