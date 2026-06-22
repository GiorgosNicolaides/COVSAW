# cryptoanalyzer/rules/credentials/cwe_798_hardcoded_credentials.py

"""
Rule to detect Use of Hard-Coded Credentials (CWE-798).

This rule flags any hard-coded credentials in source code, including:
  1. Assigning a string literal directly to a variable whose name implies credentials
     (e.g., “username”, “user”, “password”, “pass”, “token”, “secret”, “api_key”).
  2. Function parameter defaults where a credential-like name is assigned a string literal.
  3. Dictionary literals containing credential-like keys mapped to string literals.
  4. Passing string literals or credential-like variables directly into authentication
     APIs (e.g., requests.auth or SMTP login methods).

By catching these patterns, we ensure no credentials (usernames, passwords, tokens)
are embedded as literals in code.
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    is_string_literal,
    get_constant_value,
    extract_string_from_dict_key,
    get_full_attr_name,
    is_call_to,
)


class Cwe798HardcodedCredentialsRule(Rule):
    @property
    def name(self) -> str:
        return "CWE798HardcodedCredentials"

    @property
    def description(self) -> str:
        return (
            "Use of hard‐coded credentials (username, password, token, API key, etc.) "
            "in source code."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-798"]

    # Variable names that imply credentials
    _credential_names = {
        "username", "user",
        "password", "pass",
        "token", "secret",
        "apikey", "api_key",
    }

    # Authentication-related call prefixes to inspect (module or class paths, lowercase)
    _auth_call_prefixes = {
        "requests.auth",       # requests library auth
        "smtplib.smtp",        # SMTP login: smtp.login(user, password)
        "ftplib.ftp",          # FTP login: ftp.login(user, passwd)
        "paramiko.client",     # SSH login: ssh.connect(username, password)
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # 1) Direct assignment: var = "literal" where var name is credential-like
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id.lower() in self._credential_names:
                        if is_string_literal(node.value):
                            findings.append(self._make_finding(node, file_path))
                        # variable assigned from another credential-like var
                        if isinstance(node.value, ast.Name) and node.value.id.lower() in self._credential_names:
                            findings.append(self._make_finding(node, file_path))

            # 2) FunctionDef defaults: def fn(password="…", token="…")
            elif isinstance(node, ast.FunctionDef):
                defaults = node.args.defaults
                args = node.args.args[-len(defaults):] if defaults else []
                for arg, default in zip(args, defaults):
                    if arg.arg.lower() in self._credential_names and is_string_literal(default):
                        findings.append(self._make_finding(default, file_path))

            # 3) Dictionary literal: {"password": "…", "token": "…"}
            elif isinstance(node, ast.Dict):
                keys = extract_string_from_dict_key(node)
                for key_str in keys:
                    if key_str.lower() in self._credential_names:
                        # find corresponding value node
                        for k_node, v_node in zip(node.keys, node.values):
                            if (
                                isinstance(k_node, ast.Constant)
                                and isinstance(k_node.value, str)
                                and k_node.value.lower() == key_str.lower()
                            ):
                                if is_string_literal(v_node):
                                    findings.append(self._make_finding(node, file_path))
                                    break
                        break

            # 4) Passing literals/vars into auth APIs, e.g. smtp.login("user", "pass")
            elif isinstance(node, ast.Call):
                # Detect smtp.login(user, password)
                func = node.func
                full = get_full_attr_name(func).lower()

                # If call is login(...) on an SMTP/FTP/SSH client
                for prefix in self._auth_call_prefixes:
                    if full.startswith(prefix) and full.endswith("login"):
                        # Check positional args
                        for arg in node.args:
                            if is_string_literal(arg):
                                findings.append(self._make_finding(node, file_path))
                                break
                            if isinstance(arg, ast.Name) and arg.id.lower() in self._credential_names:
                                findings.append(self._make_finding(node, file_path))
                                break
                        # Check keyword args user=..., password=...
                        for kw in node.keywords:
                            if kw.arg and kw.arg.lower() in self._credential_names:
                                if is_string_literal(kw.value) or (
                                    isinstance(kw.value, ast.Name)
                                    and kw.value.id.lower() in self._credential_names
                                ):
                                    findings.append(self._make_finding(node, file_path))
                                    break
                        break

                # Also detect requests.get/post(..., auth=("user", "pass"))
                if is_call_to(node, "requests", "get") or is_call_to(node, "requests", "post") or is_call_to(node, "requests", "put") or is_call_to(node, "requests", "delete"):
                    for kw in node.keywords:
                        if kw.arg == "auth" and isinstance(kw.value, ast.Tuple):
                            for elt in kw.value.elts:
                                if is_string_literal(elt):
                                    findings.append(self._make_finding(node, file_path))
                                    break
                                if isinstance(elt, ast.Name) and elt.id.lower() in self._credential_names:
                                    findings.append(self._make_finding(node, file_path))
                                    break
                        if kw.arg in {"headers", "data", "json"}:
                            # Check if payload contains credential literals
                            payload = kw.value
                            if isinstance(payload, ast.Dict):
                                for key_node, val_node in zip(payload.keys, payload.values):
                                    if (
                                        isinstance(key_node, ast.Constant)
                                        and isinstance(key_node.value, str)
                                        and key_node.value.lower() in self._credential_names
                                        and is_string_literal(val_node)
                                    ):
                                        findings.append(self._make_finding(node, file_path))
                                        break

        return findings

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        """
        Build a Finding at the node's location.
        """
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )

