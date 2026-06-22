# cryptoanalyzer/rules/credentials/cwe_522_insufficiently_protected_credentials.py

"""
Rule to detect Insufficiently Protected Credentials (CWE-522).

This rule flags any instance where credentials (usernames, passwords, tokens, API keys, etc.)
are stored or written in a way that does not sufficiently protect them at rest. Patterns include:
  1. Writing a credential‐like variable or literal directly to a file via open(...).write(...) or writelines.
  2. Dumping a dict containing “username”, “password”, “token”, or “api_key” into JSON/YAML without encryption.
  3. Assigning a credential‐like value (literal or variable) to an environment variable without protection.
  4. Saving credentials in configuration‐style assignments (e.g., config["password"] = "...") without secure measures.

By catching these patterns, we ensure that credentials are not left unprotected on disk or in memory,
covering CWE-522: Insufficiently Protected Credentials.
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
    is_bytes_literal,
)


class Cwe522InsufficientlyProtectedCredentialsRule(Rule):
    @property
    def name(self) -> str:
        return "CWE522InsufficientlyProtectedCredentials"

    @property
    def description(self) -> str:
        return (
            "Credentials are being stored or written without sufficient protection "
            "(e.g., written to a file or config in plaintext or placed in environment variables)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-522"]

    # Variable or dict‐key names indicating credentials
    _cred_names = {
        "username", "user",
        "password", "passwd", "pwd",
        "token", "api_key", "apikey", "secret",
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # ------------------------------------------------------------
            # 1) open(...).write(...) or writelines(...) with credential literal or variable
            # ------------------------------------------------------------
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"write", "writelines"}:
                    # Check each argument for credential‐like content
                    for arg in node.args:
                        # Literal string or bytes that looks like a credential (length or key‐like)
                        if is_string_literal(arg):
                            val = get_constant_value(arg)
                            if isinstance(val, str) and self._looks_like_credential(val):
                                findings.append(self._make_finding(node, file_path))
                                break
                        if is_bytes_literal(arg):
                            findings.append(self._make_finding(node, file_path))
                            break
                        # Variable name that implies a credential
                        if isinstance(arg, ast.Name) and arg.id.lower() in self._cred_names:
                            findings.append(self._make_finding(node, file_path))
                            break
                    continue

            # ------------------------------------------------------------
            # 2) JSON/YAML dump of a dict containing credential keys
            #    e.g. json.dump({"username": "admin", "password": pwd}, f)
            # ------------------------------------------------------------
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                full = get_full_attr_name(node.func).lower()
                if full.startswith("json.dump") or full.startswith("yaml.dump") or full.startswith("yaml.safedump"):
                    if node.args:
                        obj = node.args[0]
                        if isinstance(obj, ast.Dict):
                            keys = extract_string_from_dict_key(obj)
                            for key in keys:
                                if key.lower() in self._cred_names:
                                    findings.append(self._make_finding(node, file_path))
                                    break
                    continue

            # ------------------------------------------------------------
            # 3) Assignment to os.environ[...] = credential literal or variable
            #    e.g. os.environ["PASSWORD"] = "secret"
            # ------------------------------------------------------------
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Subscript):
                sub = node.targets[0]
                # Check base is os.environ
                if isinstance(sub.value, ast.Attribute):
                    full = get_full_attr_name(sub.value).lower()
                    if full == "os.environ":
                        # Extract the environment key
                        index = sub.slice
                        key_node = index.value if hasattr(index, "value") else index
                        if is_string_literal(key_node):
                            key_val = get_constant_value(key_node)
                            if isinstance(key_val, str) and key_val.lower() in self._cred_names:
                                rhs = node.value
                                if is_string_literal(rhs) or is_bytes_literal(rhs):
                                    findings.append(self._make_finding(node, file_path))
                                    continue
                                if isinstance(rhs, ast.Name) and rhs.id.lower() in self._cred_names:
                                    findings.append(self._make_finding(node, file_path))
                                    continue

            # ------------------------------------------------------------
            # 4) Configuration‐style assignments: config["password"] = "..." or similar
            # ------------------------------------------------------------
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Subscript):
                sub = node.targets[0]
                # If the key is a credential name
                index = sub.slice
                key_node = index.value if hasattr(index, "value") else index
                if is_string_literal(key_node):
                    key_val = get_constant_value(key_node)
                    if isinstance(key_val, str) and key_val.lower() in self._cred_names:
                        # Right‐hand side: literal or credential variable
                        rhs = node.value
                        if is_string_literal(rhs) or is_bytes_literal(rhs):
                            findings.append(self._make_finding(node, file_path))
                            continue
                        if isinstance(rhs, ast.Name) and rhs.id.lower() in self._cred_names:
                            findings.append(self._make_finding(node, file_path))
                            continue

        return findings

    def _looks_like_credential(self, text: str) -> bool:
        """
        Return True if the given string literal is likely a credential:
          - If it contains characters typical of tokens/keys (e.g., length ≥ 20).
          - Or if it matches a credential name exactly (e.g., "password", "secret").
        """
        t = text.strip()
        # Check if literal itself is a key name
        if t.lower() in self._cred_names:
            return True
        # Very short literals (e.g., "a") are likely not credentials
        # A typical token or key is at least 20 characters
        if len(t) >= 20:
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
