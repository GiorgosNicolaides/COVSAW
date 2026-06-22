# cryptoanalyzer/rules/credentials/cwe_1392_default_credentials.py

"""
Rule to detect Use of Default Credentials (CWE-1392).

This rule flags any assignment or use of username/password combinations that match
known default credentials, including but not limited to:
  1. Assigning a username or password variable to a literal from a default list
     (e.g., "admin", "root", "password", "1234").
  2. Tuple or list literals like ("admin", "admin") assigned to a credentials variable.
  3. Dictionary literals containing keys "username" and "password" whose values match defaults.
  4. Passing default credentials directly into authentication APIs (e.g., smtp.login("admin", "admin")).

By catching these patterns, we ensure no known default credentials remain in code.
"""

import ast
from typing import List, Tuple

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    is_string_literal,
    get_constant_value,
    extract_string_from_dict_key,
    get_full_attr_name,
    is_call_to,
)


class Cwe1392DefaultCredentialsRule(Rule):
    @property
    def name(self) -> str:
        return "CWE1392DefaultCredentials"

    @property
    def description(self) -> str:
        return (
            "Default credentials are being used (e.g., username/password pairs like "
            "\"admin\"/\"admin\", \"root\"/\"toor\")."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-1392"]

    # Known default usernames and passwords
    _default_usernames = {
        "admin", "root", "user", "guest"
    }
    _default_passwords = {
        "admin", "root", "password", "1234", "12345", "123456", "toor", "guest", ""
    }
    # Common default username/password tuples
    _default_pairs: List[Tuple[str, str]] = [
        ("admin", "admin"),
        ("root", "toor"),
        ("admin", "password"),
        ("guest", "guest"),
        ("user", "password"),
    ]

    # Variable names likely holding credentials
    _user_var_names = {"username", "user", "login", "userid", "user_id"}
    _pass_var_names = {"password", "passwd", "pwd"}

    # Authentication-related call prefixes (similar to CWE-798)
    _auth_call_prefixes = {
        "requests.auth",       # requests library auth
        "smtplib.smtp",        # SMTP login: smtp.login(user, password)
        "ftplib.ftp",          # FTP login: ftp.login(user, passwd)
        "paramiko.client",     # SSH login: ssh.connect(username, password)
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # ------------------------------------------------------------
            # 1) Assignment to username/password variables with default literals
            #    e.g., username = "admin"
            #          password = "admin"
            # ------------------------------------------------------------
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        var_name = tgt.id.lower()
                        val_node = node.value
                        if is_string_literal(val_node):
                            val = get_constant_value(val_node)
                            if not isinstance(val, str):
                                continue
                            val_lower = val.lower()

                            # username variable assigned default username
                            if var_name in self._user_var_names and val_lower in self._default_usernames:
                                findings.append(self._make_finding(node, file_path))
                                break

                            # password variable assigned default password
                            if var_name in self._pass_var_names and val_lower in self._default_passwords:
                                findings.append(self._make_finding(node, file_path))
                                break

                        # Tuple or list literal assigned to a credentials variable
                        if isinstance(val_node, (ast.Tuple, ast.List)) and len(val_node.elts) >= 2:
                            # Extract first two string elements if present
                            elt0, elt1 = val_node.elts[0], val_node.elts[1]
                            if is_string_literal(elt0) and is_string_literal(elt1):
                                user_val = get_constant_value(elt0)
                                pass_val = get_constant_value(elt1)
                                if (
                                    isinstance(user_val, str)
                                    and isinstance(pass_val, str)
                                    and (user_val.lower(), pass_val.lower()) in self._default_pairs
                                ):
                                    findings.append(self._make_finding(node, file_path))
                                    break

            # ------------------------------------------------------------
            # 2) Dictionary literal with "username" and "password" keys using defaults
            #    e.g., {"username": "admin", "password": "admin"}
            # ------------------------------------------------------------
            elif isinstance(node, ast.Dict):
                keys = extract_string_from_dict_key(node)
                # Check if both username and password keys exist
                key_lower_set = {k.lower() for k in keys}
                if "username" in key_lower_set and "password" in key_lower_set:
                    # Find corresponding values
                    username_val = None
                    password_val = None
                    for k_node, v_node in zip(node.keys, node.values):
                        if isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                            key_str = k_node.value.lower()
                            if key_str == "username" and is_string_literal(v_node):
                                username_val = get_constant_value(v_node)
                            elif key_str == "password" and is_string_literal(v_node):
                                password_val = get_constant_value(v_node)
                    if (
                        isinstance(username_val, str)
                        and isinstance(password_val, str)
                        and (username_val.lower(), password_val.lower()) in self._default_pairs
                    ):
                        findings.append(self._make_finding(node, file_path))

            # ------------------------------------------------------------
            # 3) Passing default credentials into authentication APIs
            #    e.g., smtp.login("admin", "admin")
            # ------------------------------------------------------------
            elif isinstance(node, ast.Call):
                func = node.func
                full = get_full_attr_name(func).lower()

                for prefix in self._auth_call_prefixes:
                    if full.startswith(prefix) and full.endswith("login"):
                        # Check positional args for default literals
                        if len(node.args) >= 2:
                            arg0, arg1 = node.args[0], node.args[1]
                            if is_string_literal(arg0) and is_string_literal(arg1):
                                user_val = get_constant_value(arg0)
                                pass_val = get_constant_value(arg1)
                                if (
                                    isinstance(user_val, str)
                                    and isinstance(pass_val, str)
                                    and (user_val.lower(), pass_val.lower()) in self._default_pairs
                                ):
                                    findings.append(self._make_finding(node, file_path))
                                    break
                        # Check keyword args user/password
                        user_val = None
                        pass_val = None
                        for kw in node.keywords:
                            if kw.arg and kw.arg.lower() in self._user_var_names and is_string_literal(kw.value):
                                user_val = get_constant_value(kw.value)
                            if kw.arg and kw.arg.lower() in self._pass_var_names and is_string_literal(kw.value):
                                pass_val = get_constant_value(kw.value)
                        if (
                            isinstance(user_val, str)
                            and isinstance(pass_val, str)
                            and (user_val.lower(), pass_val.lower()) in self._default_pairs
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
