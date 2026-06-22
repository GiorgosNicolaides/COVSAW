# cryptoanalyzer/rules/plaintext_secrets/cwe_256_plaintext_storage.py

"""
Rule to detect any plaintext storage of passwords (CWE-256).

This rule aggressively flags patterns that result in storing a password
in plaintext, including but not limited to:
  1. Assigning a string literal directly to a “password”-like variable.
  2. Writing a password (literal or variable) to a file (open(...).write or writelines).
  3. Dumping a dict containing a “password” key in JSON/YAML without encryption.
  4. Inserting a “password” field into a database query or executing SQL containing “password” in plaintext.
  5. Setting environment variables like os.environ["PASSWORD"] = ... with a literal or variable.
  6. Logging a “password”-named variable directly.

By catching all these patterns, we ensure no code saving passwords in plaintext slips through.
"""

import ast
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    is_string_literal,
    get_constant_value,
    extract_string_from_dict_key,
    is_name_or_attr,
    get_full_attr_name,
)


class Cwe256PlaintextStorageRule(Rule):
    @property
    def name(self) -> str:
        return "CWE256PlaintextStorage"

    @property
    def description(self) -> str:
        return (
            "Password is being stored or written in plaintext form "
            "(e.g., assignment to literal, file write, JSON/YAML dump, "
            "database insertion, environment variable, or logging)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-256"]

    # Variable names that imply password storage
    _password_var_keywords = {"password", "passwd", "pwd", "pass"}

    # Database execute methods to inspect
    _db_methods = {
        "execute", "executemany", "run", "raw", "query"  # common DB call names
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # 1) Direct assignment: password = "literal"
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and self._is_password_name(tgt.id):
                        if is_string_literal(node.value):
                            findings.append(self._make_finding(node, file_path))
                        # also variable-to-variable assignment: user pulls default passwords
                        if isinstance(node.value, ast.Name) and self._is_password_name(node.value.id):
                            findings.append(self._make_finding(node, file_path))

            # 2) FunctionDef defaults: def fn(password="…")
            elif isinstance(node, ast.FunctionDef):
                defaults = node.args.defaults
                args = node.args.args[-len(defaults) :] if defaults else []
                for arg, default in zip(args, defaults):
                    if self._is_password_name(arg.arg) and is_string_literal(default):
                        findings.append(self._make_finding(default, file_path))

            # 3) Dictionary literal with “password” key
            elif isinstance(node, ast.Dict):
                keys = extract_string_from_dict_key(node)
                for key in keys:
                    if key.lower() in self._password_var_keywords:
                        findings.append(self._make_finding(node, file_path))
                        break

            # 4) File write: open(...).write(…) or write literal/var containing “password”
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                # open(...).write(...) or writelines
                if node.func.attr in {"write", "writelines"}:
                    # Check argument is a literal or password variable
                    for arg in node.args:
                        if is_string_literal(arg):
                            findings.append(self._make_finding(node, file_path))
                            break
                        if isinstance(arg, ast.Name) and self._is_password_name(arg.id):
                            findings.append(self._make_finding(node, file_path))
                            break
                    continue

                # 5) JSON/YAML dump: json.dump(…) or yaml.dump(…)
                full = get_full_attr_name(node.func)
                if full.lower().startswith("json.dump") or full.lower().startswith("yaml.dump") or full.lower().startswith("yaml.safedump"):
                    if node.args:
                        obj = node.args[0]
                        if isinstance(obj, ast.Dict):
                            keys = extract_string_from_dict_key(obj)
                            for key in keys:
                                if key.lower() in self._password_var_keywords:
                                    findings.append(self._make_finding(node, file_path))
                                    break
                    continue

                # 6) Database insertion: cursor.execute("...password...") or passing password var
                if node.func.attr.lower() in self._db_methods:
                    # Check first argument is a SQL string containing “password”
                    if node.args:
                        first = node.args[0]
                        if is_string_literal(first) and "password" in get_constant_value(first).lower():
                            findings.append(self._make_finding(node, file_path))
                            continue
                    # Check keyword args or second arg being a dict/list with “password” key
                    for arg in node.args[1:]:
                        if isinstance(arg, ast.Dict):
                            keys = extract_string_from_dict_key(arg)
                            for key in keys:
                                if key.lower() in self._password_var_keywords:
                                    findings.append(self._make_finding(node, file_path))
                                    break
                            else:
                                continue
                            break
                    for kw in node.keywords:
                        if kw.arg.lower() in self._password_var_keywords:
                            findings.append(self._make_finding(node, file_path))
                            break
                    continue

            # 7) Setting environment variable: os.environ["PASSWORD"] = ...
            elif isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Subscript):
                sub = node.targets[0]
                # Check base is os.environ or os.getenv assignment
                if isinstance(sub.value, ast.Attribute):
                    full = get_full_attr_name(sub.value).lower()
                    if full in {"os.environ", "os.getenv"}:
                        # Check key is literal string “PASSWORD” or similar
                        index = sub.slice
                        # ast.Index used in Python <3.9, but we can handle Constant directly
                        key_node = index.value if hasattr(index, "value") else index
                        if is_string_literal(key_node) and key_node.value.lower() in self._password_var_keywords:
                            # Check right-hand side is literal or password var
                            rhs = node.value
                            if is_string_literal(rhs) or (isinstance(rhs, ast.Name) and self._is_password_name(rhs.id)):
                                findings.append(self._make_finding(node, file_path))
                                continue

            # 8) Logging a password: logger.info(password) or print(password)
            elif isinstance(node, ast.Call):
                # Check for logger.* or direct print
                func = node.func
                if isinstance(func, ast.Attribute):
                    # logger.<level>(…)
                    if func.attr.lower() in {"debug", "info", "warning", "error", "critical", "exception"}:
                        if isinstance(func.value, ast.Name) and func.value.id.lower() in {"logger", "logging"}:
                            for arg in node.args:
                                if isinstance(arg, ast.Name) and self._is_password_name(arg.id):
                                    findings.append(self._make_finding(node, file_path))
                                    break
                            continue
                elif isinstance(func, ast.Name) and func.id == "print":
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and self._is_password_name(arg.id):
                            findings.append(self._make_finding(node, file_path))
                            break
                    continue

        return findings

    def _is_password_name(self, name: str) -> bool:
        """
        Return True if the identifier name suggests a password.
        """
        return any(keyword in name.lower() for keyword in self._password_var_keywords)

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
