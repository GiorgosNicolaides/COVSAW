# cryptoanalyzer/rules/plaintext_secrets/plaintext_storage.py

"""
Module for detecting plaintext or weakly‐encoded secrets in code or configuration.

This rule flags:
  1. String constants that appear to be base64‐ or hex‐encoded secrets in code.
  2. File write calls (open(...).write or writelines) writing literal secrets.
  3. Calls to json.dump or yaml.dump of dicts containing sensitive keys.

Findings are tagged with:
  - CWE-256: Plaintext Storage of a Password
  - CWE-261: Weak Encoding for Password
"""

import ast
import re
from typing import List

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding


class PlaintextStorageRule(Rule):
    @property
    def name(self) -> str:
        return "PlaintextSecretStorage"

    @property
    def description(self) -> str:
        return "Plaintext or weakly‐encoded secret found in code or config"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-256", "CWE-261"]

    # Minimum length to consider for encoded secrets
    _min_encoded_length = 40

    # Regex for hex strings (e.g., long hex secret)
    _hex_pattern = re.compile(r'^[0-9a-fA-F]{' + str(_min_encoded_length) + r',}$')

    # Regex for base64 strings (simple heuristic)
    _b64_pattern = re.compile(
        r'^(?:[A-Za-z0-9+/]{4})*'
        r'(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
    )

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # 1) Constant string nodes: check for long hex or base64‐like literals
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value.strip()
                if len(val) >= self._min_encoded_length:
                    if self._hex_pattern.fullmatch(val) or self._b64_pattern.fullmatch(val):
                        findings.append(self._make_finding(node, file_path))
                        continue

            # 2) File write calls: open(...).write(...) or writelines(...)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"write", "writelines"}:
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            findings.append(self._make_finding(node, file_path))
                            break
                    continue

            # 3) json.dump/json.dumps or yaml.dump/yaml.safe_dump of dicts with string literals
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                lib = getattr(node.func.value, "id", "")
                method = node.func.attr
                if lib in {"json", "yaml"} and method in {"dump", "dumps", "safe_dump"}:
                    if node.args:
                        obj = node.args[0]
                        if isinstance(obj, ast.Dict):
                            for key in obj.keys:
                                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                                    # any string literal key signals potential config dump
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
