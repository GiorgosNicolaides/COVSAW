# cryptoanalyzer/rules/credentials/cwe_324_use_of_key_past_expiration.py

"""
Rule to detect Use of Key Past its Expiration Date (CWE-324).

This rule flags any hard-coded expiration date in source code that is before
the current date (June 3, 2025), implying a key or certificate is already expired.
Patterns detected include:

  1. Calls to datetime.date(year, month, day) or datetime.datetime(year, month, day, …)
     with literal numeric arguments where the resulting date is < 2025-06-03.
  2. String literals matching ISO-8601 “YYYY-MM-DD” or “YYYY/MM/DD” formats where
     the date is before 2025-06-03.

By catching these patterns, we warn that a key or certificate using such a date
is already expired, fulfilling CWE-324 via static analysis.
"""

import ast
import re
import datetime
from typing import List, Optional

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import (
    get_full_attr_name,
    is_string_literal,
    get_constant_value,
)

# We consider today's date as June 3, 2025 for CWE-324 checks
_TODAY = datetime.date(2025, 6, 3)

# Regex for ISO-8601 date literals: "YYYY-MM-DD" or "YYYY/MM/DD"
_ISO_DATE_RE = re.compile(r'^(?P<year>\d{4})[/-](?P<month>\d{2})[/-](?P<day>\d{2})$')


class Cwe324UseOfExpiredKeyRule(Rule):
    @property
    def name(self) -> str:
        return "CWE324UseOfExpiredKey"

    @property
    def description(self) -> str:
        return (
            "A hard-coded expiration date is before the current date (June 3, 2025), "
            "indicating the key/certificate is already expired."
        )

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-324"]

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # 1) datetime.date(year, month, day) or datetime.datetime(year, month, day, …)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                full = get_full_attr_name(node.func).lower()
                # Check for datetime.date(...) or datetime.datetime(...)
                if full in {"datetime.date", "datetime.datetime"}:
                    exp_date = self._extract_date_from_args(node.args)
                    if exp_date and exp_date < _TODAY:
                        findings.append(self._make_finding(node, file_path))
                        continue

            # 2) String literal matching ISO date before today
            if is_string_literal(node):
                val = get_constant_value(node)
                if isinstance(val, str):
                    dt = self._parse_iso_date(val)
                    if dt and dt < _TODAY:
                        findings.append(self._make_finding(node, file_path))
                        continue

        return findings

    def _extract_date_from_args(self, args: List[ast.AST]) -> Optional[datetime.date]:
        """
        If args are [year, month, day, ...] as literals, return datetime.date(year, month, day).
        Otherwise return None.
        """
        if len(args) < 3:
            return None
        year_node, month_node, day_node = args[0], args[1], args[2]
        # All three must be Constant numeric literals
        if (
            isinstance(year_node, ast.Constant) and isinstance(month_node, ast.Constant)
            and isinstance(day_node, ast.Constant)
            and isinstance(year_node.value, int)
            and isinstance(month_node.value, int)
            and isinstance(day_node.value, int)
        ):
            try:
                return datetime.date(year_node.value, month_node.value, day_node.value)
            except ValueError:
                return None
        return None

    def _parse_iso_date(self, text: str) -> Optional[datetime.date]:
        """
        If text matches YYYY-MM-DD or YYYY/MM/DD, return a date object; else None.
        """
        m = _ISO_DATE_RE.match(text.strip())
        if not m:
            return None
        year, month, day = int(m.group("year")), int(m.group("month")), int(m.group("day"))
        try:
            return datetime.date(year, month, day)
        except ValueError:
            return None

    def _make_finding(self, node: ast.AST, file_path: str) -> Finding:
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=self.description,
            cwe_ids=self.cwe_ids,
        )
