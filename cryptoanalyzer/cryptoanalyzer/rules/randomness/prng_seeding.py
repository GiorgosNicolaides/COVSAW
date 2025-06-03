# cryptoanalyzer/rules/randomness/cwe_336_337_prng_seeding.py

"""
Rule to detect:
  • CWE-336: Same Seed in PRNG
  • CWE-337: Predictable Seed in PRNG

This rule inspects calls to Python’s non-cryptographic PRNG (`random`) and flags:
  1. Calls to `random.seed(...)` or `Random(...)` without arguments (default seeding from time) → CWE-337.
  2. Calls to `random.seed(...)` or `Random(...)` with a literal constant (int, str, bytes) →  
     • If the same literal appears in more than one seed call → CWE-336  
     • Otherwise → CWE-337.
  3. Calls to `random.seed(...)` or `Random(...)` with a time-based function (`time.time()`,  
     `datetime.datetime.now()`, `datetime.now()`) → CWE-337.

By collecting all seed invocations first, we can detect repeated literal seeds for CWE-336
and single or default seeds for CWE-337.
"""

import ast
import datetime
from typing import Dict, List, Optional, Tuple

from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding
from cryptoanalyzer.utils.ast_utils import get_full_attr_name, is_string_literal, get_constant_value


# Consider “today” for any date-based seed checks (not strictly needed here but kept for symmetry)
_TODAY = datetime.date(2025, 6, 3)


class Cwe336Cwe337PrngSeedingRule(Rule):
    @property
    def name(self) -> str:
        return "CWE336_CWE337_PRNGSeeding"

    @property
    def description(self) -> str:
        return (
            "Detects PRNG seeding with the same constant (CWE-336) or otherwise predictable seeds (CWE-337)."
        )

    @property
    def cwe_ids(self) -> List[str]:
        # Actual CWE(s) are determined per invocation.
        return ["CWE-336", "CWE-337"]

    # Recognize time-based seeding functions (lowercase full names)
    _time_seed_prefixes = {
        "time.time",
        "datetime.datetime.now",
        "datetime.now",
    }

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        # First, attach parent pointers so we can identify Random() calls if needed
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                setattr(child, "parent", node)

        # Collect all seed invocations: mapping literal_value -> list of AST nodes
        # Also collect non-literal seeds for CWE-337 (no args or time-based)
        literal_seeds: Dict[str, List[ast.Call]] = {}
        other_seeds: List[ast.Call] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            full = get_full_attr_name(func).lower()

            # Detect random.seed(...) or Random.seed(...) or seed(...) if imported directly
            if full == "random.seed" or full.endswith(".random.seed") or (isinstance(func, ast.Name) and func.id.lower() == "seed"):
                # positional args
                if not node.args:
                    # No-arg: default seed → CWE-337
                    other_seeds.append(node)
                else:
                    arg0 = node.args[0]
                    # 1) Literal constant seed
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, (int, str, bytes)):
                        key = repr(arg0.value)
                        literal_seeds.setdefault(key, []).append(node)
                    # 2) Time-based seed: function call to predictable source
                    elif isinstance(arg0, ast.Call):
                        seed_full = get_full_attr_name(arg0.func).lower()
                        if any(seed_full.startswith(prefix) for prefix in self._time_seed_prefixes):
                            other_seeds.append(node)
                        else:
                            # Other non-literal calls we treat as predictable → CWE-337
                            other_seeds.append(node)
                    else:
                        # Variables or expressions: assume predictable → CWE-337
                        other_seeds.append(node)
                continue

            # Detect instantiation: random.Random(...) or Random(...) if imported
            if full == "random.random" or full.endswith(".random.random") or (isinstance(func, ast.Name) and func.id == "Random"):
                # If no positional args: Random() → default seed from time → CWE-337
                if not node.args:
                    other_seeds.append(node)
                else:
                    arg0 = node.args[0]
                    # 1) Literal constant seed
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, (int, str, bytes)):
                        key = repr(arg0.value)
                        literal_seeds.setdefault(key, []).append(node)
                    # 2) Time-based seed
                    elif isinstance(arg0, ast.Call):
                        seed_full = get_full_attr_name(arg0.func).lower()
                        if any(seed_full.startswith(prefix) for prefix in self._time_seed_prefixes):
                            other_seeds.append(node)
                        else:
                            other_seeds.append(node)
                    else:
                        other_seeds.append(node)
                continue

        # After collection, generate findings:
        #  A) Literal seeds appearing more than once → CWE-336
        for key, nodes_list in literal_seeds.items():
            if len(nodes_list) > 1:
                for call_node in nodes_list:
                    findings.append(self._make_finding(call_node, file_path, "CWE-336"))
            else:
                # Single occurrence of literal seed → CWE-337
                findings.append(self._make_finding(nodes_list[0], file_path, "CWE-337"))

        # B) All other seeds → CWE-337
        for call_node in other_seeds:
            findings.append(self._make_finding(call_node, file_path, "CWE-337"))

        return findings

    def _make_finding(self, node: ast.Call, file_path: str, cwe_id: str) -> Finding:
        return Finding(
            file_path=file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            rule=self.name,
            message=f"{self.description} ({cwe_id})",
            cwe_ids=[cwe_id],
        )
