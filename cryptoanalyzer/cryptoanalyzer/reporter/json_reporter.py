# cryptoanalyzer/reporters/json_reporter.py

import json
from typing import List, Dict, Any
from cryptoanalyzer.utils.metadata import Finding


class JSONReporter:
    """
    Reporter that outputs findings as a JSON array. Automatically removes duplicate
    findings (same file, line, column, and CWE).
    """

    @staticmethod
    def dedupe_findings(findings: List[Finding]) -> List[Finding]:
        """
        Remove duplicate findings. Two findings are considered duplicates if they share
        the same file, line, column, and CWE identifier.
        """
        seen = set()
        unique = []
        for f in findings:
            # We treat each CWE separately, but if a Finding has multiple CWE IDs,
            # we flatten them so that each (file, line, col, cwe) tuple is unique.
            for cwe in f.cwe_ids:
                key = (f.file_path, f.line, f.col, cwe)
                if key not in seen:
                    seen.add(key)
                    # Create a new Finding object with just this single CWE ID to preserve one‐per‐CWE uniqueness
                    unique.append(
                        Finding(
                            file_path=f.file_path,
                            line=f.line,
                            col=f.col,
                            rule=f.rule,
                            message=f.message,
                            cwe_ids=[cwe],
                        )
                    )
        return unique

    @staticmethod
    def format(findings: List[Finding]) -> str:
        """
        Return JSON string for the list of findings, after removing duplicates.
        """
        deduped = JSONReporter.dedupe_findings(findings)

        output_list: List[Dict[str, Any]] = []
        for f in deduped:
            output_list.append({
                "file": f.file_path,
                "line": f.line,
                "col": f.col,
                "rule": f.rule,
                "message": f.message,
                "cwe_ids": f.cwe_ids,
            })

        return json.dumps(output_list, indent=2)
