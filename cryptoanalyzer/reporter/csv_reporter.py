# cryptoanalyzer/reporter/csv_reporter.py

import csv
import io
from typing import List
from cryptoanalyzer.utils.metadata import Finding


class CsvReporter:
    """
    Reporter that outputs findings as CSV. Columns:
      file,line,col,rule,message,cwe_id
    Deduplicates so that each (file, line, col, cwe_id) appears only once.
    """

    @staticmethod
    def format(findings: List[Finding]) -> str:
        """
        Return a CSV‐formatted string containing all unique findings.
        """
        # Deduplicate on (file_path, line, col, single CWE)
        seen = set()
        rows = []

        for f in findings:
            for cwe in f.cwe_ids:
                key = (f.file_path, f.line, f.col, cwe)
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "file": f.file_path,
                    "line": f.line,
                    "col": f.col,
                    "rule": f.rule,
                    "message": f.message,
                    "cwe_id": cwe,
                })

        # Write to in-memory buffer
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["file", "line", "col", "rule", "message", "cwe_id"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

        return output.getvalue()
