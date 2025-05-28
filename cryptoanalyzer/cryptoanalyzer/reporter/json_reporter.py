# cryptoanalyzer/reporter/json_reporter.py

import json
from typing import List
from cryptoanalyzer.utils.metadata import Finding

class JsonReporter:
    """
    Reporter that serializes Findings to JSON.
    """

    def report(self, findings: List[Finding]) -> str:
        """
        :param findings: List of Finding objects
        :return: A pretty-printed JSON string
        """
        # Convert each Finding to a simple dict
        serialized = []
        for f in findings:
            serialized.append({
                "file":       f.file_path,
                "line":       f.line,
                "col":        f.col,
                "rule":       f.rule,
                "message":    f.message,
                "cwe_ids":    f.cwe_ids,
            })
        return json.dumps(serialized, indent=2)
