# cryptoanalyzer/reporter/html_reporter.py

"""
HTMLReporter formats findings into a simple HTML report. It deduplicates
findings on (file, line, col, cwe_id) and renders them in an HTML table.
"""

from typing import List, Set, Tuple
from html import escape

from cryptoanalyzer.utils.metadata import Finding


class HtmlReporter:
    @staticmethod
    def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
        """
        Remove duplicate findings. Two findings are considered duplicates if they
        share the same file_path, line, col, and CWE ID. Flatten multi‐CWE findings.
        """
        seen: Set[Tuple[str, int, int, str]] = set()
        unique: List[Finding] = []

        for f in findings:
            for cwe in f.cwe_ids:
                key = (f.file_path, f.line, f.col, cwe)
                if key in seen:
                    continue
                seen.add(key)
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

    def format(self, findings: List[Finding]) -> str:
        """
        Return an HTML string containing all deduplicated findings in a table.
        """
        deduped = self._dedupe_findings(findings)

        # Basic CSS for readability
        style = """
        <style>
          body {
            font-family: Arial, sans-serif;
            margin: 20px;
          }
          table {
            border-collapse: collapse;
            width: 100%;
          }
          th, td {
            border: 1px solid #ddd;
            padding: 8px;
          }
          th {
            background-color: #f2f2f2;
            text-align: left;
          }
          tr:nth-child(even) {
            background-color: #f9f9f9;
          }
          tr:hover {
            background-color: #e9e9e9;
          }
          .cwe {
            font-weight: bold;
          }
        </style>
        """

        # Begin HTML document
        html_parts = [
            "<!DOCTYPE html>",
            "<html lang=\"en\">",
            "<head>",
            "  <meta charset=\"UTF-8\">",
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">",
            "  <title>CryptoAnalyzer Report</title>",
            style,
            "</head>",
            "<body>",
            "  <h1>CryptoAnalyzer Findings</h1>",
        ]

        if not deduped:
            html_parts.append("  <p>No findings detected.</p>")
        else:
            html_parts.append("  <table>")
            # Table header
            html_parts.append("    <tr>")
            html_parts.append("      <th>File</th>")
            html_parts.append("      <th>Line</th>")
            html_parts.append("      <th>Col</th>")
            html_parts.append("      <th>Rule</th>")
            html_parts.append("      <th>Message</th>")
            html_parts.append("      <th>CWE</th>")
            html_parts.append("    </tr>")

            # Table rows
            for f in deduped:
                file_cell = escape(f.file_path)
                line_cell = str(f.line)
                col_cell = str(f.col)
                rule_cell = escape(f.rule)
                message_cell = escape(f.message)
                cwe_cell = escape(f.cwe_ids[0])  # one per Finding after dedupe

                html_parts.append("    <tr>")
                html_parts.append(f"      <td>{file_cell}</td>")
                html_parts.append(f"      <td>{line_cell}</td>")
                html_parts.append(f"      <td>{col_cell}</td>")
                html_parts.append(f"      <td>{rule_cell}</td>")
                html_parts.append(f"      <td>{message_cell}</td>")
                html_parts.append(f"      <td class=\"cwe\">{cwe_cell}</td>")
                html_parts.append("    </tr>")

            html_parts.append("  </table>")

        # Close HTML
        html_parts.append("</body>")
        html_parts.append("</html>")

        return "\n".join(html_parts)
