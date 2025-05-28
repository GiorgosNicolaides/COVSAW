# cryptoanalyzer/reporter/html_reporter.py

import html
from datetime import datetime
from typing import List
from cryptoanalyzer.utils.metadata import Finding

class HtmlReporter:
    """
    Reporter that generates an HTML table of Findings.
    """

    def report(self, findings: List[Finding]) -> str:
        """
        :param findings: List of Finding objects
        :return: An HTML document as a string
        """
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        # HTML header and basic styling
        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "  <meta charset='utf-8'>",
            "  <title>CryptoAnalyzer Report</title>",
            "  <style>",
            "    body { font-family: sans-serif; padding: 20px; }",
            "    table { border-collapse: collapse; width: 100%; }",
            "    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }",
            "    th { background: #f5f5f5; }",
            "    tr:nth-child(even) { background: #fafafa; }",
            "  </style>",
            "</head>",
            "<body>",
            f"  <h1>CryptoAnalyzer Report</h1>",
            f"  <p>Generated: {now}</p>",
            "  <table>",
            "    <thead>",
            "      <tr>",
            "        <th>File</th>",
            "        <th>Location</th>",
            "        <th>Rule</th>",
            "        <th>Message</th>",
            "        <th>CWE IDs</th>",
            "      </tr>",
            "    </thead>",
            "    <tbody>",
        ]

        # Table rows
        for f in findings:
            file_html    = html.escape(f.file_path)
            location     = f"{f.line}:{f.col}"
            rule_html    = html.escape(f.rule)
            message_html = html.escape(f.message)
            cwes_html    = ", ".join(html.escape(c) for c in f.cwe_ids)

            html_parts.extend([
                "      <tr>",
                f"        <td>{file_html}</td>",
                f"        <td>{location}</td>",
                f"        <td>{rule_html}</td>",
                f"        <td>{message_html}</td>",
                f"        <td>{cwes_html}</td>",
                "      </tr>",
            ])

        # Closing tags
        html_parts.extend([
            "    </tbody>",
            "  </table>",
            "</body>",
            "</html>",
        ])

        return "\n".join(html_parts)
