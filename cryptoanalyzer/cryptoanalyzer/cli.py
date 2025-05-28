#!/usr/bin/env python3
"""
Entry point for the CryptoAnalyzer CLI.
"""

import argparse
import sys
import os
import webbrowser

from cryptoanalyzer.config import Config
from cryptoanalyzer.analyzer import Analyzer
from cryptoanalyzer.reporter.json_reporter import JsonReporter
from cryptoanalyzer.reporter.html_reporter import HtmlReporter


def main():
    parser = argparse.ArgumentParser(
        prog="cryptoanalyzer",
        description="Static analysis of cryptographic usage vulnerabilities"
    )
    parser.add_argument(
        "target",
        help="File, directory, or glob pattern to scan"
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to config file (TOML/YAML/INI). "
             "If omitted, will search in cwd for cryptoanalyzer.toml, etc."
    )
    parser.add_argument(
        "-f", "--format",
        choices=["json", "html"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "-o", "--output",
        help=(
            "Write report to file. "
            "For HTML, if omitted we'll write to ./cryptoanalyzer_report.html and open it."
        )
    )
    args = parser.parse_args()

    # 1) Load configuration
    config = Config.load(args.config)

    # 2) Run analysis
    analyzer = Analyzer(config)
    try:
        findings = analyzer.analyze_path(args.target)
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        sys.exit(1)

    # 3) Filter out disabled rules
    if config.disabled_rules:
        findings = [f for f in findings if f.rule not in config.disabled_rules]

    # 4) Produce report
    if args.format == "json":
        report = JsonReporter().report(findings)
        # JSON always goes to stdout or specified file
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as out_file:
                    out_file.write(report)
            except Exception as e:
                print(f"Error writing report to {args.output}: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print(report)

    else:  # html
        reporter = HtmlReporter()
        report = reporter.report(findings)

        # Decide where to write the HTML
        output_path = args.output
        if not output_path:
            output_path = "cryptoanalyzer_report.html"
        try:
            with open(output_path, "w", encoding="utf-8") as out_file:
                out_file.write(report)
        except Exception as e:
            print(f"Error writing HTML report to {output_path}: {e}", file=sys.stderr)
            sys.exit(1)

        # Open in default browser
        abs_path = os.path.abspath(output_path)
        print(f"HTML report written to {abs_path}\nOpening in your default browser…")
        webbrowser.open(f"file://{abs_path}")

    # 5) Exit normally
    sys.exit(0)


if __name__ == "__main__":
    main()
