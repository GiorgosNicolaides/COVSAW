#!/usr/bin/env python3
"""
Entry point for the CryptoAnalyzer CLI.

Supports scanning:
  - A GitHub repo URL (https://github.com/user/repo or git@github.com:user/repo.git)
  - A local directory
  - A single .py file or glob pattern

Usage examples:
  cryptoanalyzer path/to/code -f json
  cryptoanalyzer https://github.com/user/repo -f html
  cryptoanalyzer src/**/*.py -f csv -o report.csv
"""

import argparse
import sys
import os
import tempfile
import shutil
import subprocess
import webbrowser

from cryptoanalyzer.banner import print_banner
from cryptoanalyzer.config import Config
from cryptoanalyzer.analyzer import Analyzer
from cryptoanalyzer.loader import discover_source_files
from cryptoanalyzer.reporter.json_reporter import JSONReporter
from cryptoanalyzer.reporter.html_reporter import HtmlReporter
from cryptoanalyzer.reporter.csv_reporter import CsvReporter
from cryptoanalyzer.utils.logger import get_logger
from cryptoanalyzer.utils.file_utils import write_text_file, ensure_directory

LOG = get_logger(__name__)


def _is_github_url(target: str) -> bool:
    """
    Return True if the target string appears to be a GitHub repository URL.
    """
    return target.startswith("https://github.com/") or target.startswith("git@github.com:")


def _clone_repo(git_url: str) -> str:
    """
    Clone the GitHub repository (shallow) into a temporary directory.
    Return the path to the cloned directory.

    Raises RuntimeError if cloning fails or if 'git' is not available.
    """
    temp_dir = tempfile.mkdtemp(prefix="cryptoanalyzer_repo_")
    try:
        LOG.info("Cloning repository %s …", git_url)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", git_url, temp_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            shutil.rmtree(temp_dir)
            LOG.error("git clone failed: %s", result.stderr.strip())
            raise RuntimeError(f"git clone failed:\n{result.stderr.strip()}")
        LOG.debug("Repository cloned to %s", temp_dir)
        return temp_dir
    except FileNotFoundError:
        shutil.rmtree(temp_dir)
        LOG.error("'git' command not found")
        raise RuntimeError("'git' command not found. Please install Git to scan GitHub repos.")


def main():
    # 1) Print the ASCII-art banner at startup (visible for ~2.5 seconds)
    print_banner()

    # 2) Parse command-line arguments
    parser = argparse.ArgumentParser(
        prog="cryptoanalyzer",
        description=(
            "Static analysis of cryptographic usage vulnerabilities.\n\n"
            "TARGET can be:\n"
            "  • A GitHub repo URL (e.g. https://github.com/user/repo or git@github.com:user/repo.git)\n"
            "  • A local directory path\n"
            "  • A single .py file path or glob pattern"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "target",
        help="GitHub URL, directory, or .py file/glob to scan"
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to config file (TOML/YAML/INI). If omitted, will search in cwd for cryptoanalyzer.toml, etc."
    )
    parser.add_argument(
        "-f", "--format",
        choices=["json", "html", "csv"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "-o", "--output",
        help=(
            "Write report to file.\n"
            "• For JSON or CSV: if omitted, prints to stdout.\n"
            "• For HTML: if omitted, writes to ./cryptoanalyzer_report.html and opens it."
        )
    )
    args = parser.parse_args()

    # 3) Load configuration
    LOG.debug("Loading configuration from %s", args.config)
    config = Config.load(args.config)

    # 4) If target is a GitHub URL, clone it first
    cleanup_dir = None
    scan_path = args.target
    if _is_github_url(args.target):
        try:
            cleanup_dir = _clone_repo(args.target)
            scan_path = cleanup_dir
        except RuntimeError as e:
            LOG.error("Error cloning repo: %s", e)
            sys.exit(1)

    # 5) Discover .py files to analyze
    try:
        LOG.info("Discovering Python files under %s", scan_path)
        py_files = discover_source_files(scan_path, config)
        LOG.info("Found %d Python file(s)", len(py_files))
    except Exception as e:
        LOG.error("Error discovering files: %s", e)
        if cleanup_dir:
            shutil.rmtree(cleanup_dir)
        sys.exit(1)

    # 6) If no .py files found, insult and exit
    if not py_files:
        if cleanup_dir:
            shutil.rmtree(cleanup_dir)
        LOG.error("No Python files found in target: %s", scan_path)
        print("You are an asshole.", file=sys.stderr)
        sys.exit(1)

    # 7) Run analysis on each file
    analyzer = Analyzer(config)
    findings = []
    try:
        for path in py_files:
            LOG.debug("Analyzing %s", path)
            findings.extend(analyzer.analyze_file(path))
        LOG.info("Analysis complete: %d finding(s) total", len(findings))
    except Exception as e:
        LOG.error("Error during analysis: %s", e)
        if cleanup_dir:
            shutil.rmtree(cleanup_dir)
        sys.exit(1)

    # 8) Clean up cloned repo if needed
    if cleanup_dir:
        LOG.debug("Removing temporary clone at %s", cleanup_dir)
        shutil.rmtree(cleanup_dir)

    # 9) Filter out disabled rules from config
    if config.disabled_rules:
        LOG.info("Filtering out disabled rules: %s", config.disabled_rules)
        findings = [f for f in findings if f.rule not in config.disabled_rules]

    # 10) Emit report in chosen format
    if args.format == "json":
        report = JSONReporter().format(findings)
        if args.output:
            LOG.info("Writing JSON report to %s", args.output)
            parent = os.path.dirname(args.output)
            if parent:
                ensure_directory(parent)
            write_text_file(args.output, report)
        else:
            print(report)

    elif args.format == "csv":
        report = CsvReporter().format(findings)
        if args.output:
            LOG.info("Writing CSV report to %s", args.output)
            parent = os.path.dirname(args.output)
            if parent:
                ensure_directory(parent)
            write_text_file(args.output, report)
        else:
            print(report)

    else:  # html
        report = HtmlReporter().format(findings)
        output_path = args.output or "cryptoanalyzer_report.html"
        LOG.info("Writing HTML report to %s", output_path)
        parent = os.path.dirname(output_path)
        if parent:
            ensure_directory(parent)
        write_text_file(output_path, report)
        abs_path = os.path.abspath(output_path)
        LOG.info("Opening HTML report in browser: %s", abs_path)
        print(f"HTML report written to {abs_path}\nOpening in your default browser…")
        webbrowser.open(f"file://{abs_path}")

    sys.exit(0)


if __name__ == "__main__":
    main()
