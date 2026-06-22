"""Tests for the JSON and CSV reporters, including de-duplication."""

import json

from cryptoanalyzer.reporter.json_reporter import JSONReporter
from cryptoanalyzer.reporter.csv_reporter import CsvReporter
from cryptoanalyzer.utils.metadata import Finding


def _findings_with_duplicate():
    """Two findings at the same location/CWE plus one distinct finding."""
    dup_a = Finding("a.py", 10, 4, "RuleX", "weak hash", ["CWE-328"])
    dup_b = Finding("a.py", 10, 4, "RuleX", "weak hash", ["CWE-328"])
    other = Finding("b.py", 3, 0, "RuleY", "hardcoded key", ["CWE-321"])
    return [dup_a, dup_b, other]


def test_json_reporter_emits_valid_json_and_dedupes():
    report = JSONReporter().format(_findings_with_duplicate())
    parsed = json.loads(report)
    assert isinstance(parsed, list)
    # The two identical findings collapse into one; the distinct one remains.
    assert len(parsed) == 2
    keys = {(row["file"], row["line"], row["col"], row["cwe_ids"][0]) for row in parsed}
    assert ("a.py", 10, 4, "CWE-328") in keys
    assert ("b.py", 3, 0, "CWE-321") in keys


def test_csv_reporter_has_header_and_one_row_per_unique_finding():
    report = CsvReporter().format(_findings_with_duplicate())
    lines = [line for line in report.splitlines() if line.strip()]
    assert lines[0] == "file,line,col,rule,message,cwe_id"
    # Header + two unique findings.
    assert len(lines) == 3


def test_reporters_handle_empty_input():
    assert json.loads(JSONReporter().format([])) == []
    assert CsvReporter().format([]).splitlines()[0] == "file,line,col,rule,message,cwe_id"
