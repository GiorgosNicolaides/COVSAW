"""Tests for the core Analyzer: rule discovery and end-to-end scanning."""

from cryptoanalyzer.utils.metadata import Finding


def test_rules_are_discovered(analyzer):
    """The analyzer should auto-discover a non-trivial number of rules."""
    assert len(analyzer.rules) >= 30
    # Rule names must be unique.
    names = [rule.name for rule in analyzer.rules]
    assert len(names) == len(set(names))


def test_sample_scan_produces_findings(sample_findings):
    """Scanning the deliberately-vulnerable sample must yield findings."""
    assert sample_findings, "expected at least one finding in the vulnerable sample"
    assert all(isinstance(finding, Finding) for finding in sample_findings)


def test_findings_have_well_formed_metadata(sample_findings):
    """Every finding must carry usable location and CWE metadata."""
    for finding in sample_findings:
        assert finding.file_path.endswith("vulnerable_sample.py")
        assert finding.line >= 1
        assert finding.col >= 0
        assert finding.rule
        assert finding.message
        assert finding.cwe_ids and all(c.startswith("CWE-") for c in finding.cwe_ids)


def test_expected_weaknesses_detected(sample_findings):
    """Known weaknesses planted in the sample should be detected by CWE id."""
    detected_cwes = {cwe for finding in sample_findings for cwe in finding.cwe_ids}
    # Weak hash (MD5/SHA-1), broken algorithm, hardcoded secrets, weak randomness.
    for expected in ("CWE-328", "CWE-327", "CWE-798", "CWE-330"):
        assert expected in detected_cwes, f"{expected} was not detected"
