# cryptoanalyzer/utils/settings.py

"""
Default settings and constants for CryptoAnalyzer.

This module centralizes:
  - Default severity levels for each rule
  - Default exclude patterns (e.g., virtualenv, build artifacts)
  - Default output filenames
  - Any other “magic” constants that multiple modules might reference
"""

from typing import Dict, List

# -----------------------------------------------------------------------------
# Default severity levels per rule. Users can override via config.
# -----------------------------------------------------------------------------
# Possible levels: "LOW", "MEDIUM", "HIGH", "CRITICAL"
# If a rule isn’t listed here, it defaults to "MEDIUM".
DEFAULT_SEVERITY: Dict[str, str] = {
    "HardcodedCredentials":      "HIGH",    # CWE-798
    "PlaintextSecretStorage":    "HIGH",    # CWE-256, CWE-261
    "MissingEncryption":         "CRITICAL",# CWE-311
    "MissingIntegrityCheck":     "HIGH",    # CWE-353, CWE-354
    "ImproperCertificateValidation":        "CRITICAL", # CWE-295
    "MissingCertificateRevocationCheck":    "MEDIUM",   # CWE-299
    "BrokenOrWeakAlgorithm":     "HIGH",    # CWE-327, CWE-328
    "HashWithoutSalt":           "MEDIUM",  # CWE-759, CWE-760
    "RSAWithoutOAEP":            "HIGH",    # CWE-780
    "InsecureRandomness":        "MEDIUM",  # CWE-330
    "NonceReuse":                "HIGH",    # CWE-323
    "PredictableIV":             "HIGH",    # CWE-329
    "WeakPRNG":                  "MEDIUM",  # CWE-338
    "InsecureCipherMode":        "MEDIUM",  # CWE-310
    "PaddingOracleSusceptible":  "HIGH",    # CWE-346
    "HmacWeakDefault":           "MEDIUM",  # CWE-328
    "InsecureComparison":        "LOW",     # CWE-208
    "CleartextTransmission":     "HIGH",    # CWE-319
    "CleartextStorage":          "HIGH",    # CWE-312–318
}

# -----------------------------------------------------------------------------
# Default file/directory exclude patterns.
# These are globs; paths matching any pattern are skipped automatically.
# Users can override via config.exclude_patterns
# -----------------------------------------------------------------------------
DEFAULT_EXCLUDE_PATTERNS: List[str] = [
    # Virtualenvs and Python caches
    "*/.venv/*",
    "*/venv/*",
    "*/env/*",
    "*/__pycache__/*",
    "*/build/*",
    "*/dist/*",
    "*/.mypy_cache/*",
    "*/.pytest_cache/*",
    # Version control
    "*/.git/*",
    "*/.hg/*",
    "*/.svn/*",
    # Node modules (if scanned a polyglot project)
    "*/node_modules/*",
    # Bytecode or generated files
    "*.pyc",
    "*.pyo",
    "*.egg-info/*",
]

# -----------------------------------------------------------------------------
# Default output filenames (when user omits -o)
# -----------------------------------------------------------------------------
DEFAULT_HTML_REPORT = "cryptoanalyzer_report.html"
DEFAULT_CSV_REPORT  = "cryptoanalyzer_report.csv"
DEFAULT_JSON_REPORT = "cryptoanalyzer_report.json"

# -----------------------------------------------------------------------------
# Environment variable names for overriding behavior
# -----------------------------------------------------------------------------
ENV_LOG_LEVEL = "CRYPTOANALYZER_LOG"   # e.g., set to "DEBUG", "INFO", etc.
ENV_DISABLE_COLORS = "CRYPTOANALYZER_NO_COLOR"  # if set, disable terminal colors

# -----------------------------------------------------------------------------
# Utility functions (optional) for other modules to reference
# -----------------------------------------------------------------------------
def get_default_severity(rule_name: str) -> str:
    """
    Return the default severity for `rule_name`. If not found, returns "MEDIUM".
    """
    return DEFAULT_SEVERITY.get(rule_name, "MEDIUM")
