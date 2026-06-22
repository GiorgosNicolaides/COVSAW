# cryptoanalyzer/utils/metadata.py

"""
Metadata definitions for findings emitted by CryptoAnalyzer rules.

Defines the Finding dataclass, which captures:
  - file_path: Path to the source file where the issue was detected
  - line: Line number of the issue (1-based)
  - col: Column offset of the issue (0-based)
  - rule: Unique identifier of the rule that was triggered
  - message: Human-readable description of the issue
  - cwe_ids: List of associated CWE identifiers for the issue
"""

from dataclasses import dataclass
from typing import List


@dataclass
class Finding:
    file_path: str
    line: int
    col: int
    rule: str
    message: str
    cwe_ids: List[str]
