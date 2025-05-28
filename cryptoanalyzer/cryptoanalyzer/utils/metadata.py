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
