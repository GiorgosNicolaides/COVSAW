from abc import ABC, abstractmethod
from typing import List
from ast import AST
from cryptoanalyzer.utils.metadata import Finding

class Rule(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique rule identifier."""
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of the issue."""
    
    @property
    @abstractmethod
    def cwe_ids(self) -> List[str]:
        """List of CWE identifiers this rule maps to."""
    
    @abstractmethod
    def check(self, tree: AST, file_path: str) -> List[Finding]:
        """
        Inspect the AST of a single file and return any Findings.
        """
