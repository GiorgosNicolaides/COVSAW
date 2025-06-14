# CryptoAnalyzer CLI — Developer Guide

## Overview

This Developer Guide provides in-depth information for contributors and maintainers of the CryptoAnalyzer static‑analysis tool. It covers the project structure, coding conventions, adding new detection rules, testing, reporting, configuration, and release processes.

---

## Table of Contents

- [CryptoAnalyzer CLI — Developer Guide](#cryptoanalyzer-cli--developer-guide)
  - [Overview](#overview)
  - [Table of Contents](#table-of-contents)
  - [1. Project Structure](#1-project-structure)
  - [2. Coding Conventions](#2-coding-conventions)
  - [3. Rule Development](#3-rule-development)
    - [3.1 Rule Interface](#31-rule-interface)
    - [3.2 Adding a Rule](#32-adding-a-rule)
  - [4. Reporting Subsystem](#4-reporting-subsystem)
  - [5. Configuration Management](#5-configuration-management)
  - [6. Testing and Continuous Integration](#6-testing-and-continuous-integration)
  - [7. Building and Releasing](#7-building-and-releasing)
  - [8. Contribution Workflow](#8-contribution-workflow)

---

## 1. Project Structure

```
cryptoanalyzer/
├── banner.py             # ASCII‑art banner functionality
├── cli.py                # Main CLI entry-point
├── config.py             # Configuration loader (TOML/YAML/INI)
├── loader.py             # Source‑file discovery logic
├── analyzer.py           # Core engine: AST parsing and rule execution
├── rules/                # Detection rules by category
│   ├── credentials/
│   ├── randomness/
│   ├── algorithm_params/
│   ├── cleartext/
│   └── …  
├── reporter/             # Output formatters
│   ├── json_reporter.py
│   ├── csv_reporter.py
│   └── html_reporter.py
├── utils/                # Utility modules
│   ├── ast_utils.py      # AST helper functions
│   ├── file_utils.py     # File I/O helpers
│   └── logger.py         # Logging setup
├── tests/                # Unit tests for rules and core components
├── requirements.txt      
├── setup.py              
└── README.md
```

---

## 2. Coding Conventions

- **Language & Version**: Python 3.8+  
- **Formatting**: Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/). Use `black` for automatic formatting.  
- **Imports**:  
  - Standard library imports first, then third‑party, then local.  
  - Group and order: `builtins` → `third-party` → `cryptoanalyzer.*`.  
- **Docstrings**: Use triple‑quoted strings. Modules, classes, and functions must include docstrings following [PEP 257](https://www.python.org/dev/peps/pep-0257/).  
- **Type Annotations**: Use PEP 484 style for function signatures and return types.  
- **Logging**: Use the `logging` module via `utils/logger.py`, not print statements.

---

## 3. Rule Development

### 3.1 Rule Interface

All detection rules must inherit from the abstract `Rule` base class:

```python
from cryptoanalyzer.rules import Rule
from cryptoanalyzer.utils.metadata import Finding

class CweXYZMyRule(Rule):
    @property
    def name(self) -> str:
        return "CWEXYZMyRule"

    @property
    def description(self) -> str:
        return "Detects my specific vulnerability."

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-XYZ"]

    def check(self, tree: ast.AST, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        # AST traversal logic
        return findings
```

### 3.2 Adding a Rule

1. **Locate category** under `rules/` or create a new subfolder if needed.  
2. Name your file `cwe_<id>_<short_name>.py`.  
3. Implement `check()` to traverse `tree` with `ast.walk`. Use helpers from `utils/ast_utils.py`:  
   - `get_full_attr_name(node)`  
   - `is_string_literal(node)`, `get_constant_value(node)`  
4. Unit‑test your rule in `tests/`.  

---

## 4. Reporting Subsystem

- **JSONReporter** (`reporter/json_reporter.py`):  
  - `format(findings: List[Finding]) -> str` returns a JSON array.  
  - Deduplicates by `(file, line, col, cwe_id)`.

- **CsvReporter** (`reporter/csv_reporter.py`):  
  - `format(findings) -> str` returns CSV with header: `file,line,col,rule,message,cwe_id`.

- **HtmlReporter** (`reporter/html_reporter.py`):  
  - `format(findings) -> str` returns a complete HTML document with a styled table.  

To add a new format, create a new class in `reporter/` with a `format()` method and extend `cli.py` to handle the new `-f` choice.

---

## 5. Configuration Management

- **Config Loader** (`config.py`):  
  - Supports TOML, YAML, and INI via `toml`, `PyYAML`, or `configparser`.  
  - Exposes: `Config.load(path: Optional[str]) -> Config`  
  - Attributes: `disabled_rules: List[str]`

- **Using Config**:  
  ```python
  config = Config.load("cryptoanalyzer.toml")
  analyzer = Analyzer(config)
  ```
  The CLI filters out findings whose rule names appear in `config.disabled_rules`.

---

## 6. Testing and Continuous Integration

- **Unit Tests**: Place under `tests/`.  
  - Each rule should have positive and negative test cases.  
  - Use `pytest` as the test runner.  
- **Fixtures**: Use small code snippets stored in `tests/fixtures/`.  
- **CI Pipeline**:  
  - On pull requests, run `black --check .`, `flake8`, and `pytest`.  
  - Report coverage metrics; aim for > 90% rule coverage.

---

## 7. Building and Releasing

- **Packaging**: Define dependencies in `setup.py` or `pyproject.toml`.  
- **Versioning**: Follow [Semantic Versioning](https://semver.org/).  
- **Distribution**: Publish to PyPI via `twine`.  
- **Release Process**:  
  1. Bump version in `setup.py`.  
  2. Tag git commit: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`.  
  3. Push tags and upload to PyPI.

---

## 8. Contribution Workflow

1. **Fork** the repository.  
2. **Create a feature branch**: `git checkout -b feature/my-rule`.  
3. **Implement** rule or fix.  
4. **Write tests** and ensure all pass.  
5. **Format** code with `black .` and check lint: `flake8`.  
6. **Submit** a Pull Request describing your changes.  

We welcome improvements, bug fixes, and new rule contributions!

---

*End of Developer Guide*  