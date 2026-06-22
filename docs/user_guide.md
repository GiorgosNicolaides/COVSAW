# CryptoAnalyzer CLI — User Guide

## Table of Contents

- [CryptoAnalyzer CLI — User Guide](#cryptoanalyzer-cli--user-guide)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Command-Line Usage](#command-line-usage)
    - [Syntax](#syntax)
    - [Arguments](#arguments)
    - [Options](#options)
  - [Report Formats](#report-formats)
    - [JSON](#json)
    - [CSV](#csv)
    - [HTML](#html)
  - [Configuration File](#configuration-file)
    - [Disabling Rules](#disabling-rules)
  - [Extending with New Rules](#extending-with-new-rules)
  - [Examples](#examples)
    - [1. Hard-coded Key](#1-hard-coded-key)
    - [2. Directory Scan](#2-directory-scan)
    - [3. GitHub Repo](#3-github-repo)
  - [Troubleshooting](#troubleshooting)
  - [License](#license)

---

## Introduction

**CryptoAnalyzer** is a static-analysis command-line tool for detecting cryptographic vulnerabilities in Python code. It scans `.py` files (single file, directory, or GitHub repo) and flags patterns mapped to standard [CWE](https://cwe.mitre.org/) identifiers.

---

## Installation

1. **Clone the repository** (or install via PyPI if published):

   ```bash
   git clone https://github.com/yourorg/cryptoanalyzer.git
   cd cryptoanalyzer
   ```

2. **Create a virtual environment** (optional but recommended):

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

4. **(Optional) Install globally**:

   ```bash
   pip install .
   ```

   This will make the `cryptoanalyzer` command available in your shell.

---

## Quick Start

Scan a single file and print JSON to stdout:

```bash
cryptoanalyzer path/to/app.py
```

Scan a directory, produce HTML, and open it in your browser:

```bash
cryptoanalyzer my_project/ -f html
```

Scan a GitHub repo and save CSV output:

```bash
cryptoanalyzer https://github.com/user/repo.git -f csv -o findings.csv
```

---

## Command-Line Usage

### Syntax

```text
cryptoanalyzer TARGET [ -c CONFIG ] [ -f {json,html,csv} ] [ -o OUTPUT ]
```

### Arguments

- `TARGET`  
  Path to scan. Can be:
  - A local directory (recursive)
  - A single `.py` file or glob pattern (e.g. `src/**/*.py`)
  - A GitHub URL (HTTPS or SSH) — the tool will shallow-clone it

### Options

- `-c, --config CONFIG`  
  Path to a TOML/YAML/INI config file. If omitted, the tool searches the current directory for `cryptoanalyzer.toml`, `.yaml`, or `.ini`.

- `-f, --format {json,html,csv}`  
  Output format. Defaults to `json`.

- `-o, --output OUTPUT`  
  Output file path.  
  - For **JSON** or **CSV**: if omitted, prints to stdout.  
  - For **HTML**: if omitted, writes to `./cryptoanalyzer_report.html` and opens it in your default browser.

---

## Report Formats

### JSON

- **Machine-readable** array of findings.
- Each object has:  
  ```json
  {
    "file": "...",
    "line": 123,
    "col": 4,
    "rule": "CWE329PredictableIV",
    "message": "...",
    "cwe_ids": ["CWE-329"]
  }
  ```
- Deduplicated by `(file, line, col, CWE)`.

### CSV

- **Spreadsheet-friendly** rows. Columns:

  ```
  file,line,col,rule,message,cwe_id
  ```

- One row per `(file, line, col, single CWE)`.

### HTML

- **Human-readable** styled table.
- Auto-opens in your browser (if no `-o` specified).
- Columns: File, Line, Col, Rule, Message, CWE.

---

## Configuration File

CryptoAnalyzer supports a simple config file in TOML, YAML, or INI format. Place it in your project root or specify with `-c`.

Example **`cryptoanalyzer.toml`**:

```toml
# Disable specific rules by their class names
disabled_rules = [
  "CWE321HardcodedCryptoKey",
  "CWE329PredictableIV"
]
```

### Disabling Rules

To turn off certain checks, list their rule names under `disabled_rules`. The CLI filters out any findings whose `rule` matches an entry in this list.

---

## Extending with New Rules

1. **Create a new module** under `cryptoanalyzer/rules/<category>/`, e.g.:

   ```
   cryptoanalyzer/rules/credentials/cwe_999_my_new_rule.py
   ```

2. **Implement the rule**:

   ```python
   import ast
   from cryptoanalyzer.rules import Rule
   from cryptoanalyzer.utils.metadata import Finding

   class Cwe999MyNewRule(Rule):
       @property
       def name(self):
           return "CWE999MyNewRule"

       @property
       def description(self):
           return "Description of the new rule."

       @property
       def cwe_ids(self):
           return ["CWE-999"]

       def check(self, tree: ast.AST, file_path: str):
           findings = []
           # walk the AST, append Finding(...) as needed
           return findings
   ```

3. **No core changes needed** — the `Analyzer` auto-discovers all `Rule` subclasses.

---

## Examples

### 1. Hard-coded Key

```bash
cryptoanalyzer example1.py -f json
```

```json
[
  {
    "file": "example1.py",
    "line": 2,
    "col": 4,
    "rule": "CWE321HardcodedCryptoKey",
    "message": "A cryptographic key is left as a literal...",
    "cwe_ids": ["CWE-321"]
  }
]
```

### 2. Directory Scan

```bash
cryptoanalyzer src/ -f csv -o report.csv
```

```
file,line,col,rule,message,cwe_id
src/app.py,45,12,CWE329PredictableIV,Literal IV in CBC mode,CWE-329
...
```

### 3. GitHub Repo

```bash
cryptoanalyzer https://github.com/user/project -f html
```

- Clones the repo, scans, writes `cryptoanalyzer_report.html`, then opens it.

---

## Troubleshooting

- **“No Python files found”**  
  Ensure your `TARGET` contains files ending in `.py`. Globs must be quoted (e.g. `"src/**/*.py"`).

- **Syntax errors in legacy code**  
  Files with Python-2 syntax will be skipped with an error log.  
  To scan, convert them to Python 3 (e.g. use `2to3`).

- **Git not found**  
  To scan GitHub URLs, you need the `git` command installed on your PATH.

- **Slow performance on large trees**  
  You can disable heavy rules in your config or scan smaller directories.

---

## License

CryptoAnalyzer is released under the **MIT License**. See `LICENSE` for details.