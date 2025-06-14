# CryptoAnalyzer

CryptoAnalyzer is a static-analysis command-line tool for detecting cryptographic vulnerabilities in Python code. It inspects Python source files for patterns mapped to Common Weakness Enumeration (CWE) identifiers and produces detailed reports in JSON, CSV, or HTML formats.

## Features

- **Comprehensive Rule Set**  
  Detects a wide range of cryptographic issues, including:
  - Hard-coded keys and credentials (CWE-321, CWE-798, etc.)
  - Plaintext or weak storage (CWE-256, CWE-312–318, CWE-526)
  - Broken or risky algorithms (CWE-327, CWE-780, CWE-1240)
  - Improper API usage and missing integrity checks (CWE-311, CWE-353, etc.)
  - Predictable or insufficient randomness (CWE-323, CWE-330–338)
  - Missing entity authentication (CWE-322)

- **Flexible Input**  
  Scan a single file, a directory (recursive), or a GitHub repository (shallow clone).

- **Multi-Format Reports**  
  Export findings in:
  - **JSON**: machine-readable array of findings.
  - **CSV**: spreadsheet-friendly rows.
  - **HTML**: styled table, auto-open in browser.

- **Extensible Architecture**  
  Add new detection rules by dropping modules under `rules/`. The tool auto-discovers and applies them.

- **Configurable**  
  Disable specific rules via a simple TOML, YAML, or INI config file (`cryptoanalyzer.toml`).

- **User-Friendly CLI**  
  Clear help text, colored banner, and robust error handling.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourorg/cryptoanalyzer.git
   cd cryptoanalyzer
   ```

2. (Optional) Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. (Optional) Install globally:
   ```bash
   pip install .
   ```

## Usage

```bash
cryptoanalyzer TARGET [-c CONFIG] [-f {json,html,csv}] [-o OUTPUT]
```

- **TARGET**:  
  - A local directory path (recursive).  
  - A single `.py` file or glob pattern (e.g. `src/**/*.py`).  
  - A GitHub URL (shallow clone).

- **Options**:
  - `-c, --config CONFIG`: Path to a TOML/YAML/INI config file.
  - `-f, --format {json,html,csv}`: Output format (default: `json`).
  - `-o, --output OUTPUT`: Output file path. For HTML, if omitted, opens in browser.

### Examples

- Scan a file and print JSON:
  ```bash
  cryptoanalyzer app.py
  ```

- Scan a directory and save CSV:
  ```bash
  cryptoanalyzer project/ -f csv -o findings.csv
  ```

- Scan a GitHub repo and view HTML report:
  ```bash
  cryptoanalyzer https://github.com/user/repo -f html
  ```

## Configuration

Create a `cryptoanalyzer.toml`, `.yaml`, or `.ini` file in your project root:

```toml
disabled_rules = [
  "CWE321HardcodedCryptoKey",
  "CWE329PredictableIV"
]
```

## Contributing

We welcome contributions! To add a new rule or feature:

1. Fork the repository and create a new branch.
2. Add or modify code (follow PEP 8 and existing patterns).
3. Write tests under `tests/`.
4. Run `black .`, `flake8`, and `pytest`.
5. Submit a Pull Request.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.