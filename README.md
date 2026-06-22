# CryptoAnalyzer (COVSAW)

> **C**lassification **O**f Cryptographic **V**ulnerabilities and **S**ecurity **A**ssessment of **W**eb applications

CryptoAnalyzer is a static-analysis command-line tool that detects **cryptographic
misuse in Python source code**. It parses each file into an Abstract Syntax Tree
(AST) and runs a suite of 30+ detection rules — each mapped to one or more
[Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) identifiers — to flag
issues such as broken hash algorithms, hard-coded keys, insecure randomness, weak
TLS configuration, and plaintext storage of secrets. Findings are exported as
JSON, CSV, or a styled HTML report. The project demonstrates practical secure-code
review automation: AST-based program analysis, a pluggable rule-engine architecture,
CWE taxonomy mapping, and CLI/report engineering — the kind of tooling a security
engineer builds to scale code review across a codebase.

---

## Tech stack

| Area | Choice |
| --- | --- |
| Language | Python 3.8+ |
| Program analysis | Python standard-library [`ast`](https://docs.python.org/3/library/ast.html) module |
| Rule discovery | `pkgutil` / `importlib` dynamic plugin loading |
| Config formats | [`toml`](https://pypi.org/project/toml/), [`PyYAML`](https://pypi.org/project/PyYAML/), and `configparser` (INI) |
| Terminal UX | [`colorama`](https://pypi.org/project/colorama/) for cross-platform colored output |
| Packaging | `setuptools` with a `console_scripts` entry point |
| Testing | `pytest` |
| Taxonomy | MITRE CWE identifiers |

No third-party AST or "AI" library is used — detection logic is hand-written against
the standard-library AST, which keeps the rules transparent and auditable.

---

## How it works

```
                 ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
 target  ─────▶  │   loader     │ ──▶ │   analyzer   │ ──▶ │  reporter    │ ──▶ JSON / CSV / HTML
 (file/dir/URL)  │ discover &   │     │ run every    │     │ dedupe &     │
                 │ parse → AST  │     │ Rule on AST  │     │ format       │
                 └──────────────┘     └──────────────┘     └──────────────┘
                                            ▲
                                      ┌──────────────┐
                                      │  rules/      │  auto-discovered Rule
                                      │  (plugins)   │  subclasses, one per weakness
                                      └──────────────┘
```

1. **Discover** — resolve the target (a file, a directory tree, a glob, or a GitHub
   URL that is shallow-cloned) into a list of `.py` files, honoring exclude patterns.
2. **Parse** — read each file and build an AST.
3. **Analyze** — every `Rule` subclass under `cryptoanalyzer/rules/` is auto-discovered
   and run against the AST, emitting `Finding` objects.
4. **Report** — findings are de-duplicated and serialized to the chosen format.

New detections are added simply by dropping a new `Rule` subclass module under
`rules/` — no central registry to edit.

---

## Installation

Prerequisites: **Python 3.8+** and **Git** (only needed to scan remote GitHub URLs).

```bash
# 1. Clone
git clone https://github.com/GiorgosNicolaides/COVSAW.git
cd COVSAW

# 2. (Recommended) create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) install the `cryptoanalyzer` command globally
pip install .
```

After `pip install .` you can invoke `cryptoanalyzer …` directly. Otherwise run it
as a module: `python -m cryptoanalyzer.cli …`.

---

## Usage

```bash
cryptoanalyzer TARGET [-c CONFIG] [-f {json,html,csv}] [-o OUTPUT]
```

- **TARGET** — a single `.py` file, a directory (scanned recursively), a glob
  (`src/**/*.py`), or a GitHub URL (shallow-cloned, scanned, then discarded).
- **`-c, --config`** — path to a TOML/YAML/INI config file (auto-discovered if omitted).
- **`-f, --format`** — `json` (default), `csv`, or `html`.
- **`-o, --output`** — output file path. JSON/CSV print to stdout if omitted; HTML
  writes `cryptoanalyzer_report.html` and opens it in your browser.

### Examples

```bash
# Scan the bundled deliberately-vulnerable sample and print JSON
cryptoanalyzer examples/vulnerable_sample.py

# Scan a project directory and save a CSV report
cryptoanalyzer myproject/ -f csv -o findings.csv

# Scan a public GitHub repo and view an HTML report
cryptoanalyzer https://github.com/user/repo -f html
```

---

## Example output

Scanning the bundled `examples/vulnerable_sample.py` (a file of intentionally
insecure functions) reports **18 findings across 11 rules**. Truncated JSON:

```json
[
  {
    "file": "examples/vulnerable_sample.py",
    "line": 24,
    "col": 8,
    "rule": "CWE328WeakHash",
    "message": "Use of a weak or broken hash algorithm (MD5, SHA-1) or HMAC defaulting to MD5.",
    "cwe_ids": ["CWE-328"]
  },
  {
    "file": "examples/vulnerable_sample.py",
    "line": 31,
    "col": 4,
    "rule": "CWE798HardcodedCredentials",
    "message": "Use of hard-coded credentials (username, password, token, API key, etc.) in source code.",
    "cwe_ids": ["CWE-798"]
  },
  {
    "file": "examples/vulnerable_sample.py",
    "line": 36,
    "col": 9,
    "rule": "CWE330InsufficientRandom",
    "message": "Non-cryptographic random values from the `random` module are used for security-sensitive purposes, leading to predictable values.",
    "cwe_ids": ["CWE-330"]
  }
]
```

The **HTML report** renders the same findings as a styled, sortable table with a
column per field (file, line, rule, message, CWE) — useful for sharing a scan
result with a non-technical reviewer. The **CSV report** produces one row per
unique `(file, line, column, CWE)` tuple for easy import into a spreadsheet or
ticketing system.

> Screenshots: to capture one, run
> `cryptoanalyzer examples/vulnerable_sample.py -f html` and screenshot the page
> that opens. (Generated reports are git-ignored.)

---

## Configuration

Drop a `cryptoanalyzer.toml` (or `.yaml` / `setup.cfg` / `pyproject.toml` under
`[tool.cryptoanalyzer]`) in your project root to disable rules or exclude paths:

```toml
disabled_rules = [
  "CWE328WeakHash",
  "CWE330InsufficientRandom",
]
exclude_patterns = [
  "**/tests/**",
  "**/migrations/**",
]
```

Set the log verbosity with the `CRYPTOANALYZER_LOG` environment variable
(`DEBUG`, `INFO`, `WARNING`, `ERROR`):

```bash
CRYPTOANALYZER_LOG=DEBUG cryptoanalyzer myproject/
```

---

## What I learned / Skills demonstrated

- **AST-based static analysis** — modeling source code as a tree and writing
  pattern-matching passes over it, rather than brittle regex/grep, to reason about
  *how* cryptographic APIs are called (positional vs. keyword args, attribute
  chains, string literals).
- **Mapping code to a vulnerability taxonomy** — translating real cryptographic
  failure modes into MITRE CWE identifiers (CWE-327/328, 321/798, 330–338, 256,
  295/370, 522 …), which is the language used by security findings and SAST tools.
- **Extensible plugin architecture** — an abstract `Rule` base class plus
  `pkgutil`/`importlib` auto-discovery, so new detections are added by convention
  with zero changes to the engine.
- **CLI and reporting engineering** — argument parsing, multi-format output
  (JSON/CSV/HTML), de-duplication, structured logging, and graceful handling of
  unparseable files and failed clones.
- **Secure-code-review mindset** — encoding the heuristics a human reviewer uses
  (weak primitives, hard-coded secrets, missing integrity checks, predictable IVs)
  into automated, repeatable checks.

---

## Security Concepts

This project is a **defensive** security tool: it finds cryptographic weaknesses so
they can be fixed. The classes of real-world vulnerabilities it detects include:

- **Broken / weak primitives (CWE-327, CWE-328)** — MD5 and SHA-1 are collision-prone;
  DES/RC4/Blowfish are obsolete. Using them for integrity or password hashing enables
  forgery and offline cracking.
- **Hard-coded & insufficiently protected credentials (CWE-321, CWE-522, CWE-798)** —
  secrets committed to source control or shipped in binaries are trivially extracted
  and cannot be rotated without a code change.
- **Insecure randomness (CWE-330–338)** — `random` is a deterministic PRNG; using it
  for keys, IVs, tokens, or nonces makes those values predictable and breaks the
  security of whatever depends on them.
- **Plaintext / recoverable storage & transmission (CWE-256, CWE-311–318, CWE-526)** —
  storing or sending secrets without encryption exposes them to anyone with disk,
  log, or network access.
- **TLS / certificate validation gaps (CWE-295, CWE-370)** — disabling certificate or
  hostname verification, or skipping revocation checks, reopens the door to
  man-in-the-middle attacks.

**Attack surface of the tool itself:** CryptoAnalyzer parses untrusted source files
and can shallow-clone untrusted GitHub URLs. It only *parses* code (via `ast.parse`)
and never executes it, which avoids arbitrary-code-execution from analyzed targets.
The `git clone` path shells out to Git with an argument list (no shell string
interpolation). See [SECURITY.md](SECURITY.md) for limitations and hardening notes.

---

## Project layout

```
cryptoanalyzer/
├── cli.py                # entry point (console_scripts: cryptoanalyzer)
├── analyzer.py           # rule auto-discovery + per-file analysis
├── loader.py             # file discovery and AST parsing
├── config.py             # TOML/YAML/INI configuration loading
├── banner.py             # startup ASCII-art banner
├── cwe_mapping.py        # rule-name → CWE reference table
├── reporter/             # JSON / CSV / HTML reporters
├── rules/                # one module per detection (auto-discovered)
└── utils/                # AST helpers, file helpers, logging, metadata
examples/vulnerable_sample.py   # deliberately insecure demo input
tests/                          # pytest suite
docs/                           # architecture, user & developer guides
```

---

## Development & tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

To add a rule: create a module under `cryptoanalyzer/rules/…`, subclass `Rule`,
implement `name`, `description`, `cwe_ids`, and `check(tree, file_path)`, and add a
test. The analyzer discovers it automatically on the next run.

---

## License

Released under the [MIT License](LICENSE).
