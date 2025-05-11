# ✍️ Digital Signature Analysis

This folder contains tools to statically analyze the misuse of digital signature schemes in Python code.

---

## 📦 Modules

### `detect_insecure_signature_algos.py`
- Extends a `SignatureChecker` AST base class for consistent parsing/reporting.
- Detects insecure hash algorithms (e.g., `hashlib.md5`, `hashlib.new('md5', ...)`, `Crypto.Hash.MD5.new()`).
- Supports configurable insecure hashes via `SIG_CHECK_CONFIG` environment variable (TOML).
- Flags use of any loaded insecure algorithm constants.

**CWE: CWE-327** (Use of a broken or risky cryptographic algorithm)

### `detect_missing_verification.py`
- Inherits from the shared `SignatureChecker` base.
- Tracks signature variable assignments (`sig = key.sign(...)`) and corresponding `verify` calls.
- Flags unverified signatures per variable and anonymous signing calls without any verification.
- Configurable `sign_functions` and `verify_functions` via `SIG_CHECK_CONFIG`.

**CWE: CWE-347** (Improper verification of cryptographic signature)

### `detect_nonconstant_compare.py`
- Inherits from the shared `SignatureChecker` base.
- Detects direct `==` or `!=` comparisons on signature-like names (e.g., `sig`, `mac`, `tag`).
- Flags both `Compare` and `Assert` nodes.
- Configurable `compare_names` via `SIG_CHECK_CONFIG`.
- Recommends using `secrets.compare_digest()` for constant-time comparison.

**CWE: CWE-203** (Information exposure through timing attacks)

---

## 🏃 Signature Scheme Runner

**`runner.py`** (formerly `signature_scheme_runner.py`)

- **Dynamic discovery** of all `*Checker` classes in `detect_*.py` modules.
- Argparse-based CLI with:
  - `path` (file or directory) to analyze.
  - `--format` (`text` or `json`).
  - `-q`/`--quiet` to suppress OK messages.
  - `-v`/`--verbose` to show OK messages for clean files.
- **Recursive scanning** of `.py` files under directories.
- **Output**:
  - **Text**: `path:line: [checker] message`.
  - **JSON**: structured list of issues.
- **Exit codes**:
  - `0` when no issues.
  - `1` when issues found.
  - `2` when no checkers discovered.
- **Robustness**: catches and reports individual checker crashes without stopping.

---

## ✅ Unit Tests

### Checkers tests (`scripts/signatures/tests/test_signatures_checkers.py`)
- **Insecure-hash**: ensures `md5` is flagged, `sha256` is ignored.
- **Missing-verification**: flags sign-only code; passes when verify is present.
- **Non-constant compare**: flags `==` comparisons; ignores `secrets.compare_digest()`.

### Runner tests (`tests/test_signature_scheme_runner.py`)
- Mocks dummy checkers to verify:
  - `discover_checkers()` dynamic loading of modules.
  - `scan_py_files()` filters only `.py` files.
  - `analyze_file()` collects issues and handles checker exceptions.
  - CLI invocation in both `text` and `json` modes with correct exit codes.

---

## ⚙️ Configuration

Create a TOML file and point `SIG_CHECK_CONFIG` at it:

```toml
# sig_config.toml
insecure_hashes = ["md5", "sha1"]
sign_functions = ["sign"]
verify_functions = ["verify"]
compare_names = ["sig", "tag"]
```

Export before running:
```bash
export SIG_CHECK_CONFIG=/path/to/sig_config.toml
python runner.py --format json ./my_project
```

---

## 📖 Usage

```bash
# Text output
git clone ... && cd scripts/signatures
python runner.py ./src

# JSON output
python runner.py --format json ./src

# Verbose OK messages
python runner.py -v ./src

# Quiet mode (no OK messages)
python runner.py -q ./src
```
