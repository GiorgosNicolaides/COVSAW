# 🔐 Symmetric Encryption Analysis

This directory provides static analysis tools for identifying insecure symmetric encryption patterns in Python code. It covers weaknesses in block/stream ciphers, IV/key management, and custom encryption schemes.

---

## 📂 Modules

### `detect_ecb_des.py`
- **Flags** use of ECB mode with weak ciphers: DES or TripleDES.
- Detects calls like `DES.new(key, DES.MODE_ECB)` or `Cipher.new(..., MODE_ECB)`.

**CWE:** CWE-326 – Inadequate encryption strength

### `detect_hardcoded_keys.py`
- **Detects** hardcoded cryptographic material (keys, secrets, passwords, IVs, tokens).
- Scans assignments, f‑strings, function defaults, and `os.getenv(..., default)` fallbacks.

**CWE:** CWE-259 – Use of hard-coded password

### `detect_weak_iv.py`
- **Detects** static or predictable IVs (all-zero IVs or `b"\x00" * n`).
- Inspects both keyword arguments (`iv=...`, `nonce=...`) and positional arguments (2nd or 3rd parameter).

**CWE:** CWE-330 – Use of insufficiently random values

### `detect_xor_encryption.py`
- **Detects** custom XOR-based “encryption” (bitwise `^`) on plaintext.
- Flags nested or repeated XOR operations suggesting home‑grown cipher logic.

**CWE:** CWE-327 – Use of a broken or risky cryptographic algorithm

---

## 🏃 CLI Runner (`symmetric_analysis_runner.py`)

Discovers all `*Checker` classes in this directory and runs them against a target file or directory.

**Usage:**
```bash
python symmetric_analysis_runner.py [options] <path>
```

**Options:**
- `-f, --format {text,json}`: Output format (default: `text`).
- `-v, --verbose`: Show ✅ OK for clean files.
- `-q, --quiet`: Suppress OK messages.

**Output:**
- **Text**: `path:line: [checker] message`
- **JSON**: `[ {"file":..., "line":..., "message":...}, ... ]`

**Exit codes:**
- `0` – No issues.
- `1` – Issues found.
- `2` – No checkers discovered.

---

## 🧪 Unit Tests

### Checker Tests
Located in `scripts/symmetric/tests/test_symmetric_checkers.py`:
- **ECB & DES**: flags ECB usage, ignores CBC.
- **Hardcoded Keys**: flags hex‑like literals for sensitive names.
- **Weak IV**: flags zero IVs via keyword and positional arguments.
- **XOR Encryption**: flags XOR patterns, ignores non‑XOR operations.

### Runner Tests
Located in `scripts/symmetric/tests/test_symmetric_runner.py`:
- Dynamically creates a dummy checker module.
- Verifies both **text** and **JSON** runner outputs and non‑zero exit code.

Run tests with:
```bash
pytest scripts/symmetric/tests -v
```

---

## ⚙️ Configuration

Optionally customize behavior via a TOML file and the `SYM_CHECK_CONFIG` environment variable:
```toml
# sym_config.toml
iv_arg_names = ["iv", "nonce", "ctr"]
hardcoded_pattern = "^[A-Za-z0-9]{16,}$"
min_xor_ops = 2
```

Export before running:
```bash
export SYM_CHECK_CONFIG=/path/to/sym_config.toml
python symmetric_analysis_runner.py ./src
```
