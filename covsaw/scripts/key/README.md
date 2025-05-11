# 🗝️ Key Management & Secret Handling Analysis

This project provides static analysis tools to detect insecure key-management and secret-handling patterns in Python code. It includes three main modules and a suite of pytest-based unit tests to ensure correct detection.

---

## 📦 Modules

### `scripts/key/detect_hardcoded_secrets.py`
Detects hardcoded secret values in code, including:
- **Literal assignments** to variables whose names imply secrets (e.g., `password = "hunter2"`).
- **Hex/Base64 blobs** matching common key lengths (e.g., 32+ hex characters or 40+ Base64 chars).
- **High-entropy strings** via Shannon entropy fallback (threshold: 4.0 bits/char).
- **Concatenated literals** across `+` operations.
- **F-strings** containing literal fragments of sufficient length.
- **Function defaults** for parameters named like secrets (e.g., `def foo(api_key="...")`).
- **`os.getenv` fallbacks** with hardcoded second-argument defaults.

Each finding reports the line number, a concise message (e.g., `password assigned hardcoded secret`), and a severity tag (`high` or `medium`).

### `scripts/key/detect_insecure_storage.py`
Flags insecure storage or transmission of sensitive variables:
- **Printing** or **logging** of secret-named variables (e.g., `print(password)`, `logger.info(token)`).
- **File writes** via `with open(...) as f: f.write(secret)` and unguarded `open(...).write(secret)` calls.
- **Subprocess/system calls** passing secret variables, including list/tuple args (`subprocess.run([token])`).
- **Clipboard leaks** via `pyperclip.copy(secret)`.
- **Environment assignments** to `os.environ[...] = secret`.

Reports include CWE codes (e.g., CWE-78 for command injection) and severity levels.

### `scripts/key/key_management_runner.py`
A CLI runner that:
- **Discovers** all `*Checker` classes in `detect_*.py` modules within `scripts/key/`.
- **Recursively scans** Python files under a target path.
- **Executes** each checker, collecting `(file, line, message)` tuples.
- **Supports** `--format text` (default) and `--format json` output.
- Honors `--quiet`/`--verbose` flags for OK messages.
- **Exit codes:** `0` if clean, `1` if issues found, `2` if no checkers loaded.

---

## ✅ Unit Tests

All detectors and the runner are covered by pytest tests located in:
```
scripts/key/tests/test_key_management.py
```

**Test categories:**

1. **Hardcoded Secrets Tests**
   - `test_literal_secret_flagged`: variables named like secrets with string literals.
   - `test_hex_blob_flagged`: detection of 32+ hex-character literals.
   - `test_fstring_secret_flagged`: f-strings containing literal secret fragments.
   - `test_function_default_secret_flagged`: function parameters with hardcoded default secrets.
   - `test_getenv_fallback_flagged`: `os.getenv` calls with hardcoded fallbacks.

2. **Insecure Storage Tests**
   - `test_print_secret_flagged`, `test_logger_secret_flagged`: print/log secret variables.
   - `test_with_open_write_flagged`, `test_open_write_flagged`: file writes of secrets.
   - `test_subprocess_secret_flagged`: passing secrets to `subprocess.run` (list or tuple args).
   - `test_pyperclip_copy_flagged`: clipboard copying of secrets.
   - `test_env_assign_flagged`: environment variable assignments.

3. **Runner Tests**
   - `test_discover_checkers`: ensures runner finds both checkers.
   - `test_scan_py_files`: verifies `.py` file listing behavior.
   - `test_analyze_file_reports`: runner reports issues on a known-hardcoded secret.
   - `test_analyze_file_no_issues`: runner yields no findings on benign code.

Run them with:
```bash
pytest -v
```

---

All modules and tests should now pass without errors. If you add new detectors or modify thresholds, be sure to update these tests accordingly.
