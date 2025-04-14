# 🗝️ Key Management & Secret Handling Analysis

This folder contains static analysis tools to detect improper handling of cryptographic keys and secret materials in Python code. These patterns are commonly associated with insecure design choices, hardcoded credentials, and poor secret hygiene.

---

## 📦 Modules

### `detect_hardcoded_secrets.py`
Scans for:
- API keys, passwords, or credentials stored as string or byte literals
- Hardcoded cryptographic keys (symmetric or private)
- Secrets embedded in config variables, `.env` style assignments, or constants

**CWEs:**
- CWE-321: Use of hard-coded cryptographic key
- CWE-798: Use of hard-coded credentials
- CWE-312: Cleartext storage of sensitive information

---

### `detect_insecure_key_assignments.py`
Detects:
- Static or reused cryptographic key assignments
- Keys not generated using `os.urandom`, `secrets`, or secure keygen functions
- Derivation of keys from predictable values or weak input

**CWEs:**
- CWE-330: Use of insufficiently random values
- CWE-326: Inadequate encryption strength

---

### `key_management_runner.py`
Runs both key management modules and returns a unified security report.

---

