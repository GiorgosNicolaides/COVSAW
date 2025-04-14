# 🔐 Password Storage Analysis

This folder contains static analysis tools that detect insecure password handling, storage, and hashing practices in Python code.

---

## 📦 Modules

### `detect_plaintext_passwords.py`
Scans for:
- Hardcoded password strings (e.g., `password = "1234"`)
- Writing passwords to files or logs
- Printing sensitive variables

**CWEs:**
- CWE-257: Storing passwords in a recoverable format
- CWE-312: Insecure storage or transmission of sensitive data

---

### `detect_weak_password_hashing.py`
Detects:
- Use of weak hash algorithms like `md5`, `sha1`
- Direct password comparisons using `==` instead of hashes

**CWE:**
- CWE-328: Use of weak hash

---

### `detect_missing_salt_or_kdf.py`
Flags:
- Lack of salting when hashing passwords
- Use of `hashlib` without a KDF (`pbkdf2_hmac`, `bcrypt`, `scrypt`)
- Absence of pepper or static salts
- Insecure password hashing construction

**CWEs:**
- CWE-759: Missing salt
- CWE-916: Missing key stretching
- CWE-330: Weak randomness

---

### `password_storage_runner.py`
Aggregates results from all three modules and outputs a unified report.

---