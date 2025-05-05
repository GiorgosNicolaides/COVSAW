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

## 🧪 Tests

We have added a suite of `pytest` tests covering each static analysis module:

### `detect_missing_salt_or_kdf.py`
- **`test_hashlib_without_salt_or_pepper`**: Flags direct calls like `hashlib.sha256(b"password")` without salt or pepper (CWE-759).
- **`test_pbkdf2_hmac_missing_salt`**: Verifies that `hashlib.pbkdf2_hmac("sha256", b"password")` with fewer than 3 args triggers a missing-salt error and a missing-pepper warning (CWE-916).
- **`test_with_salt_variable_no_issue`**: Ensures that mixing in a proper `salt = os.urandom(16)` into the hash produces no findings.
- **`test_with_pepper_variable_no_issue`**: Checks that appending `pepper.encode()` counts as pepper and does not raise an issue.

### `detect_plaintext_passwords.py`
- **`test_literal_assignment_detected`**: Detects assignments of plain-text passwords via string literals (e.g. `password = "secret"`).
- **`test_fstring_assignment_detected`**: Catches f-strings embedding literal password content.
- **`test_print_password_detected`**: Flags calls like `print(pwd)` where `pwd` matches a password-variable pattern.
- **`test_write_password_detected`**: Identifies writing password variables to file-like objects (e.g. `f.write(pw)`).
- **`test_nonpassword_var_no_issue`**: Confirms that non-password variables (e.g. `username`) are not falsely flagged.

### `detect_weak_password_hashing.py`
- **`test_md5_usage_flagged`**: Ensures `hashlib.md5(...)` is reported as a weak hash (CWE-328).
- **`test_sha1_direct_import_flagged`**: Verifies direct `sha1(b"...")` imports are flagged.
- **`test_constant_time_compare_low_severity`**: Recognizes `hmac.compare_digest(a, b)` as a good practice (low-severity).
- **`test_direct_equality_flagged_medium`**: Checks that `if pw == input:` triggers a medium-severity recommendation to use constant-time compare.
- **`test_no_weak_hash_no_issue`**: Confirms that strong hashes (`sha256`) with no other issues produce no warnings.

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