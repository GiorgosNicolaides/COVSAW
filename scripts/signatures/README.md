# ✍️ Digital Signature Analysis

This folder contains tools to statically analyze the misuse of digital signature schemes in Python code.

---

## 📦 Modules

### `detect_insecure_signature_algos.py`
Scans for:
- Use of insecure hash algorithms (e.g., `MD5`, `SHA1`) in digital signatures

**CWE:**
- CWE-327: Use of a broken or risky cryptographic algorithm

---

### `detect_missing_verification.py`
Flags:
- Digital signature generation with no corresponding verification logic
- Cases where `sign(...)` is used but `verify(...)` is missing

**CWE:**
- CWE-347: Improper verification of cryptographic signature

---

### `detect_nonconstant_compare.py`
Detects:
- Use of `==` or `!=` for signature comparisons
- Recommends `hmac.compare_digest(...)` for constant-time comparison

**CWE:**
- CWE-203: Information exposure through timing attacks

---

### `signature_scheme_runner.py`
Orchestrates all three modules and outputs a unified report.

---