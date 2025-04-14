# 🔐 Symmetric Encryption Analysis

This folder contains tools to detect insecure, outdated, or misused symmetric encryption techniques in Python code. Each module targets a specific class of weakness in block ciphers, stream ciphers, and key/IV management.

---

## 📦 Modules

### `detect_ecb_des_usage.py`
Flags:
- Use of Electronic Codebook (ECB) mode
- Use of Data Encryption Standard (DES) or 3DES

**CWEs:**
- CWE-327: Use of a broken or risky cryptographic algorithm

---

### `detect_xor_encryption.py`
Detects:
- Use of XOR for "encryption" — commonly seen in insecure custom schemes
- Bitwise operations on bytes and plaintext directly

**CWE:**
- CWE-780: Use of non-standard encryption

---

### `detect_hardcoded_keys.py`
Scans for:
- Symmetric keys defined as string/byte literals
- Static or hardcoded cryptographic keys

**CWE:**
- CWE-321: Use of hard-coded cryptographic key

---

### `detect_weak_ivs_or_random.py`
Checks:
- Reuse or constant initialization vectors (IVs)
- Use of insecure random generators (e.g., `random.random()` instead of `secrets` or `os.urandom`)
- Non-random or predictable IV generation logic

**CWEs:**
- CWE-330: Use of insufficiently random values
- CWE-329: Predictable initialization vectors

---

### `symmetric_crypto_runner.py`
Runs all the symmetric analysis modules and aggregates results into a unified report.

---

