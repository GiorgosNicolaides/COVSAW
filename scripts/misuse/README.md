# 🔄 Cryptographic Protocol Misuse Analysis

This folder contains static analysis tools to detect insecure or non-standard composition of cryptographic primitives — often seen in custom or flawed protocols.

---

## 📦 Modules

### `detect_custom_crypto_protocols.py`
Flags:
- Manual chaining of encryption + HMAC
- Usage of CBC/ECB without integrity
- Misuse of `encrypt(...) + digest()` combinations
- Import of low-level cipher modules (e.g., PyCrypto, Crypto.Cipher)

**CWEs:**
- CWE-327: Use of broken/weak crypto
- CWE-294: Insecure chaining without authentication

---

### `detect_aead_misuse.py`
Detects:
- AEAD modes (e.g., AES-GCM, ChaCha20Poly1305) used without:
  - AAD (Additional Authenticated Data)
  - Proper tag verification
  - Secure nonce usage (constant, wrong length, reused)

**CWEs:**
- CWE-338: Use of weak PRNG for nonce
- CWE-330: Incorrect use of crypto API (nonce length)
- CWE-352: Missing AAD
- CWE-347: Improper handling of decrypt return value

---

### `detect_hybrid_crypto_misuse.py`
Scans for:
- Direct RSA encryption of plaintext (no symmetric envelope)
- Insecure padding (e.g. PKCS1v15 instead of OAEP)
- Missing symmetric layer in a hybrid scheme

**CWEs:**
- CWE-326: Insecure padding
- CWE-330: Missing symmetric layer (hybrid misuse)

---

### `misuse_runner.py`
- Dynamically discovers all `*Checker` classes in this directory
- Scans files or directories (`--path`)
- Supports text or JSON output (`--format json`)
- Returns non-zero exit code on detected issues

---

## 🧪 Tests

We have added pytest tests for each misuse detector (except the `ECB`-mode test which is pending):

### AEAD Misuse (`detect_aead_misuse.py`)
- **`test_aead_constant_nonce_flagged`**: constant nonce literal triggers a warning.
- **`test_aead_missing_aad_flagged`**: omitting `associated_data` is flagged.
- **`test_aead_missing_nonce_flagged`**: calling `encrypt()` without nonce argument is flagged.

### Custom Protocols (`detect_custom_crypto_protocols.py`)
- **`test_custom_cbc_no_hmac_flagged`**: CBC without HMAC triggers authentication warning.
- **`test_custom_cbc_with_hmac_no_issue`**: CBC with HMAC produces no warnings.
- *(`test_custom_ecb_mode_flagged` is currently pending)*

### Hybrid Misuse (`detect_hybrid_crypto_misuse.py`)
- **`test_hybrid_rsa_no_padding_flagged`**: missing padding argument is flagged.
- **`test_hybrid_rsa_insecure_padding_flagged`**: use of PKCS1v15 is flagged.
- **`test_hybrid_rsa_without_sym_layer_flagged`**: RSA.encrypt without a symmetric layer is flagged.
- **`test_hybrid_correct_hybrid_no_issue`**: proper hybrid pattern yields no warnings.

To run the tests:

```bash
pip install pytest
pytest -v
```
