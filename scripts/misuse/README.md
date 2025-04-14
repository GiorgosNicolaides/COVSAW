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
  - Secure nonce usage

**CWEs:**
- CWE-330: Use of insufficiently random values
- CWE-347: Improper verification of cryptographic signature

---

### `detect_hybrid_crypto_misuse.py`
Scans for:
- Direct RSA encryption of plaintext (no envelope)
- Static/shared session keys
- Lack of secure key wrapping

**CWEs:**
- CWE-780: Use of RSA without hybrid encryption
- CWE-329: Use of predictable values in crypto

---

### `misuse_runner.py`
Runs all protocol misuse detectors and aggregates the results.

---