# 🔐 TLS Analysis Modules

This folder contains modules that audit Transport Layer Security (TLS) configurations, certificates, and cryptographic settings.

## 📦 Modules

### `tls_certificate_checker.py`
- Retrieves and parses the server's certificate
- Checks:
  - Subject & Issuer
  - Expiry date
  - Hostname validation
  - Self-signed detection
  - Issuer trust (based on `greek_trusted_cas.txt`)

**CWE:** CWE-295, CWE-297

---

### `tls_revocation_checker.py`
- Sends OCSP request to verify revocation status of the certificate
- Handles no-OCSP-case gracefully

**CWE:** CWE-299

---

### `tls_crypto_strength_checker.py`
- Checks the cryptographic strength of the certificate:
  - RSA key size (≥2048)
  - EC curve safety
  - Signature hash algorithm

**CWE:** CWE-326, CWE-327

---

### `tls_protocol_cipher_checker.py`
- Connects to server and inspects:
  - TLS protocol version
  - Cipher suite used
  - Whether forward secrecy is supported

**CWE:** CWE-327, CWE-757

---

### `tls_extension_checker.py`
- Parses X.509 extensions in the cert:
  - `keyUsage` → must include digitalSignature/keyEncipherment
  - `extendedKeyUsage` → must include `serverAuth`
  - `basicConstraints` → must not be a CA for end-entity

**CWE:** CWE-284

---

### `tls_runner.py`
- Orchestrates all TLS modules and prints a unified security report.

---

### `greek_trusted_cas.txt`
- Text file listing known trusted Greek or EU CAs (used in issuer validation).

---
