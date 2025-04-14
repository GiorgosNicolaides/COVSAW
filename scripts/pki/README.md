# 🏛️ PKI & Certificate Transparency Analysis

This folder contains tools to analyze X.509 certificate chain structure and detect the presence of Certificate Transparency (CT) logs via Signed Certificate Timestamps (SCTs).

---

## 📦 Modules

### `ct_sct_checker.py`
Checks:
- Presence of SCTs (Signed Certificate Timestamps) in the certificate
- Validates whether the certificate is logged to public CT logs

**CWE:**
- CWE-295: Improper certificate validation (missing CT could indicate misissuance)

---

### `pki_chain_analyzer.py`
Analyzes:
- Certificate chain completeness (self-signed root vs. intermediates)
- Subject/issuer relationships
- Chain depth
- Root self-signing

**CWE:**
- CWE-295: Incomplete or improperly validated trust chain

---

### `pki_runner.py`
Combines SCT check and chain analysis into a unified PKI report.

---

