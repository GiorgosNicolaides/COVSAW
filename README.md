## Classification of Cryptograhic Vulnerabilies and Security Assesment of Web Appilcations 

---

## Features

### 1. TLS Certificate Analysis (`tls_certificate_checker.py`)
Performs deep inspection of a domain's TLS certificate. Includes:
- Certificate expiry check
- Self-signed certificate detection
- Hostname validation (CN and SAN)
- Issuer validation against trusted Greek CAs
- OCSP-based revocation status check
- Public key strength (RSA key size, EC curve security)
- Signature algorithm validation (e.g., SHA-1 detection)

### 2. Fetch Trusted CAs from EU TSL (`fetch_greek_trusted_cas.py`)
- Downloads the EU Trusted List and extracts all Qualified Trust Service Providers (QTSPs) for Greece (`EL`)
- Saves results to `greek_trusted_cas.txt`

### 3. Static Hash Analysis (`hash_analyzer.py`)
AST-based static code analyzer for insecure hashing practices in Python:
- Detects weak hash functions (e.g., MD5, SHA1)
- Warns on potential custom hashing logic using XOR/bitwise operators
- Highlights secure usage (e.g., PBKDF2, SHA-256)
- Configurable via YAML rule file (`rules/hash_rules.yaml`)

### 4. RSA Security Checker (`rsa_security_checker.py`)
AST-based scanner for insecure RSA usage in Python:
- Detects hardcoded RSA keys (private/public)
- Flags weak key sizes (<512 bits)
- Detects insecure PRNG usage in key generation
- Warns about missing padding (e.g., no OAEP in encryption)
- Identifies duplicate or reused key material


