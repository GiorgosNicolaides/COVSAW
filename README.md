# 🛡️ COVSAW

> **Classification of Cryptographic Vulnerabilities and Security Assessment of Web Applications**

COVSAW is a modular command-line tool that performs both static and dynamic analysis to uncover cryptographic vulnerabilities in Python applications and TLS-enabled web servers. Designed for educational, professional, or research purposes, COVSAW classifies common cryptographic implementation errors, insecure design patterns, and weak protocol configurations.

---

## 📦 Installation

1. **Clone the repository**:
```bash
git clone https://github.com/yourusername/covsaw.git
cd covsaw
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. *(Optional)* Install in development mode for CLI access:
```bash
pip install -e .
```

> **Python 3.9 or higher is required** due to reliance on `ast.unparse()` for source inspection.

---

## 🧪 How to Use

Run COVSAW from the project root or after installing as a package:

### 🔐 TLS Analysis
```bash
python cli.py --tls example.com
```

### 🏛️ PKI and Certificate Transparency
```bash
python cli.py --pki example.com
```

### 🔑 Static File-Based Analysis
```bash
python cli.py --passwords app.py
python cli.py --symmetric app.py
python cli.py --signatures app.py
python cli.py --misuse app.py
python cli.py --keymgmt app.py
```

### 🧰 Full Static Analysis
```bash
python cli.py --all app.py
```

---

## 🧠 What the Tool Does

COVSAW performs a **comprehensive audit of cryptographic usage**:

- ✅ Fetches and inspects **TLS certificates** from live hosts
- ✅ Checks **certificate validity, revocation (OCSP)**, hostname matching, signature/key strength
- ✅ Audits Python source code for:
  - ❌ Plaintext password storage
  - ❌ Weak/insecure hash usage
  - ❌ Missing salts or KDFs
  - ❌ Hardcoded or static cryptographic keys
  - ❌ Use of ECB, DES, XOR, or predictable IVs
  - ❌ Improper protocol chaining (e.g., CBC+HMAC)
  - ❌ AEAD misuse (e.g., no nonce/AAD/tag checks)
  - ❌ Direct RSA usage without hybrid encryption
  - ❌ Missing signature verification or insecure comparison

Each module is independent and CWE-tagged, providing useful context about what class of vulnerability was found.

---

## 📄 Output

The output is printed to the terminal and includes:

- ✅ CWE classification (e.g., CWE-321: Hardcoded Key)
- ✅ Line numbers of findings (for source code scans)
- ✅ Host-specific details (for TLS checks)
- ❌ Errors or warnings with clear messages when validation fails

No data is exported or stored unless extended manually.

---

## 🎯 Who Is This For?

- Students learning cryptography or secure development
- Security professionals auditing Python apps or TLS configurations
- Educators running crypto security workshops
- Researchers exploring CWE classification and automated crypto misuse detection

---

## ⚖️ License

COVSAW is licensed under the MIT License. See the `LICENSE` file for more.

---

