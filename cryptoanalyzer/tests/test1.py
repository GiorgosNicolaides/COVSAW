# tests/test1.py

import hashlib
import random
import ssl
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hmac

# 1. Weak hash algorithms (MD5, SHA-1)
def weak_hashing(data):
    m = hashlib.md5(data)       # CWE-328
    s = hashlib.sha1(data)      # CWE-327
    return m.hexdigest(), s.hexdigest()

# 2. Hardcoded secrets
def hardcoded_secrets():
    key = "supersecretkey123"   # CWE-321
    password = "hunter2"        # CWE-321
    return key, password

# 3. Insecure randomness
def insecure_randomness():
    r1 = random.random()        # CWE-330
    r2 = random.randint(1, 10)  # CWE-330
    return r1, r2

# 4. ECB mode usage
def ecb_encryption(data, key):
    cipher = AES.new(key, AES.MODE_ECB)  # CWE-310
    return cipher.encrypt(data)
mode_str = "ECB"                         # CWE-310 (string literal)

# 5. Insecure TLS configuration
def tls_issues():
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_NONE      # CWE-295
    ctx.check_hostname = False           # CWE-295
    old_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # CWE-326
    return ctx, old_ctx

# 6. Padding oracle pattern
def padding_oracle(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    try:
        plain = cipher.decrypt(data)
        return unpad(plain, AES.block_size)  # unpad inside broad except
    except Exception:                        # CWE-346
        pass

# 7. HMAC defaulting to MD5
def hmac_default_md5(msg, key):
    hm = hmac.new(key, msg)           # defaults to MD5 → CWE-328
    return hm.hexdigest()

# 8. Timing-attack prone comparison
def timing_attack(a, b):
    if a == b:                         # CWE-208
        return True
    return False

if __name__ == "__main__":
    data = b"attack at dawn"
    key  = b"0123456789abcdef"
    iv   = b"abcdef0123456789"

    print("Hashes:", weak_hashing(data))
    print("Secrets:", hardcoded_secrets())
    print("Randoms:", insecure_randomness())
    print("ECB:", ecb_encryption(data, key))
    print("TLS contexts:", tls_issues())
    padding_oracle(data, key, iv)
    print("HMAC:", hmac_default_md5(data, key))
    print("Compare:", timing_attack("password123", "password123"))
