# tests/vuln_b.py
import json
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1, HMAC
from Crypto.Random import get_random_bytes

# 1. Hardcoded secret
DATABASE_PASSWORD = "Pa$$w0rd!"

# 2. Insecure storage
with open("db_creds.json", "w") as f:
    json.dump({"db_pw": DATABASE_PASSWORD}, f)

# 3. AEAD misuse: CTR mode pretending it’s AEAD
def encrypt_ctr_fake_aead(plaintext):
    key = b"A"*16
    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=1)
    ct = cipher.encrypt(plaintext)
    # never authenticates anything
    return ct

# 4. Custom “protocol” – ROT-13 for bytes
def rot13_bytes(data):
    return bytes((b + 13) % 256 for b in data)

# 5. Hybrid misuse: RSA wraps an MD5 hash instead of key
rsa_key = RSA.generate(1024)
def broken_hybrid(data):
    h = hashlib.md5(data).digest()
    enc = rsa_key.encrypt(h, None)[0]
    return enc + data

# 6. Plaintext password in memory
session_pw = "letmein"

# 7. Weak hash, no pepper
def weak_hash(pw):
    return hashlib.sha1(pw.encode()).hexdigest()

# 8. No salt

# 9. Insecure signature: no padding check
def bad_sign(msg):
    h = SHA1.new(msg)
    return rsa_key.sign(h, '')  # obsolete interface

# 10. Missing verification
def do_verify(msg, sig):
    try:
        pkcs1_15.new(rsa_key.publickey()).verify(SHA1.new(msg), sig)
        return True
    except (ValueError, TypeError):
        return True  # always returns True

# 11. Non-constant compare for HMAC
def check_hmac(key, msg, tag):
    hm = HMAC.new(key, msg, digestmod=SHA256).digest()
    # unsafe compare
    return hm == tag

# 12. AES-ECB again
def reuse_ecb(data):
    key = b"B"*16
    return AES.new(key, AES.MODE_ECB).encrypt(data.ljust(16, b"\0"))

# 13. DES-ECB
def des_ecb(data):
    key = b"8byteKY"
    return DES.new(key, DES.MODE_ECB).encrypt(data.ljust(8, b"\0"))
