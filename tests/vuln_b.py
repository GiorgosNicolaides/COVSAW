# vuln_b.py
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

# 13. DES-ECB# tests/vuln_b_fixed.py

import os
import json
import bcrypt
import hmac
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# 1. Load secret from environment (no hard-coding)
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
if not DATABASE_PASSWORD:
    raise RuntimeError("Please set DATABASE_PASSWORD in your environment")

# 2. Secure storage: if you must write creds to disk, encrypt or at least lock down perms
creds = {"db_pw": DATABASE_PASSWORD}
creds_path = "secure_db_creds.json"
with open(creds_path, "w") as f:
    json.dump(creds, f)
os.chmod(creds_path, 0o600)  # rw------- only

# 3. Proper AEAD: AES-GCM with random nonce and full tag verification
def encrypt_aead(plaintext: bytes, key: bytes):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ct, tag

def decrypt_aead(nonce: bytes, ct: bytes, tag: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

# 4. Remove custom “ROT-13” – rely on real ciphers above

# 5. Correct hybrid encryption: RSA-OAEP + AES-GCM
#    (generate a fresh symmetric key per message)
rsa_key = RSA.generate(2048)
def hybrid_encrypt(data: bytes):
    # 5.a Generate a one-time symmetric key
    sym_key = get_random_bytes(32)
    # 5.b Encrypt it with RSA-OAEP+SHA256
    oaep = PKCS1_OAEP.new(rsa_key.publickey(), hashAlgo=SHA256)
    enc_key = oaep.encrypt(sym_key)
    # 5.c Encrypt the data with AES-GCM
    nonce, ct, tag = encrypt_aead(data, sym_key)
    return enc_key, nonce, ct, tag

def hybrid_decrypt(enc_key: bytes, nonce: bytes, ct: bytes, tag: bytes):
    oaep = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    sym_key = oaep.decrypt(enc_key)
    return decrypt_aead(nonce, ct, tag, sym_key)

# 6–8. Secure password handling with bcrypt (built-in salt, plus optional pepper)
PEPPER = os.getenv("PASSWORD_PEPPER", "")
def hash_password(pw: str) -> bytes:
    salted = (pw + PEPPER).encode()
    return bcrypt.hashpw(salted, bcrypt.gensalt())

def verify_password(pw: str, stored_hash: bytes) -> bool:
    return bcrypt.checkpw((pw + PEPPER).encode(), stored_hash)

# 9–10. Secure signatures with RSA-PSS + SHA-256, and proper verification
def sign_message(msg: bytes) -> bytes:
    h = SHA256.new(msg)
    signer = pss.new(rsa_key)
    return signer.sign(h)

def verify_message(msg: bytes, signature: bytes) -> bool:
    h = SHA256.new(msg)
    verifier = pss.new(rsa_key.publickey())
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# 11. Constant-time comparisons
def safe_compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

# 12–13. **Removed** all ECB/DES usage in favor of AES-GCM above.
# If you need a simple wrapper:
def encrypt_symmetric(data: bytes, key: bytes):
    return encrypt_aead(data, key)

def decrypt_symmetric(nonce: bytes, ct: bytes, tag: bytes, key: bytes):
    return decrypt_aead(nonce, ct, tag, key)

def des_ecb(data):
    key = b"8byteKY"
    return DES.new(key, DES.MODE_ECB).encrypt(data.ljust(8, b"\0"))
