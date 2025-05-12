# vuln_a.py
import os
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1, SHA256
from Crypto.Random import get_random_bytes

# 1. Hardcoded secret
API_KEY = "SUPER_SECRET_API_KEY_12345"

# 2. Insecure storage (writing secret to plaintext file)
with open("secrets.txt", "w") as f:
    f.write(API_KEY)

# 3. AEAD misuse: GCM but never checks the tag
def encrypt_gcm_misuse(plaintext):
    key = b"0" * 32           # hardcoded weak key
    iv  = b"\x00" * 12        # weak IV
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct  # tag is discarded

# 4. Custom XOR “crypto”
def xor_encrypt(data: bytes):
    key = b"ABC"  # hardcoded key
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

# 5. Hybrid crypto misuse: encrypt symmetric key with RSA but no padding
rsa_key = RSA.generate(1024)
def hybrid_encrypt(data):
    sym_key = b"K" * 16  # hardcoded symmetric key
    # misuse: no OAEP or padding
    enc_key = rsa_key.encrypt(sym_key, None)[0]
    cipher = AES.new(sym_key, AES.MODE_CBC, iv=b"\x00"*16)
    return enc_key + cipher.encrypt(data)

# 6. Plain‐text password
PASSWORD = "hunter2"

# 7. Weak password hashing (MD5, no salt)
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

# 8. Missing salt or pepper on any hashing

# 9. Insecure signature algorithm: SHA1 with RSA
def sign_message(msg: bytes):
    h = SHA1.new(msg)
    sig = pkcs1_15.new(rsa_key).sign(h)
    return sig

# 10. Missing verification on signature
def verify_message(msg: bytes, sig: bytes):
    # completely skips checking, just returns True
    return True

# 11. Non-constant time comparison on HMAC
def bad_compare(a: bytes, b: bytes):
    return a == b

# 12. ECB mode usage
def encrypt_ecb(data):
    key = b"Y" * 16
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data.ljust(16, b"\0"))

# 13. DES usage
def encrypt_des(data):
    key = b"8byteKY"
    cipher = DES.new(key, DES.MODE_CBC, iv=b"\x00"*8)  # weak IV
    return cipher.encrypt(data.ljust(8, b"\0"))
