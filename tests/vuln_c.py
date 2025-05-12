# vuln_c.py
import sqlite3
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA1, SHA256, HMAC
from Crypto.Random import get_random_bytes

# 1. Hardcoded secret
JWT_SECRET = "jwt-secret-unsafe"

# 2. Insecure storage
conn = sqlite3.connect("unsafe.db")
c = conn.cursor()
c.execute("CREATE TABLE IF NOT EXISTS creds (secret TEXT)")
c.execute("INSERT INTO creds VALUES (?)", (JWT_SECRET,))
conn.commit()

# 3. AEAD misuse: GCM but decrypts before verifying tag
def decrypt_gcm_bad(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    pt = cipher.decrypt(ciphertext)
    # only verifies after using plaintext
    try:
        cipher.verify(b"\x00"*16)
    except:
        pass
    return pt

# 4. Custom “handshake”
def silly_handshake(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# 5. Hybrid protocol error: splits IV into two halves
rsa_key = RSA.generate(1024)
def ugly_hybrid(data):
    sym = b"S"*16
    iv = get_random_bytes(16)
    part1, part2 = iv[:8], iv[8:]
    enc_iv = rsa_key.encrypt(part1, None)[0] + rsa_key.encrypt(part2, None)[0]
    cipher = AES.new(sym, AES.MODE_CBC, iv=iv)
    return enc_iv + cipher.encrypt(data)

# 6. Hard-coded plaintext PIN
PIN = "1234"

# 7. Weak hash MD5, missing salt
def pw_md5(pw):
    return hashlib.md5(pw.encode()).hexdigest()

# 8. No pepper

# 9. Insecure signature: SHA1
def sign1(msg):
    signer = PKCS1_v1_5.new(rsa_key)
    h = SHA1.new(msg)
    return signer.sign(h)

# 10. No signature verification at all
def verify1(msg, sig):
    # never even loads public key
    return True

# 11. Unsafe compare
def cmp(a, b):
    return a == b

# 12. ECB + DES
def multi_ecb(data):
    k1 = b"C"*16
    k2 = b"8byteKY"
    a = AES.new(k1, AES.MODE_ECB).encrypt(data.ljust(16, b"\0"))
    d = DES.new(k2, DES.MODE_ECB).encrypt(data.ljust(8, b"\0"))
    return a + d

# 13. XOR cipher with predictable “IV”
def xor_with_iv(data):
    iv = b"\x00"*4
    key = b"KEY!"
    return bytes((b ^ iv[i % len(iv)] ^ key[i % len(key)]) for i, b in enumerate(data))
