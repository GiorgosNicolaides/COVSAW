import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import bytes_to_long

# 1. Hardcoded RSA Private Key (CWE-321)
HARD_CODED_PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA7...
-----END RSA PRIVATE KEY-----
"""

# 2. Hardcoded RSA Public Key (CWE-321)
HARD_CODED_PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA...
-----END PUBLIC KEY-----
"""

# 3. Weak RSA Key Length (CWE-326) - Using a 256-bit key (too small)
weak_key = RSA.generate(256)  # Extremely weak key size

# 4. Writing RSA Key to a File Without Hashing (Plaintext Key Storage) (CWE-312)
with open("rsa_key.pem", "w") as key_file:
    key_file.write(weak_key.export_key().decode())  # Storing key in plaintext

# 5. Weak PRNG Usage (CWE-338)
random.seed(42)  # Predictable PRNG
weak_random_key = random.getrandbits(1024)  # Generating a key with weak randomness

# 6. Key Reuse (CWE-322) - Using the same RSA key for encryption and signing
key_reuse = RSA.generate(1024)  # Not recommended for security
cipher = PKCS1_OAEP.new(key_reuse)
signature = pow(bytes_to_long(b"data"), key_reuse.d, key_reuse.n)  # Misuse of RSA

# 7. Weak Public Exponent (e=3) (CWE-1240) - Vulnerable to attacks
weak_exponent_key = RSA.construct((key_reuse.n, 3, key_reuse.d))  # Weak exponent

# 8. Missing Padding in Encryption (CWE-780) - Using raw RSA encryption (NO padding)
raw_encryption = pow(bytes_to_long(b"Secret"), weak_exponent_key.e, weak_exponent_key.n)

print("Vulnerable RSA operations executed. This file is for testing purposes only.")
