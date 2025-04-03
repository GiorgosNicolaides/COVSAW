import hashlib

# Insecure algorithms
hash1 = hashlib.md5("mypassword".encode())  #  Insecure MD5
hash2 = hashlib.sha1("mypassword".encode())  #  Insecure SHA-1

# Secure algorithms
hash3 = hashlib.sha256("mypassword".encode())  # Safe SHA-256
hash4 = hashlib.sha512("mypassword".encode())  # Safe SHA-512
hash5 = hashlib.sha3_256("mypassword".encode())  # Safe SHA3-256
hash6 = hashlib.sha3_512("mypassword".encode())  # Safe SHA3-512

# Custom hashing
def custom_hash(data):
    return "".join(chr(ord(c) ^ 0x55) for c in data)  # XOR-based hash (insecure)
