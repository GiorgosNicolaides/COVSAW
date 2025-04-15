# Using MD5 to hash passwords
import hashlib
password = "password123"
hashed = hashlib.md5(password.encode()).hexdigest()
