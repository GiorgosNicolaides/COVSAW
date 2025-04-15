import hashlib
password = "password123"
hashed = hashlib.sha1(password.encode()).hexdigest()  # Missing salt
