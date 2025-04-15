import subprocess

def test_plaintext_password():
    # Run COVSAW's password checker on a sample file with plaintext password
    result = subprocess.run(['python', 'cli.py', '--passwords', 'tests/test_samples/insecure_passwords.py'], capture_output=True, text=True)
    
    # Check if the output includes the correct CWE ID (CWE-257 for plaintext storage)
    assert "CWE-257" in result.stdout
    assert "plaintext password" in result.stdout

def test_weak_hash():
    # Run the weak hash checker on a sample file
    result = subprocess.run(['python', 'cli.py', '--passwords', 'tests/test_samples/weak_hashes.py'], capture_output=True, text=True)
    
    # Check if MD5 is flagged as weak
    assert "CWE-328" in result.stdout
    assert "MD5" in result.stdout

def test_missing_salt():
    # Run the missing salt checker on a sample file
    result = subprocess.run(['python', 'cli.py', '--passwords', 'tests/test_samples/missing_salt.py'], capture_output=True, text=True)
    
    # Check if missing salt is flagged
    assert "CWE-759" in result.stdout
    assert "Missing salt" in result.stdout
