import sys
import os
import tempfile
import pytest

# Ensure the checker modules in this directory are importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detect_aead_misuse import AEADMisuseChecker
from detect_custom_crypto_protocols import CustomCryptoProtocolChecker
from detect_hybrid_crypto_misuse import HybridCryptoMisuseChecker


def run_checker(code: str, CheckerClass):
    # write to temp file and run checker
    fd, path = tempfile.mkstemp(suffix=".py")
    os.close(fd)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(code)
    checker = CheckerClass(path)
    issues = checker.analyze()
    os.remove(path)
    return issues

# --- AEAD Misuse Tests ---

def test_aead_constant_nonce_flagged():
    code = '''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=128)
aead = AESGCM(key)
aead.encrypt(b"AAAAAAAAAAAA", b"secret", b"header")
'''
    issues = run_checker(code, AEADMisuseChecker)
    assert any("constant nonce" in msg.lower() for _, msg in issues)


def test_aead_missing_aad_flagged():
    code = '''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
key = AESGCM.generate_key(bit_length=128)
aead = AESGCM(key)
aead.encrypt(os.urandom(12), b"secret")
'''
    issues = run_checker(code, AEADMisuseChecker)
    assert any("omits associated_data" in msg.lower() for _, msg in issues)


def test_aead_missing_nonce_flagged():
    code = '''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=128)
aead = AESGCM(key)
aead.encrypt()
'''
    issues = run_checker(code, AEADMisuseChecker)
    assert any("called without a nonce" in msg.lower() for _, msg in issues)

# --- Custom Crypto Protocol Tests ---
# Problematic unit test MUST FIX 
"""
def test_custom_ecb_mode_flagged():
    code = '''
from Crypto.Cipher import AES
key = b"0"*16
cipher = AES.new(key, AES.MODE_ECB)
'''
    issues = run_checker(code, CustomCryptoProtocolChecker)
    assert any("insecure mode ecb" in msg.lower() for _, msg in issues)

"""

def test_custom_cbc_no_hmac_flagged():
    code = '''
from Crypto.Cipher import AES
key = b"0"*16
cipher = AES.new(key, AES.MODE_CBC)
'''
    issues = run_checker(code, CustomCryptoProtocolChecker)
    assert any("without authentication" in msg.lower() for _, msg in issues)


def test_custom_cbc_with_hmac_no_issue():
    code = '''
from Crypto.Cipher import AES
import hmac
from Crypto.Hash import SHA256
key = b"0"*16
cipher = AES.new(key, AES.MODE_CBC)
h = hmac.new(key, digestmod=SHA256)
'''
    issues = run_checker(code, CustomCryptoProtocolChecker)
    assert issues == []

# --- Hybrid Crypto Misuse Tests ---

def test_hybrid_rsa_no_padding_flagged():
    code = '''
plaintext = b"secret"
ciphertext = rsa_pub.encrypt(plaintext)
'''
    issues = run_checker(code, HybridCryptoMisuseChecker)
    assert any("missing padding" in msg.lower() for _, msg in issues)


def test_hybrid_rsa_insecure_padding_flagged():
    code = '''
from cryptography.hazmat.primitives.asymmetric import padding
ciphertext = rsa_pub.encrypt(b"secret", padding.PKCS1v15())
'''
    issues = run_checker(code, HybridCryptoMisuseChecker)
    assert any("insecure padding" in msg.lower() for _, msg in issues)


def test_hybrid_rsa_without_sym_layer_flagged():
    code = '''
from cryptography.hazmat.primitives.asymmetric import padding
ciphertext = rsa_pub.encrypt(b"secret", padding.OAEP())
'''
    issues = run_checker(code, HybridCryptoMisuseChecker)
    assert any("without a symmetric encryption layer" in msg.lower() for _, msg in issues)


def test_hybrid_correct_hybrid_no_issue():
    code = '''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
import os
# symmetric layer
key = AESGCM.generate_key(bit_length=128)
aead = AESGCM(key)
ct = aead.encrypt(os.urandom(12), b"secret", b"aad")
# hybrid encryption
ciphertext = rsa_pub.encrypt(ct, padding.OAEP())
'''
    issues = run_checker(code, HybridCryptoMisuseChecker)
    assert issues == []
