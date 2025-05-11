# scripts/passwords/tests/test_missing_salt_or_kdf.py

import os
import tempfile
import pytest
from scripts.passwords.detect_missing_salt_or_kdf import MissingSaltOrKDFChecker

def _run_checker(code: str):
    # write code to a temp file and run the checker
    fd, path = tempfile.mkstemp(suffix=".py")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        f.write(code)
    checker = MissingSaltOrKDFChecker(path)
    issues = checker.analyze()
    os.remove(path)
    return issues

def test_hashlib_without_salt_or_pepper():
    code = """
import hashlib

# direct use of sha256 on plaintext
hashlib.sha256(b"password").hexdigest()
"""
    issues = _run_checker(code)
    assert len(issues) == 1
    lineno, msg = issues[0]
    # adjusted to line 5 where hashlib.sha256(...) actually appears
    assert lineno == 5
    assert "salt or pepper" in msg.lower()
    assert "cwe-759" in msg.lower()

def test_pbkdf2_hmac_missing_salt():
    code = """
import hashlib

# pbkdf2_hmac with only 2 args → missing salt
hashlib.pbkdf2_hmac("sha256", b"password")
"""
    issues = _run_checker(code)
    # now reports both missing-salt and missing-pepper
    assert len(issues) == 2
    lineno, msg = issues[0]
    # call is on line 5
    assert lineno == 5
    assert "kdf 'pbkdf2_hmac' used without salt" in msg.lower()

def test_with_salt_variable_no_issue():
    code = """
import hashlib
import os

# proper use: generate salt and mix in
salt = os.urandom(16)
hashlib.sha256(b\"password\" + salt).hexdigest()
"""
    issues = _run_checker(code)
    assert issues == []  # no missing‐salt issue

def test_with_pepper_variable_no_issue():
    code = """
import hashlib

pepper = "static_secret_value"
hashlib.sha256(b"password" + pepper.encode()).hexdigest()
"""
    issues = _run_checker(code)
    assert issues == []
