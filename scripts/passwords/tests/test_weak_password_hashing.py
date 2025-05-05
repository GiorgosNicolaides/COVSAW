# tests/test_weak_password_hashing.py

import os
import tempfile
import pytest
from scripts.passwords.detect_weak_password_hashing import WeakPasswordHashingChecker

def _run_checker(code: str):
    # write code, run analyze(), return issues
    fd, path = tempfile.mkstemp(suffix=".py")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        f.write(code)
    checker = WeakPasswordHashingChecker(path)
    issues = checker.analyze()
    os.remove(path)
    return issues

def test_md5_usage_flagged():
    code = """
import hashlib
hashlib.md5(b"secret").hexdigest()
"""
    issues = _run_checker(code)
    assert len(issues) == 1
    lineno, msg = issues[0]
    assert lineno == 3
    assert "weak hash function used" in msg.lower()
    assert "md5" in msg.lower()

def test_sha1_direct_import_flagged():
    code = """
from hashlib import sha1
sha1(b"secret")
"""
    issues = _run_checker(code)
    assert len(issues) == 1
    _, msg = issues[0]
    assert "weak hash function used" in msg.lower()
    assert "sha1" in msg.lower()

def test_constant_time_compare_low_severity():
    code = """
import hmac
hmac.compare_digest(a, b)
"""
    issues = _run_checker(code)
    # this is good practice => low severity but still reported
    assert any("good practice" in msg.lower() for _, msg in issues)
    # no md5/sha1 in that list
    assert all("weak hash" not in msg.lower() for _, msg in issues)

def test_direct_equality_flagged_medium():
    code = """
password = get_pw()
if password == user_input:
    pass
"""
    issues = _run_checker(code)
    # expecting a medium‐severity direct comparison warning
    assert any("direct comparison" in msg.lower() and "compare_digest" in msg.lower() for _, msg in issues)

def test_no_weak_hash_no_issue():
    code = """
import hashlib
hashlib.sha256(b"secret")
"""
    issues = _run_checker(code)
    # sha256 is strong => no weak‐hash warnings, though compare_digest is not used
    assert not any("weak hash" in msg.lower() for _, msg in issues)
