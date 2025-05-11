# tests/test_plaintext_passwords.py

import os
import tempfile
import re
import pytest
from covsaw.scripts.passwords.detect_plaintext_passwords import PlaintextPasswordChecker
import ast

def _run_checker(code: str):
    # write code to temp file, parse AST, collect issues
    fd, path = tempfile.mkstemp(suffix=".py")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        f.write(code)
    checker = PlaintextPasswordChecker(path)
    tree = ast.parse(code, filename=path)
    checker.visit(tree)
    os.remove(path)
    return checker.issues

def test_literal_assignment_detected():
    code = "password = 'supersecret'"
    issues = _run_checker(code)
    assert len(issues) == 1
    assert re.search(r"variable 'password' assigned a hard-coded string literal", issues[0], re.IGNORECASE)

def test_fstring_assignment_detected():
    code = "pwd = f'user_{user_id}_pwd'"
    issues = _run_checker(code)
    assert len(issues) == 1
    assert "assigned an f-string containing a literal" in issues[0]

def test_print_password_detected():
    code = """
pwd = get_password()
print(pwd)
"""
    issues = _run_checker(code)
    # should flag the print of a variable matching 'pwd'
    assert any("passed to print" in issue.lower() for issue in issues)

def test_write_password_detected():
    code = """
pw = load_pw()
f.write(pw)
"""
    issues = _run_checker(code)
    assert any("passed to write" in issue.lower() for issue in issues)

def test_nonpassword_var_no_issue():
    code = "username = 'alice'\nprint(username)"
    issues = _run_checker(code)
    assert issues == []
