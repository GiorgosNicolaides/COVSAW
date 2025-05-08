import os
import sys
import tempfile
import pytest
import textwrap

# Ensure key-management modules are importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detect_hardcoded_secrets import HardcodedSecretsChecker 
from detect_insecure_storage import InsecureStorageChecker
import key_management_runner as runner


def run_checker(code: str, CheckerClass):
    # Strip any leading indentation so AST.parse can succeed
    code = textwrap.dedent(code).lstrip()
    fd, path = tempfile.mkstemp(suffix=".py")
    os.close(fd)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(code)
    checker = CheckerClass(path)
    issues = checker.analyze()
    os.remove(path)
    return issues

# --- Hardcoded Secrets Tests ---

def test_literal_secret_flagged():
    code = 'password = "hunter2"'
    issues = run_checker(code, HardcodedSecretsChecker)
    assert any("password assigned hardcoded secret" in msg.lower() for _, msg in issues)


def test_hex_blob_flagged():
    code = 'secret = "abcdef0123456789abcdef0123456789"'
    issues = run_checker(code, HardcodedSecretsChecker)
    assert any("secret assigned hardcoded secret" in msg.lower() for _, msg in issues)


def test_fstring_secret_flagged():
    code = '''
suffix = "XYZ"
token = f"AAAAAAAA{suffix}"
'''
    issues = run_checker(code, HardcodedSecretsChecker)
    assert any("f-string contains literal with secret-like content" in msg.lower() for _, msg in issues)


def test_function_default_secret_flagged():
    code = '''
def foo(api_key="defaultsecret"):
    pass
'''
    issues = run_checker(code, HardcodedSecretsChecker)
    assert any("parameter 'api_key' has hardcoded default secret" in msg.lower() for _, msg in issues)


def test_getenv_fallback_flagged():
    code = '''
import os
val = os.getenv("API_KEY", "hardcoded")
'''
    issues = run_checker(code, HardcodedSecretsChecker)
    assert any("os.getenv fallback provides hardcoded default" in msg.lower() for _, msg in issues)

# --- Insecure Storage Tests ---

def test_print_secret_flagged():
    code = '''
password = "s"
print(password)
'''
    issues = run_checker(code, InsecureStorageChecker)
    assert any("printing sensitive variable 'password'" in msg.lower() for _, msg in issues)


def test_logger_secret_flagged():
    code = '''
import logging
secret = "s"
logger.info(secret)
'''
    issues = run_checker(code, InsecureStorageChecker)
    assert any("logging sensitive variable 'secret'" in msg.lower() for _, msg in issues)


def test_with_open_write_flagged():
    code = '''
token = "s"
with open("file","w") as f:
    f.write(token)
'''
    issues = run_checker(code, InsecureStorageChecker)
    assert any("writing sensitive variable 'token' to file" in msg.lower() for _, msg in issues)


def test_open_write_flagged():
    code = '''
key = "s"
open("file","w").write(key)
'''
    issues = run_checker(code, InsecureStorageChecker)
    assert any("writing sensitive variable 'key' with open() call" in msg.lower() for _, msg in issues)


def test_subprocess_secret_flagged():
    code = '''
import subprocess
token = "s"
subprocess.run([token])
'''
    issues = run_checker(code, InsecureStorageChecker)
    assert any("passing sensitive variable 'token' to system call" in msg.lower() for _, msg in issues)


def test_pyperclip_copy_flagged():
    code = '''
import pyperclip
secret = "s"
pyperclip.copy(secret)
'''
    issues = run_checker(code, InsecureStorageChecker)
    assert any("copying sensitive variable 'secret' to clipboard" in msg.lower() for _, msg in issues)


def test_env_assign_flagged():
    code = '''
import os
key = "s"
os.environ['KEY'] = key
'''
    issues = run_checker(code, InsecureStorageChecker)
    assert any("storing sensitive variable 'key' in environment" in msg.lower() for _, msg in issues)

# --- Runner Tests ---

def test_discover_checkers():
    classes = runner.discover_checkers()
    names = [cls.__name__ for cls in classes]
    assert 'HardcodedSecretsChecker' in names
    assert 'InsecureStorageChecker' in names


def test_scan_py_files(tmp_path):
    f1 = tmp_path / "a.py"
    f1.write_text("# test")
    f2 = tmp_path / "b.txt"
    f2.write_text("# test")
    found = list(runner.scan_py_files(str(tmp_path)))
    assert str(f1) in found and all(f.endswith('.py') for f in found)


def test_analyze_file_reports(tmp_path):
    code = 'password = "hunter2"'
    file = tmp_path / "test.py"
    file.write_text(code)
    classes = runner.discover_checkers()
    issues = runner.analyze_file(str(file), classes)
    assert issues, "Runner should report issues for hardcoded secret"


def test_analyze_file_no_issues(tmp_path):
    code = 'a = 1'
    file = tmp_path / "test.py"
    file.write_text(code)
    classes = runner.discover_checkers()
    issues = runner.analyze_file(str(file), classes)
    assert issues == []
