import os
import importlib.util
import pytest
from pathlib import Path

def load_module(path):
    spec = importlib.util.spec_from_file_location(Path(path).stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

@pytest.fixture(scope='session')
def sym_dir():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# -------- ECB and DES Checker --------

def test_ecb_des_flagged(tmp_path, sym_dir):
    module = load_module(os.path.join(sym_dir, 'detect_ecb_des.py'))
    Checker = module.ECBAndDESChecker
    code = (
        "from Crypto.Cipher import DES\n"
        "cipher = DES.new(b'12345678', DES.MODE_ECB)\n"
    )
    path = tmp_path / 'ecb_des.py'
    path.write_text(code)

    issues = Checker(str(path)).analyze()
    assert issues, "Expected ECB mode on DES to be flagged"
    assert any('ecb' in msg.lower() and 'des' in msg.lower() for _, msg in issues)

def test_ecb_des_not_flagged_with_strong_mode(tmp_path, sym_dir):
    module = load_module(os.path.join(sym_dir, 'detect_ecb_des.py'))
    Checker = module.ECBAndDESChecker
    code = (
        "from Crypto.Cipher import DES\n"
        "cipher = DES.new(b'12345678', DES.MODE_CBC, iv=b'\\x00'*8)\n"
    )
    path = tmp_path / 'cbc_des.py'
    path.write_text(code)

    issues = Checker(str(path)).analyze()
    assert not issues, f"No ECB issues expected, got {issues}"

# -------- Hardcoded Key Checker --------

def test_hardcoded_key_flagged(tmp_path, sym_dir):
    module = load_module(os.path.join(sym_dir, 'detect_hardcoded_keys.py'))
    Checker = module.HardcodedKeyChecker
    code = "key = 'A1B2C3D4E5F6A7B8'\n"
    path = tmp_path / 'hardcoded.py'
    path.write_text(code)

    issues = Checker(str(path)).analyze()
    assert issues, "Expected hardcoded key to be flagged"
    assert any('hardcoded' in msg.lower() for _, msg in issues)

def test_hardcoded_key_not_flagged_for_var(tmp_path, sym_dir):
    module = load_module(os.path.join(sym_dir, 'detect_hardcoded_keys.py'))
    Checker = module.HardcodedKeyChecker
    code = "other = 'A1B2C3D4E5F6G7H8'\n"
    path = tmp_path / 'other.py'
    path.write_text(code)

    issues = Checker(str(path)).analyze()
    assert not issues

# -------- Weak IV Checker --------

def test_weak_iv_keyword(tmp_path, sym_dir):
    module = load_module(os.path.join(sym_dir, 'detect_weak_iv.py'))
    Checker = module.WeakIVChecker
    code = "cipher.encrypt(data, iv=b'\\x00'*16)\n"
    path = tmp_path / 'weak_iv.py'
    path.write_text(code)

    issues = Checker(str(path)).analyze()
    assert issues, "Expected weak IV via keyword to be flagged"

def test_weak_iv_positional(tmp_path, sym_dir):
    module = load_module(os.path.join(sym_dir, 'detect_weak_iv.py'))
    Checker = module.WeakIVChecker
    code = "cipher.encrypt(data, key, b'\\x00'*16)\n"
    path = tmp_path / 'weak_iv_pos.py'
    path.write_text(code)

    issues = Checker(str(path)).analyze()
    assert issues, "Expected weak IV via positional to be flagged"

# -------- XOR Encryption Checker --------

def test_xor_encryption_flagged(tmp_path, sym_dir):
    module = load_module(os.path.join(sym_dir, 'detect_xor_encryption.py'))
    Checker = module.XORBasedEncryptionChecker
    code = "out = a ^ b ^ c\n"
    path = tmp_path / 'xor.py'
    path.write_text(code)

    issues = Checker(str(path)).analyze()
    assert issues, "Expected XOR operations to be flagged"
    assert any('xor' in msg.lower() for _, msg in issues)

def test_xor_encryption_not_flagged(tmp_path, sym_dir):
    module = load_module(os.path.join(sym_dir, 'detect_xor_encryption.py'))
    Checker = module.XORBasedEncryptionChecker
    code = "out = a + b\n"
    path = tmp_path / 'add.py'
    path.write_text(code)

    issues = Checker(str(path)).analyze()
    assert not issues
