import os
import sys
import pytest

# Ensure runner can import checkers
HERE = os.path.dirname(__file__)
SYM_ROOT = os.path.abspath(os.path.join(HERE, '..'))
sys.path.insert(0, SYM_ROOT)

from symmetric_analysis_runner import main as runner_main

DUMMY_MODULE = os.path.join(SYM_ROOT, 'detect_dummy.py')

def setup_module(module):
    with open(DUMMY_MODULE, 'w') as f:
        f.write('''import ast
class DummyChecker:
    NAME = 'dummy'
    def __init__(self, path): pass
    def analyze(self): return [(1, 'issue')]
''')

def teardown_module(module):
    try:
        os.remove(DUMMY_MODULE)
    except OSError:
        pass

@pytest.fixture
def sample_file(tmp_path):
    p = tmp_path / 's.py'
    p.write_text('# sample')
    return str(p)

@pytest.mark.parametrize('fmt,expected', [
    ('text', 's.py:1: [dummy] issue'),
    ('json', '"message": "issue"')
])
def test_runner_outputs(fmt, expected, tmp_path, sample_file, capsys):
    old_argv = sys.argv
    sys.argv = ['symmetric_analysis_runner', '-f', fmt, str(tmp_path)]
    try:
        with pytest.raises(SystemExit) as exc:
            runner_main()
    finally:
        sys.argv = old_argv

    out = capsys.readouterr().out
    assert expected in out
    assert exc.value.code == 1
