import ast
import os
import toml

# Default configuration for weak IV detection
DEFAULT_CONFIG = {
    'iv_arg_names': ['iv', 'nonce'],
}

class SymmetricChecker(ast.NodeVisitor):
    """
    Base class for symmetric encryption-related AST checkers.
    """
    NAME = 'symmetric-checker'
    CWECODE = None
    SEVERITY = 'MEDIUM'

    def __init__(self, file_path, config=None):
        self.file_path = file_path
        self.issues = []
        # Make a fresh copy of default config
        self.config = config or DEFAULT_CONFIG.copy()

    def report(self, lineno, message, cwe=None, severity=None):
        cwe = cwe or self.CWECODE
        severity = severity or self.SEVERITY
        self.issues.append((lineno, f"{message} [CWE {cwe}, Severity {severity}]"))

    def analyze(self):
        # Load user configuration if present
        cfg_path = os.getenv('SYM_CHECK_CONFIG')
        if cfg_path and os.path.isfile(cfg_path):
            try:
                user_cfg = toml.load(cfg_path)
                self.config.update(user_cfg)
            except Exception:
                pass

        with open(self.file_path, encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=self.file_path)
        self.visit(tree)
        return self.issues

class WeakIVChecker(SymmetricChecker):
    """
    Detect use of hardcoded or static IVs (e.g., all-zero IVs or repeated zero).
    """
    NAME = 'weak-iv'
    CWECODE = 'CWE-330'
    SEVERITY = 'HIGH'

    def __init__(self, file_path, config=None):
        super().__init__(file_path, config)
        # Case-insensitive set of argument names to treat as IVs
        self.iv_names = {n.lower() for n in self.config.get('iv_arg_names', [])}

    def _is_zero_bytes(self, node):
        # Matches literal bytes/bytearray with all zeros
        if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, bytearray)):
            return all(b == 0 for b in node.value)
        return False

    def _is_repeated_zero_binop(self, node):
        # Matches pattern: b'\x00' * N (N > 0)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            left, right = node.left, node.right
            if (
                isinstance(left, ast.Constant)
                and isinstance(left.value, (bytes, bytearray))
                and len(left.value) == 1
                and left.value[0] == 0
                and isinstance(right, ast.Constant)
                and isinstance(right.value, int)
                and right.value > 0
            ):
                return True
        return False

    def visit_Call(self, node):
        # Check keyword args named 'iv' or 'nonce'
        for kw in node.keywords:
            if kw.arg and kw.arg.lower() in self.iv_names:
                iv_node = kw.value
                if self._is_zero_bytes(iv_node) or self._is_repeated_zero_binop(iv_node):
                    self.report(
                        node.lineno,
                        f"Use of weak static IV in argument '{kw.arg}'"
                    )
        # Check positional: IV often passed as 2nd or 3rd positional arg
        for idx in (1, 2):
            if len(node.args) > idx:
                iv_node = node.args[idx]
                if self._is_zero_bytes(iv_node) or self._is_repeated_zero_binop(iv_node):
                    self.report(
                        node.lineno,
                        f"Use of weak static IV in positional argument #{idx+1}"
                    )
        self.generic_visit(node)
