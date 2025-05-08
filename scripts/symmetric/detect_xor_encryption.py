import ast
import os
import toml

# Default configuration for XOR-detection
DEFAULT_CONFIG = {
    'min_xor_ops': 1,  # minimum number of XOR operations to flag
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
        self.config = config or DEFAULT_CONFIG.copy()
        # Load user config if provided
        cfg_path = os.getenv('SYM_CHECK_CONFIG')
        if cfg_path and os.path.isfile(cfg_path):
            try:
                user_cfg = toml.load(cfg_path)
                self.config.update(user_cfg)
            except Exception:
                pass

    def report(self, lineno, message, cwe=None, severity=None):
        cwe = cwe or self.CWECODE
        severity = severity or self.SEVERITY
        self.issues.append((lineno, f"{message} [CWE {cwe}, Severity {severity}]"))

    def analyze(self):
        with open(self.file_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=self.file_path)
        self.visit(tree)
        return self.issues

class XORBasedEncryptionChecker(SymmetricChecker):
    """
    Detect potential insecure XOR-based custom encryption patterns.
    """
    NAME = 'xor-encryption'
    CWECODE = 'CWE-327'
    SEVERITY = 'HIGH'

    def __init__(self, file_path, config=None):
        super().__init__(file_path, config)
        self.min_ops = int(self.config.get('min_xor_ops', 1))

    def visit_BinOp(self, node):
        # Detect binary XOR operations (a ^ b)
        count = self._count_xor(node)
        if count >= self.min_ops:
            self.report(
                node.lineno,
                f"Detected {count} XOR operation{'s' if count>1 else ''}; possible insecure custom encryption",
                cwe=self.CWECODE,
                severity=self.SEVERITY
            )
        self.generic_visit(node)

    def _count_xor(self, node):
        # Recursively count BitXor operations
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor):
            return 1 + self._count_xor(node.left) + self._count_xor(node.right)
        return 0
