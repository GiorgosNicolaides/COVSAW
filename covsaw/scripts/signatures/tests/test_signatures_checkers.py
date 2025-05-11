import ast
import os
import toml

# Default configuration for insecure hash algorithms
DEFAULT_CONFIG = {
    'insecure_hashes': [
        'md5',
        'sha1',
        'sha-1',
        'ripemd160',
    ],
}

class SignatureChecker(ast.NodeVisitor):
    """
    Base class for signature-related AST checkers.
    """
    NAME = 'signature-checker'
    CWECODE = 'CWE-327'
    SEVERITY = 'HIGH'

    def __init__(self, file_path, config=None):
        self.file_path = file_path
        self.issues = []
        self.config = config or DEFAULT_CONFIG
        # Map alias names if extended in future
        self.aliases = {}

    def report(self, lineno, message, cwe=None, severity=None):
        cwe = cwe or self.CWECODE
        severity = severity or self.SEVERITY
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]") )

    def analyze(self):
        with open(self.file_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=self.file_path)
        self.visit(tree)
        return self.issues

class InsecureSignatureAlgoChecker(SignatureChecker):
    """
    Detect use of weak or deprecated hash functions for signatures.
    """
    NAME = 'insecure-signature-algo'

    def __init__(self, file_path, config=None):
        super().__init__(file_path, config)
        cfg_path = os.getenv('SIG_CHECK_CONFIG')
        if cfg_path and os.path.isfile(cfg_path):
            try:
                user_cfg = toml.load(cfg_path)
                self.config.update(user_cfg)
            except Exception:
                pass
        # Normalize to lower-case set
        self.insecure = {h.lower() for h in self.config.get('insecure_hashes', [])}

    def visit_Call(self, node):
        func = node.func
        qualname = ''
        if isinstance(func, ast.Attribute):
            parts = []
            cur = func
            while isinstance(cur, ast.Attribute):
                parts.insert(0, cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.insert(0, cur.id)
            qualname = '.'.join(parts).lower()
        elif isinstance(func, ast.Name):
            qualname = func.id.lower()

        # Direct insecure algos: hashlib.md5, md5
        for alg in self.insecure:
            if qualname.endswith(f".{alg}") or qualname == alg:
                self.report(node.lineno, f"Use of insecure hash algorithm: {alg}")
                return

        # hashlib.new('md5', ...)
        if qualname.endswith('.new') and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if first.value.lower() in self.insecure:
                    self.report(
                        node.lineno,
                        f"Use of insecure hash algorithm via hashlib.new: {first.value}"
                    )
                    return

        self.generic_visit(node)
