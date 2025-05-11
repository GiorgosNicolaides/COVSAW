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

class InsecureSignatureAlgoChecker(ast.NodeVisitor):
    """
    Base class for signature-related AST checkers.
    """
    NAME = 'signature-checker'
    CWECODE = 'CWE-327'
    SEVERITY = 'HIGH'

    def __init__(self, path, config=None):
        self.path = path
        self.issues = []
        self.config = config or DEFAULT_CONFIG
        # Map alias name -> original qualified name
        self.aliases = {}

    def report(self, lineno, message, cwe=None, severity=None):
        cwe = cwe or self.CWECODE
        severity = severity or self.SEVERITY
        self.issues.append((lineno, f"{message} [CWE {cwe}, Severity {severity}]") )

    def analyze(self):
        with open(self.path, encoding='utf-8') as f:
            source = f.read()
        tree = ast.parse(source, filename=self.path)
        self.visit(tree)
        return self.issues

class InsecureSignatureAlgoChecker(SignatureChecker):
    """
    Detect use of weak or deprecated hash functions for signatures.
    """
    NAME = 'insecure-signature-algo'

    def __init__(self, path, config=None):
        super().__init__(path, config)
        # Load user config file if present
        cfg_path = os.getenv('SIG_CHECK_CONFIG')
        if cfg_path and os.path.isfile(cfg_path):
            try:
                user_cfg = toml.load(cfg_path)
                self.config.update(user_cfg)
            except Exception:
                pass
        # Normalize insecure names to lower-case set
        self.insecure = {h.lower() for h in self.config.get('insecure_hashes', [])}

    def visit_Import(self, node):
        # Record aliases: import hashlib as hf
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            if name in ('hashlib', 'Crypto.Hash.MD5', 'Crypto.Hash.SHA1'):
                self.aliases[asname] = name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        # from hashlib import md5 as weak
        module = node.module or ''
        for alias in node.names:
            full = f"{module}.{alias.name}" if module else alias.name
            if alias.name.lower() in self.insecure or module.lower().endswith(tuple(self.insecure)):
                self.aliases[alias.asname or alias.name] = full
        self.generic_visit(node)

    def visit_Call(self, node):
        # Determine the qualified name of the function called
        func = node.func
        qualname = ''
        if isinstance(func, ast.Attribute):
            # e.g. hashlib.md5 or Crypto.Hash.MD5.new
            if isinstance(func.value, ast.Name) and func.value.id in self.aliases:
                base = self.aliases[func.value.id]
            else:
                parts = []
                cur = func
                while isinstance(cur, ast.Attribute):
                    parts.insert(0, cur.attr)
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    parts.insert(0, cur.id)
                base = '.'.join(parts)
            qualname = base.lower()
        elif isinstance(func, ast.Name):
            name = func.id
            qualname = (self.aliases.get(name, name)).lower()

        # Case 1: direct insecure calls: hashlib.md5(), md5(), Crypto.Hash.MD5.new()
        for alg in self.insecure:
            if qualname.endswith(f".{alg}") or qualname == alg:
                self.report(node.lineno, f"Use of insecure hash algorithm: {alg}")
                return

        # Case 2: hashlib.new('md5', ...)
        if qualname.endswith('.new') and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if first.value.lower() in self.insecure:
                    self.report(node.lineno, f"Use of insecure hash algorithm via hashlib.new: {first.value}")
                    return

        self.generic_visit(node)
