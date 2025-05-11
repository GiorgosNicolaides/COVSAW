import ast
import os
import toml

# Default configuration for insecure block cipher modes and weak algorithms
DEFAULT_CONFIG = {
    'insecure_modes': ['MODE_ECB'],
    'weak_algorithms': ['DES', 'TripleDES'],
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
        self.config = config or DEFAULT_CONFIG
        self.aliases = {}  # alias name -> module or class

    def report(self, lineno, message, cwe=None, severity=None):
        cwe = cwe or self.CWECODE
        severity = severity or self.SEVERITY
        self.issues.append((lineno, f"{message} [CWE {cwe}, Severity {severity}]"))

    def analyze(self):
        # Load user config if provided
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

class ECBAndDESChecker(SymmetricChecker):
    """
    Detect use of ECB mode and weak algorithms (DES/3DES).
    """
    NAME = 'ecb-des'
    CWECODE = 'CWE-326'
    SEVERITY = 'HIGH'

    def __init__(self, file_path, config=None):
        super().__init__(file_path, config)
        # Normalize
        self.insecure_modes = {m.upper() for m in self.config.get('insecure_modes', [])}
        self.weak_algos     = {a.upper() for a in self.config.get('weak_algorithms', [])}

    def visit_ImportFrom(self, node):
        # e.g. from Crypto.Cipher import DES as myDES
        module = node.module or ''
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            full = f"{module}.{name}" if module else name
            self.aliases[asname] = full
        self.generic_visit(node)

    def visit_Import(self, node):
        # e.g. import Crypto.Cipher.DES as DESmod
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            self.aliases[asname] = name
        self.generic_visit(node)

    def visit_Call(self, node):
        # Detect calls like DES.new(key, DES.MODE_ECB) or AES.new(key, AES.MODE_ECB)
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == 'new':
            # determine class name
            if isinstance(func.value, ast.Name):
                cls_name = func.value.id
            elif isinstance(func.value, ast.Attribute):
                parts = []
                cur = func.value
                while isinstance(cur, ast.Attribute):
                    parts.insert(0, cur.attr)
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    parts.insert(0, cur.id)
                cls_name = parts[-1]
            else:
                cls_name = None

            if cls_name and cls_name.upper() in self.weak_algos:
                # check if a mode argument is provided
                # usually 2nd positional arg or mode=...
                mode_nodes = []
                # positional
                if len(node.args) >= 2:
                    mode_nodes.append(node.args[1])
                # keywords
                for kw in node.keywords:
                    if kw.arg in ('mode',):
                        mode_nodes.append(kw.value)
                for mnode in mode_nodes:
                    if isinstance(mnode, ast.Attribute):
                        # e.g. DES.MODE_ECB or AES.MODE_ECB
                        mode_name = mnode.attr.upper()
                        if mode_name in self.insecure_modes:
                            self.report(
                                node.lineno,
                                f"Use of {cls_name}.MODE_ECB with weak cipher {cls_name}",
                                cwe=self.CWECODE,
                                severity=self.SEVERITY
                            )
                            break
        self.generic_visit(node)

# Example CLI stub omitted; use symmetric_analysis_runner.py for execution
