import ast
import os
import re
import toml

# Default configuration for hardcoded keys and sensitive values
DEFAULT_CONFIG = {
    'sensitive_names': [
        'key', 'secret', 'encryption_key', 'password',
        'iv', 'token', 'salt',
    ],
    'hardcoded_pattern': r'^[A-Fa-f0-9+/=]{16,}$',
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
        self.aliases = {}

    def report(self, lineno, message, cwe=None, severity=None):
        cwe = cwe or self.CWECODE
        severity = severity or self.SEVERITY
        self.issues.append((lineno, f"{message} [CWE {cwe}, Severity {severity}]") )

    def analyze(self):
        # Load user config if present
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

class HardcodedKeyChecker(SymmetricChecker):
    """
    Detect hardcoded keys or sensitive literals in code.
    """
    NAME = 'hardcoded-key'
    CWECODE = 'CWE-259'
    SEVERITY = 'HIGH'

    def __init__(self, file_path, config=None):
        super().__init__(file_path, config)
        self.sensitive_names = {n.lower() for n in self.config.get('sensitive_names', [])}
        self.pattern = re.compile(self.config.get('hardcoded_pattern', DEFAULT_CONFIG['hardcoded_pattern']))

    def _extract_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    def visit_Assign(self, node):
        # Check each assignment target
        for target in node.targets:
            name = self._extract_name(target)
            if name and name.lower() in self.sensitive_names:
                val = node.value
                # Plain string literal
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    if self.pattern.match(val.value):
                        self.report(node.lineno, f"Hardcoded sensitive value in '{name}'")
                # f-string literal
                elif isinstance(val, ast.JoinedStr):
                    s = ''.join(
                        part.value for part in val.values
                        if isinstance(part, ast.Constant) and isinstance(part.value, str)
                    )
                    if self.pattern.match(s):
                        self.report(node.lineno, f"Hardcoded sensitive f-string in '{name}'")
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        # Detect default argument values that are hardcoded
        for arg, default in zip(reversed(node.args.args), node.args.defaults):
            if arg.arg.lower() in self.sensitive_names and \
               isinstance(default, ast.Constant) and isinstance(default.value, str) and \
               self.pattern.match(default.value):
                self.report(
                    node.lineno,
                    f"Function default hardcoded sensitive value for '{arg.arg}'"
                )
        self.generic_visit(node)

    def visit_Call(self, node):
        # Detect hardcoded default in os.getenv calls
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == 'getenv':
            if len(node.args) >= 2:
                default = node.args[1]
                if isinstance(default, ast.Constant) and isinstance(default.value, str):
                    if self.pattern.match(default.value):
                        self.report(node.lineno, "Hardcoded default in os.getenv() call")
        self.generic_visit(node)
