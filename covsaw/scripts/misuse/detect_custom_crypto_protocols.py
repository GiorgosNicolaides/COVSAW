import ast
import sys

# Block cipher classes and insecure modes
BLOCK_CIPHER_CLASSES = {
    'AES', 'DES', 'Blowfish', 'ARC2', 'ARC4', 'Camellia'
}
INSECURE_MODES = {'ECB'}

class CustomCryptoProtocolChecker(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'r', encoding='utf-8') as f:
            self.lines = f.readlines()
        self.issues = []
        # Stack of scopes to detect HMAC in same context
        self.scopes = []

    def report(self, lineno, message, cwe=None, severity=None):
        snippet = self.lines[lineno - 1].rstrip() if lineno <= len(self.lines) else ''
        parts = []
        if cwe:
            parts.append(f"CWE: {cwe}")
        if severity:
            parts.append(f"Severity: {severity}")
        meta = f" [{', '.join(parts)}]" if parts else ''
        self.issues.append((lineno, f"{message}{meta}: '{snippet}'"))

    def visit_Module(self, node):
        # module-level scope
        self.scopes.append({'ciphers': [], 'hmac': False})
        self.generic_visit(node)
        self._analyze_scope(self.scopes.pop())

    def visit_FunctionDef(self, node):
        # function-level scope
        self.scopes.append({'ciphers': [], 'hmac': False})
        self.generic_visit(node)
        self._analyze_scope(self.scopes.pop())
        # do not re-enter child functions into parent scope

    def visit_Call(self, node):
        # Detect HMAC usage: hmac.new(...)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == 'hmac' and node.func.attr == 'new':
                self.scopes[-1]['hmac'] = True
        # Detect block cipher instantiation: AES.new(key, mode)
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'new':
            cls = node.func.value
            if isinstance(cls, ast.Name) and cls.id in BLOCK_CIPHER_CLASSES:
                mode = None
                # positional mode arg
                if len(node.args) >= 2:
                    arg = node.args[1]
                    if isinstance(arg, ast.Attribute):
                        mode = arg.attr.split('_')[-1]
                # keyword mode arg
                for kw in node.keywords:
                    if kw.arg == 'mode' and isinstance(kw.value, ast.Attribute):
                        mode = kw.value.attr.split('_')[-1]
                if mode:
                    self.scopes[-1]['ciphers'].append((node.lineno, mode))
        self.generic_visit(node)

    def _analyze_scope(self, scope):
        for lineno, mode in scope['ciphers']:
            if mode in INSECURE_MODES:
                self.report(
                    lineno,
                    f"Block cipher mode {mode} is insecure; avoid {mode}",
                    "CWE-327",
                    "high"
                )
            elif not scope['hmac']:
                # mode is secure but no authentication
                self.report(
                    lineno,
                    f"Mode {mode} used without authentication (MAC)",
                    "CWE-300",
                    "medium"
                )

    def analyze(self):
        with open(self.filename, 'r', encoding='utf-8') as f:
            source = f.read()
        tree = ast.parse(source, filename=self.filename)
        self.visit(tree)
        return self.issues

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <file_to_check.py>")
        sys.exit(1)
    checker = CustomCryptoProtocolChecker(sys.argv[1])
    issues = checker.analyze()
    if not issues:
        print("No custom crypto protocol issues detected.")
    else:
        print("Custom crypto protocol issues detected:")
        for lineno, issue in issues:
            print(f"Line {lineno}: {issue}")
