import ast
import sys

# Symmetric AEAD/Symmetric classes for hybrid detection
SYMMETRIC_CLASSES = {'AESGCM', 'ChaCha20Poly1305', 'Fernet'}

class HybridCryptoMisuseChecker(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'r', encoding='utf-8') as f:
            self.lines = f.readlines()
        self.issues = []
        self.scopes = []
        # Track variables that hold symmetric instances
        self.var_types = {}

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
        self.scopes.append({'symm': False, 'rsa_calls': []})
        self.generic_visit(node)
        self._analyze_scope(self.scopes.pop())

    def visit_FunctionDef(self, node):
        self.scopes.append({'symm': False, 'rsa_calls': []})
        self.generic_visit(node)
        self._analyze_scope(self.scopes.pop())

    def visit_Assign(self, node):
        # Track symmetric instance creation: var = AESGCM(key)
        if isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Call):
            ctor = node.value.func
            if isinstance(ctor, ast.Name) and ctor.id in SYMMETRIC_CLASSES:
                self.var_types[node.targets[0].id] = ctor.id
        self.generic_visit(node)

    def visit_Call(self, node):
        # Look for any .encrypt(...) call
        if not isinstance(node.func, ast.Attribute) or node.func.attr != 'encrypt':
            return self.generic_visit(node)

        target = node.func.value
        is_symmetric = False

        # Direct symmetric class or instance var
        if isinstance(target, ast.Name):
            if target.id in SYMMETRIC_CLASSES:
                is_symmetric = True
            elif target.id in self.var_types:
                is_symmetric = True

        # e.g. AESGCM(key).encrypt(...)
        elif isinstance(target, ast.Call) and isinstance(target.func, ast.Name):
            if target.func.id in SYMMETRIC_CLASSES:
                is_symmetric = True

        if is_symmetric:
            self.scopes[-1]['symm'] = True
        else:
            # This is likely an RSA.encrypt(...) misuse
            lineno = node.lineno
            padding_ok = False

            # Check for padding argument
            if len(node.args) >= 2:
                pad_arg = node.args[1]
                if (
                    isinstance(pad_arg, ast.Call)
                    and isinstance(pad_arg.func, ast.Attribute)
                    and isinstance(pad_arg.func.value, ast.Name)
                    and pad_arg.func.value.id == 'padding'
                ):
                    if pad_arg.func.attr == 'OAEP':
                        padding_ok = True
                    else:
                        self.report(
                            lineno,
                            f"RSA encrypt uses insecure padding {pad_arg.func.attr}",
                            "CWE-326", "high"
                        )
            else:
                self.report(
                    lineno,
                    "RSA encrypt missing padding argument",
                    "CWE-326", "high"
                )

            self.scopes[-1]['rsa_calls'].append((lineno, padding_ok))

        return self.generic_visit(node)

    def _analyze_scope(self, scope):
        for lineno, padding_ok in scope['rsa_calls']:
            if not padding_ok:
                continue
            if not scope['symm']:
                self.report(
                    lineno,
                    "RSA encrypt called without a symmetric encryption layer",
                    "CWE-330", "high"
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
    checker = HybridCryptoMisuseChecker(sys.argv[1])
    issues = checker.analyze()
    if not issues:
        print("No hybrid crypto misuse detected.")
    else:
        print("Hybrid crypto misuse issues detected:")
        for lineno, issue in issues:
            print(f"Line {lineno}: {issue}")
