import ast
import sys

# Configurable lists
KDF_FUNCTIONS = {
    'pbkdf2_hmac',
    'bcrypt.hashpw',
    'scrypt',
    'argon2.PasswordHasher().hash'
}
STRONG_HASHLIB_ALGOS = {'sha256', 'sha512', 'blake2b', 'blake2s'}
SALT_NAMES = {'salt'}
PEPPER_NAMES = {'pepper'}

class MissingSaltOrKDFChecker(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'r', encoding='utf-8') as f:
            self.lines = f.readlines()
        self.issues = []

    def report(self, lineno, message, cwe=None, severity=None):
        snippet = self.lines[lineno - 1].rstrip() if lineno <= len(self.lines) else ''
        parts = []
        if cwe:
            parts.append(f"CWE: {cwe}")
        if severity:
            parts.append(f"Severity: {severity}")
        meta = f" [{', '.join(parts)}]" if parts else ''
        self.issues.append((lineno, f"{message}{meta}: '{snippet}'"))

    def visit_Call(self, node):
        # Handle KDF calls by name or via hashlib.<func>
        func_name = None
        if isinstance(node.func, ast.Name) and node.func.id in KDF_FUNCTIONS:
            func_name = node.func.id
        elif (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "hashlib"
            and node.func.attr in KDF_FUNCTIONS
        ):
            func_name = node.func.attr

        if func_name:
            # salt must be the 3rd positional arg
            if len(node.args) < 3:
                self.report(node.lineno,
                            f"KDF '{func_name}' used without salt",
                            "CWE-759")
            else:
                salt_arg = node.args[2]
                if not self._expr_contains_name(salt_arg, SALT_NAMES):
                    self.report(node.lineno,
                                f"KDF '{func_name}' used with missing or unclear salt",
                                "CWE-759")
            # pepper is always recommended
            if not self._contains_pepper(node):
                self.report(node.lineno,
                            f"KDF '{func_name}' does not appear to include pepper",
                            "CWE-916", "medium")

        # Detect bare hashlib.<strong algo>(...) without salt/pepper
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"
                and node.func.attr.lower() in STRONG_HASHLIB_ALGOS
            ):
                if not self._contains_salt_or_pepper(node):
                    self.report(
                        node.lineno,
                        f"Hash function '{node.func.attr.lower()}' used without salt or pepper",
                        "CWE-759"
                    )

        self.generic_visit(node)

    def _contains_salt_or_pepper(self, node):
        return any(
            self._expr_contains_name(arg, SALT_NAMES | PEPPER_NAMES)
            for arg in node.args
        )

    def _contains_pepper(self, node):
        return any(
            self._expr_contains_name(arg, PEPPER_NAMES)
            for arg in node.args
        )

    def _expr_contains_name(self, expr, name_set):
        if isinstance(expr, ast.BinOp):
            return (
                self._expr_contains_name(expr.left, name_set)
                or self._expr_contains_name(expr.right, name_set)
            )
        if isinstance(expr, ast.Name):
            return expr.id.lower() in name_set
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
            if (
                isinstance(expr.func.value, ast.Name)
                and expr.func.value.id.lower() in name_set
            ):
                return True
            return any(self._expr_contains_name(arg, name_set)
                       for arg in expr.args)
        return False

    def analyze(self):
        with open(self.filename, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=self.filename)
        self.visit(tree)
        return self.issues

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <file_to_check.py>")
        sys.exit(1)

    checker = MissingSaltOrKDFChecker(sys.argv[1])
    issues = checker.analyze()
    if not issues:
        print("No missing salt or KDF issues detected.")
    else:
        print("Salt/KDF issues detected:")
        for lineno, issue in issues:
            print(f"Line {lineno}: {issue}")
