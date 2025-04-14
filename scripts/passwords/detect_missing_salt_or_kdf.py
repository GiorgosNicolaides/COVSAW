import ast

KDF_FUNCTIONS = {"pbkdf2_hmac", "bcrypt", "scrypt", "argon2", "argon2id"}
STRONG_HASHLIB_ALGOS = {"sha256", "sha512", "sha3_256", "sha3_512"}

SALT_NAMES = {"salt", "salt_value", "random_salt"}
PEPPER_NAMES = {"pepper", "pepper_secret", "static_secret"}

class MissingSaltOrKDFChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []
        self.salt_detected = False
        self.pepper_detected = False

    def report(self, lineno, message, cwe, severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Call(self, node):
        # --- 1. Detect use of hashlib.<algo>(...) without salt ---
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                func_name = node.func.attr.lower()
                if func_name in STRONG_HASHLIB_ALGOS:
                    if not self._contains_salt_or_pepper(node):
                        self.report(
                            node.lineno,
                            f"Hash function '{func_name}' used without salt or pepper",
                            "CWE-759"
                        )

        # --- 2. Detect missing salt in KDFs (e.g., pbkdf2_hmac) ---
        if isinstance(node.func, ast.Name):
            if node.func.id in KDF_FUNCTIONS:
                if len(node.args) < 3:
                    self.report(
                        node.lineno,
                        f"KDF '{node.func.id}' used without salt",
                        "CWE-759"
                    )
                else:
                    salt_arg = node.args[2]
                    if not self._expr_contains_name(salt_arg, SALT_NAMES):
                        self.report(
                            node.lineno,
                            f"KDF '{node.func.id}' used with missing or unclear salt",
                            "CWE-759"
                        )
                if not self._contains_pepper(node):
                    self.report(
                        node.lineno,
                        f"KDF '{node.func.id}' does not appear to include pepper",
                        "CWE-916",
                        "medium"
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
        # Check if a variable in the expression matches a known salt/pepper name
        if isinstance(expr, ast.BinOp):
            return (
                self._expr_contains_name(expr.left, name_set)
                or self._expr_contains_name(expr.right, name_set)
            )
        if isinstance(expr, ast.Name):
            return expr.id.lower() in name_set
        return False

    def analyze(self):
        with open(self.file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=self.file_path)
        self.visit(tree)
        return self.issues


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python detect_missing_salt_or_kdf.py <file_to_check.py>")
        sys.exit(1)

    checker = MissingSaltOrKDFChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No salt/pepper/KDF issues detected.")
    else:
        print("Missing salt, pepper, or KDF issues detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
