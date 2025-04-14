import ast

WEAK_HASHES = {"md5", "sha1"}
PASSWORD_VAR_NAMES = {"password", "passwd", "pwd"}

class WeakPasswordHashingChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe="CWE-328", severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Call(self, node):
        # Detect use of hashlib.md5, hashlib.sha1
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                if node.func.attr in WEAK_HASHES:
                    self.report(
                        node.lineno,
                        f"Weak hash function used: hashlib.{node.func.attr}"
                    )
        self.generic_visit(node)

    def visit_Compare(self, node):
        # Detect password == stored_password comparisons (no hashing)
        if isinstance(node.ops[0], ast.Eq):
            left = node.left
            right = node.comparators[0]
            if isinstance(left, ast.Name) and isinstance(right, ast.Name):
                var_names = {left.id.lower(), right.id.lower()}
                if var_names & PASSWORD_VAR_NAMES:
                    self.report(
                        node.lineno,
                        f"Direct comparison of password variables using '=='",
                        "CWE-328",
                        "medium"
                    )
        self.generic_visit(node)

    def analyze(self):
        with open(self.file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=self.file_path)
        self.visit(tree)
        return self.issues


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python detect_weak_password_hashing.py <file_to_check.py>")
        sys.exit(1)

    checker = WeakPasswordHashingChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No weak password hashing detected.")
    else:
        print("Weak password hashing issues detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
