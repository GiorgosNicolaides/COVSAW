import ast

SENSITIVE_VARIABLE_NAMES = {
    "key", "secret", "password", "token", "api_key", "credentials", "auth", "access_key"
}

class InsecureStorageChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe="CWE-312", severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Call(self, node):
        # Detect print(secret) — printing sensitive variables to console
        if isinstance(node.func, ast.Name) and node.func.id == "print":
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    if arg.id.lower() in SENSITIVE_VARIABLE_NAMES:
                        self.report(
                            node.lineno,
                            f"Sensitive variable '{arg.id}' printed to console"
                        )

        # Detect open(...).write(secret) — writing secrets to files
        if isinstance(node.func, ast.Attribute) and node.func.attr == "write":
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    if arg.id.lower() in SENSITIVE_VARIABLE_NAMES:
                        self.report(
                            node.lineno,
                            f"Sensitive variable '{arg.id}' written to file"
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
        print("Usage: python detect_insecure_storage.py <file_to_check.py>")
        sys.exit(1)

    checker = InsecureStorageChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No insecure secret storage found.")
    else:
        print("Insecure storage of secrets detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
