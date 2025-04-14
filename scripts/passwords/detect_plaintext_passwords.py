import ast

PASSWORD_VAR_NAMES = {
    "password", "passwd", "pwd", "user_pass", "admin_password"
}

class PlaintextPasswordChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe, severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Assign(self, node):
        # Detect assignments like password = "123456"
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if target.id.lower() in PASSWORD_VAR_NAMES:
                        self.report(
                            node.lineno,
                            f"Hardcoded password assigned to variable '{target.id}'",
                            "CWE-257"
                        )
        self.generic_visit(node)

    def visit_Call(self, node):
        # Detect print(password) or open(...).write(password)
        if isinstance(node.func, ast.Name) and node.func.id == "print":
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id.lower() in PASSWORD_VAR_NAMES:
                    self.report(
                        node.lineno,
                        f"Sensitive variable '{arg.id}' printed to console",
                        "CWE-312"
                    )

        if isinstance(node.func, ast.Attribute) and node.func.attr == "write":
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id.lower() in PASSWORD_VAR_NAMES:
                    self.report(
                        node.lineno,
                        f"Sensitive variable '{arg.id}' written to file",
                        "CWE-312"
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
        print("Usage: python detect_plaintext_passwords.py <file_to_check.py>")
        sys.exit(1)

    checker = PlaintextPasswordChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No plaintext password issues found.")
    else:
        print("Plaintext password issues detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
