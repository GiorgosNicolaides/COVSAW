import ast

SIGN_FUNCTIONS = {"sign", "sign_deterministic"}
VERIFY_FUNCTIONS = {"verify", "public_key.verify"}

class MissingSignatureVerificationChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []
        self.found_sign = False
        self.found_verify = False

    def report(self, lineno, message, cwe="CWE-347", severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Call(self, node):
        # Detect function calls like key.sign(...) or module.sign(...)
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr.lower()
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id.lower()

        if func_name in SIGN_FUNCTIONS:
            self.found_sign = True
            sign_line = node.lineno

        if func_name in VERIFY_FUNCTIONS:
            self.found_verify = True

        self.generic_visit(node)

    def analyze(self):
        with open(self.file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=self.file_path)
        self.visit(tree)

        if self.found_sign and not self.found_verify:
            self.report(
                0,
                "Digital signature operation found without any verification call"
            )
        return self.issues


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python detect_missing_verification.py <file_to_check.py>")
        sys.exit(1)

    checker = MissingSignatureVerificationChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("Signature verification is present.")
    else:
        print("Missing signature verification detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
