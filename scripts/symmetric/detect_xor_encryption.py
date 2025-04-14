import ast

class XORBasedEncryptionChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe, severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_BinOp(self, node):
        # Detect binary XOR operations (a ^ b), commonly used in insecure custom encryption
        if isinstance(node.op, ast.BitXor):
            self.report(
                node.lineno,
                "Possible XOR-based custom encryption detected",
                "CWE-327"
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
        print("Usage: python detect_xor_encryption.py <file_to_check.py>")
        sys.exit(1)

    checker = XORBasedEncryptionChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No XOR-based encryption patterns found.")
    else:
        print("Potential XOR-based encryption detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
