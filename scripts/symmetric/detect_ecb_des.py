import ast

# AES.MODE_ECB and DES/3DES detection
INSECURE_MODES = {"MODE_ECB"}
WEAK_ALGORITHMS = {"DES", "TripleDES"}

class ECBAndDESChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe, severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Call(self, node):
        # Detect DES or TripleDES usage via <DES>.new(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "new":
            if isinstance(node.func.value, ast.Name):
                algorithm_name = node.func.value.id
                if algorithm_name in WEAK_ALGORITHMS:
                    self.report(
                        node.lineno,
                        f"Insecure algorithm used: {algorithm_name}",
                        "CWE-327"
                    )

        # Detect ECB mode usage in AES.new(..., AES.MODE_ECB)
        for arg in node.args:
            if isinstance(arg, ast.Attribute):
                if arg.attr in INSECURE_MODES:
                    self.report(
                        arg.lineno,
                        f"Insecure block mode used: {arg.attr}",
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
        print("Usage: python detect_ecb_des.py <file_to_check.py>")
        sys.exit(1)

    checker = ECBAndDESChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No ECB mode or DES usage found.")
    else:
        print("ECB mode or DES usage detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
