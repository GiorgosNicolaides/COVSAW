
import ast

# Identifiers that likely represent signature variables
SIGNATURE_LIKE_NAMES = {"signature", "sig", "signed_data", "provided_sig", "received_sig"}

class NonConstantSignatureCompareChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe="CWE-203", severity="medium"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Compare(self, node):
        # Detect comparisons using `==` or `!=` on signature-like variables
        if isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            left = node.left
            comparators = node.comparators

            def is_signature_var(expr):
                return isinstance(expr, ast.Name) and expr.id.lower() in SIGNATURE_LIKE_NAMES

            if any(is_signature_var(expr) for expr in [left] + comparators):
                op = "==" if isinstance(node.ops[0], ast.Eq) else "!="
                self.report(
                    node.lineno,
                    f"Signature comparison using '{op}' instead of constant-time comparison"
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
        print("Usage: python detect_nonconstant_compare.py <file_to_check.py>")
        sys.exit(1)

    checker = NonConstantSignatureCompareChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No insecure signature comparisons found.")
    else:
        print("Insecure (non-constant-time) signature comparison detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
