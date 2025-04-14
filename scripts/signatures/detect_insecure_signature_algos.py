import ast

# Extended list of known insecure or deprecated hash algorithms
INSECURE_HASHES = {
    "md5",
    "sha1",
    "sha0",
    "ripemd128",
    "ripemd-128",
    "tiger",
    "whirlpool"
}

class InsecureSignatureAlgoChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe="CWE-327", severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Call(self, node):
        # Detect use of hashlib.<insecure_hash>()
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                func_name = node.func.attr.lower()
                if func_name in INSECURE_HASHES:
                    self.report(
                        node.lineno,
                        f"Use of weak hash function: hashlib.{func_name}"
                    )

        # Detect insecure hash names passed as strings, e.g., rsa.sign(..., ..., "SHA-1")
        if isinstance(node.func, (ast.Attribute, ast.Name)):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.lower() in INSECURE_HASHES:
                        self.report(
                            node.lineno,
                            f"Signature uses weak hash algorithm: '{arg.value}'"
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
        print("Usage: python detect_insecure_signature_algos.py <file_to_check.py>")
        sys.exit(1)

    checker = InsecureSignatureAlgoChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No insecure signature algorithms found.")
    else:
        print("Insecure signature algorithms detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
