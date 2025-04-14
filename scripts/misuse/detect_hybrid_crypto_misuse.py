import ast

RSA_ENCRYPT_FUNCS = {"encrypt", "rsa_encrypt"}
RSA_KEY_CLASSES = {"RSAPublicKey", "PublicKey"}
BAD_RSA_USAGE_HINTS = {"message.encode", "b\"", "plaintext"}

class HybridCryptoMisuseChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe="CWE-780", severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Call(self, node):
        # Look for direct RSA.encrypt(...) of raw data (no symmetric layer)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in RSA_ENCRYPT_FUNCS:
                if isinstance(node.func.value, ast.Name) or isinstance(node.func.value, ast.Attribute):
                    object_name = node.func.value.id if hasattr(node.func.value, "id") else ""
                    if any(kw in ast.unparse(node).lower() for kw in BAD_RSA_USAGE_HINTS):
                        self.report(
                            node.lineno,
                            f"Possible direct RSA encryption of plaintext — use hybrid encryption (RSA + AES)",
                            "CWE-780"
                        )
        self.generic_visit(node)

    def visit_Assign(self, node):
        # Look for static keys assigned as shared secrets
        if isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, (str, bytes)):
                if "key" in ast.unparse(node.target if isinstance(node.target, ast.Name) else node.targets[0]).lower():
                    self.report(
                        node.lineno,
                        "Static key used as session key — must be randomly generated",
                        "CWE-329"
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
        print("Usage: python detect_hybrid_crypto_misuse.py <file_to_check.py>")
        sys.exit(1)

    checker = HybridCryptoMisuseChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No hybrid cryptosystem misuse detected.")
    else:
        print("Hybrid crypto misuse detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
