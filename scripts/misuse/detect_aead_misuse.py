import ast


AEAD_CLASSES = {
    "AESGCM", "ChaCha20Poly1305", "AES_GCM", "chacha20poly1305"
}

SUSPICIOUS_AESGCM_CALLS = {
    "encrypt", "decrypt"
}


class AEADMisuseChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe="CWE-330", severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Call(self, node):
        # Check for AEAD encrypt/decrypt missing AAD (Additional Authenticated Data)
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
            if method_name in SUSPICIOUS_AESGCM_CALLS:
                if isinstance(node.func.value, ast.Name) or isinstance(node.func.value, ast.Attribute):
                    if hasattr(node.func.value, "id"):
                        class_name = node.func.value.id
                    elif hasattr(node.func.value, "attr"):
                        class_name = node.func.value.attr
                    else:
                        class_name = ""

                    if class_name in AEAD_CLASSES:
                        if len(node.args) < 3:
                            self.report(
                                node.lineno,
                                f"{class_name}.{method_name} called with insufficient arguments (likely missing nonce or AAD)",
                                "CWE-330"
                            )
                        if method_name == "decrypt" and len(node.args) < 4:
                            self.report(
                                node.lineno,
                                f"{class_name}.decrypt may be missing tag verification or AAD",
                                "CWE-347"
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
        print("Usage: python detect_aead_misuse.py <file_to_check.py>")
        sys.exit(1)

    checker = AEADMisuseChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No AEAD misuse detected.")
    else:
        print("AEAD misuse detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
