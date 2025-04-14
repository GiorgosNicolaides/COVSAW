import ast
import re

# Regex to detect likely symmetric keys in hex/base64/plain string formats
HARD_CODED_KEY_PATTERN = re.compile(r'^[A-Fa-f0-9+/=]{16,}$')
SENSITIVE_NAMES = {"key", "secret", "encryption_key", "password", "iv", "token", "salt"}

class HardcodedKeyChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe, severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Assign(self, node):
        # Look for variable assignments like key = "secretvalue123"
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            var_names = [t.id.lower() for t in node.targets if isinstance(t, ast.Name)]
            for var_name in var_names:
                if var_name in SENSITIVE_NAMES:
                    if HARD_CODED_KEY_PATTERN.match(node.value.value) or len(node.value.value) >= 16:
                        self.report(
                            node.lineno,
                            f"Hardcoded symmetric key or sensitive value assigned to '{var_name}'",
                            "CWE-321"
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
        print("Usage: python detect_hardcoded_keys.py <file_to_check.py>")
        sys.exit(1)

    checker = HardcodedKeyChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No hardcoded keys or sensitive constants found.")
    else:
        print("Hardcoded key or sensitive value detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
