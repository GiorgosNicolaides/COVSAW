import ast
import re

SENSITIVE_VARIABLE_NAMES = {
    "password", "passwd", "token", "secret", "api_key", "apikey",
    "access_key", "auth", "authorization", "credentials", "key"
}

SECRET_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9\-_+=]{12,}$")  # JWTs, API tokens, etc.

class HardcodedSecretsChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe="CWE-798", severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Assign(self, node):
        # Match variables like 'password', 'api_key', etc.
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            assigned_value = node.value.value.strip()
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.lower()
                    if var_name in SENSITIVE_VARIABLE_NAMES:
                        if len(assigned_value) >= 8:
                            self.report(
                                node.lineno,
                                f"Hardcoded secret assigned to '{var_name}'"
                            )
                    elif SECRET_VALUE_PATTERN.match(assigned_value):
                        self.report(
                            node.lineno,
                            f"Suspicious hardcoded string assigned to '{var_name}'"
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
        print("Usage: python detect_hardcoded_secrets.py <file_to_check.py>")
        sys.exit(1)

    checker = HardcodedSecretsChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No hardcoded secrets found.")
    else:
        print("Hardcoded secrets detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
