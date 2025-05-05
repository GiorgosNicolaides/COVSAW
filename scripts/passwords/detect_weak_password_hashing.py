import ast
import sys

WEAK_HASHES = {"md5", "sha1"}
PASSWORD_VAR_NAMES = {"password", "passwd", "pwd"}
SAFE_COMPARE_FUNCS = {"compare_digest"}

class WeakPasswordHashingChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe="CWE-328", severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]") )

    def visit_Call(self, node):
        # Detect weak hash usage via hashlib.md5 or hashlib.sha1
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                if node.func.attr in WEAK_HASHES:
                    self.report(
                        node.lineno,
                        f"Weak hash function used: hashlib.{node.func.attr}. Use hashlib.sha256 or a KDF like bcrypt instead."
                    )
        # Detect weak hash usage via direct import (e.g., "from hashlib import md5")
        elif isinstance(node.func, ast.Name) and node.func.id in WEAK_HASHES:
            self.report(
                node.lineno,
                f"Weak hash function used: {node.func.id}. Use hashlib.sha256 or a KDF like bcrypt instead."
            )
        # Detect constant-time compare usage (good practice)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hmac" and node.func.attr == "compare_digest":
                self.report(
                    node.lineno,
                    "Constant-time comparison used: hmac.compare_digest (good practice)",
                    cwe="CWE-311",
                    severity="low"
                )
        elif isinstance(node.func, ast.Name) and node.func.id in SAFE_COMPARE_FUNCS:
            self.report(
                node.lineno,
                f"Constant-time comparison used: {node.func.id} (good practice)",
                cwe="CWE-311",
                severity="low"
            )

        self.generic_visit(node)

    def visit_Compare(self, node):
        # Detect direct comparisons of password variables
        if isinstance(node.ops[0], ast.Eq):
            # Skip if comparison originates from constant-time function
            left_call = isinstance(node.left, ast.Call)
            right_call = isinstance(node.comparators[0], ast.Call)
            def is_safe_call(call):
                if isinstance(call.func, ast.Attribute):
                    return isinstance(call.func.value, ast.Name) and call.func.value.id == "hmac" and call.func.attr == "compare_digest"
                if isinstance(call.func, ast.Name):
                    return call.func.id in SAFE_COMPARE_FUNCS
                return False

            if (left_call and is_safe_call(node.left)) or (right_call and is_safe_call(node.comparators[0])):
                return  # safe usage, skip warning

            left = node.left
            right = node.comparators[0]
            if isinstance(left, ast.Name) and isinstance(right, ast.Name):
                var_names = {left.id.lower(), right.id.lower()}
                if var_names & PASSWORD_VAR_NAMES:
                    self.report(
                        node.lineno,
                        "Direct comparison of password variables using '==' (consider using hmac.compare_digest for constant-time comparison)",
                        severity="medium"
                    )
        self.generic_visit(node)

    def analyze(self):
        with open(self.file_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=self.file_path)
        self.visit(tree)
        return self.issues

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect_weak_password_hashing.py <file_to_check.py>")
        sys.exit(1)

    checker = WeakPasswordHashingChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No weak password hashing detected.")
    else:
        print("Weak password hashing issues detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
