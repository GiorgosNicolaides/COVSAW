import ast

# Known insecure randomness sources
WEAK_RANDOM_SOURCES = {
    "random", "random.random", "random.randint", "random.getrandbits", "random.seed"
}
SUSPICIOUS_IV_NAMES = {"iv", "nonce", "initialization_vector", "counter"}

class WeakIVChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe, severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Call(self, node):
        # Check function calls that use insecure randomness
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            full_func = f"{node.func.value.id}.{node.func.attr}"
            if full_func in WEAK_RANDOM_SOURCES:
                self.report(
                    node.lineno,
                    f"Weak random function used for IV/nonce: {full_func}",
                    "CWE-330"
                )
        self.generic_visit(node)

    def visit_Assign(self, node):
        # Check if an IV or nonce is assigned a weak source (e.g., random, constant)
        if isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id.lower()
            if var_name in SUSPICIOUS_IV_NAMES:
                if isinstance(node.value, ast.Constant):
                    self.report(
                        node.lineno,
                        f"IV/nonce '{var_name}' is statically assigned a constant value",
                        "CWE-329"
                    )
                elif isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute):
                    func_name = f"{node.value.func.value.id}.{node.value.func.attr}"
                    if func_name in WEAK_RANDOM_SOURCES:
                        self.report(
                            node.lineno,
                            f"IV/nonce '{var_name}' generated using insecure PRNG: {func_name}",
                            "CWE-330"
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
        print("Usage: python detect_weak_iv.py <file_to_check.py>")
        sys.exit(1)

    checker = WeakIVChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No weak IV or nonce issues detected.")
    else:
        print("Potential weak IV/nonce usage detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
