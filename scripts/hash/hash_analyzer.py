import os
import ast
import yaml


project_root = os.path.dirname(os.path.abspath(__file__))  
project_root = os.path.dirname(project_root) 

yaml_path = os.path.join(project_root, "rules", "hash_rules.yaml")

# Load rules from the YAML file
with open(yaml_path, "r", encoding="utf-8") as file:
    RULES = yaml.safe_load(file)["hash_rules"]

class HashAnalysis(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def visit_ImportFrom(self, node):
        """Checks for import statements related to hashlib."""
        if node.module == "hashlib":
            for alias in node.names:
                self.check_hash_function(alias.name, node.lineno)

    def visit_Call(self, node):
        """Checks function calls for hashing algorithms."""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "hashlib":
                self.check_hash_function(node.func.attr, node.lineno)

        # Detect potential custom hash functions (XOR, bitwise ops)
        if any(isinstance(op, (ast.BitXor, ast.BitAnd, ast.BitOr)) for op in ast.walk(node)):
            issue = RULES["warnings"]["custom_hash"]
            self.issues.append((node.lineno, f"{issue['message']} {issue['cwe']} {issue['recommendation']}"))

        self.generic_visit(node)

    def check_hash_function(self, func_name, lineno):
        """Checks if a hashing function is secure or insecure."""
        if func_name in RULES["insecure_algorithms"]:
            issue = RULES["insecure_algorithms"][func_name]
            self.issues.append((lineno, f"Insecure hashing: {func_name}. {issue['message']} {issue['cwe']} {issue['recommendation']}"))
        elif func_name in RULES["safe_algorithms"]:
            safe_algo = RULES["safe_algorithms"][func_name]
            self.issues.append((lineno, f"Safe hashing: {func_name}. {safe_algo['message']} "))
        elif func_name == "pbkdf2_hmac":
            # Explicitly mark PBKDF2 as secure
            self.issues.append((lineno, f"Safe hashing: {func_name}. PBKDF2 is a secure cryptographic hashing function. {RULES['safe_algorithms']['sha256']['cwe']}"))
        elif func_name not in RULES["insecure_algorithms"] and func_name not in RULES["safe_algorithms"]:
            # Custom hash detection that is genuinely insecure
            self.issues.append((lineno, f"Unrecognized hashing function: {func_name}. Please ensure it is secure."))

    def analyze(self):
        """Runs the analysis and prints issues."""
        with open(self.file_path, "r", encoding="utf-8") as file:
            tree = ast.parse(file.read(), filename=self.file_path)
            self.visit(tree)

        if not self.issues:
            print(f"No hashing vulnerabilities found in {self.file_path}. ")
        else:
            print(f"Potential hashing issues detected in {self.file_path}: ")
            for lineno, issue in self.issues:
                print(f"Line {lineno}: {issue}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python hash_analyzer.py <python_file_to_check>")
        sys.exit(1)

    analyzer = HashAnalysis(sys.argv[1])
    analyzer.analyze()
