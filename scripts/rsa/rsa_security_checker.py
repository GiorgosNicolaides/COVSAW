import ast
import re
from pathlib import Path

# Define patterns for detecting RSA keys and insecure practices
RSA_PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (RSA|PRIVATE) KEY-----")
RSA_PUBLIC_KEY_PATTERN = re.compile(r"-----BEGIN PUBLIC KEY-----")
WEAK_PRNG_PATTERN = re.compile(r"random\.getrandbits|random\.seed")
SMALL_PRIME_THRESHOLD = 512  # Keys smaller than 512 bits are considered weak
WEAK_EXPONENTS = {3, 5, 7}  # Weak public exponents

class RSASecurityChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []
        self.detected_keys = set()
    
    def report_issue(self, lineno, message, severity, cwe):
        self.issues.append(f"Line {lineno}: {message} [CWE: {cwe}, Severity: {severity}]")
    
    def visit_Assign(self, node):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            self.check_for_rsa_key(node.lineno, node.value.value)
        self.generic_visit(node)
    
    def visit_Call(self, node):
        # Detect weak key generation
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "random" and node.func.attr in {"getrandbits", "seed"}:
                self.report_issue(node.lineno, "Weak PRNG detected in RSA key generation.", "high", "CWE-338")
        
        # Detect weak RSA key sizes
        if isinstance(node.func, ast.Attribute) and node.func.attr == "generate" and node.func.value.id == "RSA":
            if len(node.args) > 0 and isinstance(node.args[0], ast.Constant):
                key_size = node.args[0].value
                if key_size < SMALL_PRIME_THRESHOLD:
                    self.report_issue(node.lineno, "RSA key size is too small (less than 512 bits).", "high", "CWE-326")
        
        # Detect weak public exponents
        if isinstance(node.func, ast.Call) and hasattr(node.func, "attr") and node.func.attr == "construct":
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                exponent = node.args[1].value
                if exponent in WEAK_EXPONENTS:
                    self.report_issue(node.lineno, f"Weak RSA exponent detected: e={exponent}.", "high", "CWE-780")
        
        # Detect missing padding (e.g., no OAEP padding in encryption)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "encrypt":
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Name):
                padding = node.args[1].id
                if padding.lower() not in {"oaep", "pkcs1_oaep"}:
                    self.report_issue(node.lineno, "RSA encryption without OAEP padding detected.", "high", "CWE-780")
        
        self.generic_visit(node)
    
    def check_for_rsa_key(self, lineno, value):
        if value in self.detected_keys:
            self.report_issue(lineno, "Duplicate RSA key detected, indicating possible key reuse.", "medium", "CWE-323")
        
        self.detected_keys.add(value)
        
        if RSA_PRIVATE_KEY_PATTERN.search(value):
            self.report_issue(lineno, "Hardcoded RSA Private Key detected.", "high", "CWE-321")
        elif RSA_PUBLIC_KEY_PATTERN.search(value):
            self.report_issue(lineno, "Hardcoded RSA Public Key detected.", "medium", "CWE-321")
    
    def visit_FunctionDef(self, node):
        # Check if function writes keys to an insecure location
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute):
                if stmt.func.attr == "write" and len(stmt.args) > 0:
                    if isinstance(stmt.args[0], ast.Constant) and "PRIVATE KEY" in stmt.args[0].value:
                        self.report_issue(stmt.lineno, "RSA private key written to file insecurely.", "high", "CWE-312")
        self.generic_visit(node)
    
    def analyze(self):
        with open(self.file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        self.visit(tree)
        return self.issues

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python rsa_security_checker.py <file_to_analyze>")
        sys.exit(1)
    
    script_path = sys.argv[1]
    checker = RSASecurityChecker(script_path)
    results = checker.analyze()
    for issue in results:
        print(issue)
