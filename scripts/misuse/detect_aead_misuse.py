import ast
import sys

# AEAD classes and methods to check
AEAD_CLASSES = {
    'AESGCM',
    'ChaCha20Poly1305',
    # add others as needed
}
SUSPICIOUS_METHODS = {'encrypt', 'decrypt'}

class AEADMisuseChecker(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'r', encoding='utf-8') as f:
            self.lines = f.readlines()
        self.issues = []
        # Track nonces from os.urandom
        self.seen_nonces = set()
        # Track AEAD instance variables: var_name -> class_name
        self.var_types = {}

    def report(self, lineno, message, cwe=None, severity=None):
        snippet = self.lines[lineno - 1].rstrip() if lineno <= len(self.lines) else ''
        parts = []
        if cwe:
            parts.append(f"CWE: {cwe}")
        if severity:
            parts.append(f"Severity: {severity}")
        meta = f" [{', '.join(parts)}]" if parts else ''
        self.issues.append((lineno, f"{message}{meta}: '{snippet}'"))

    def visit_Assign(self, node):
        # Track nonce variables
        if isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Attribute) and func.attr == 'urandom':
                self.seen_nonces.add(node.targets[0].id)
        # Track AEAD instance creation: var = AESGCM(key)
        if isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Call):
            ctor = node.value.func
            if isinstance(ctor, ast.Name) and ctor.id in AEAD_CLASSES:
                self.var_types[node.targets[0].id] = ctor.id
        self.generic_visit(node)

    def visit_Call(self, node):
        if not isinstance(node.func, ast.Attribute):
            return self.generic_visit(node)

        method = node.func.attr
        if method not in SUSPICIOUS_METHODS:
            return self.generic_visit(node)

        # Determine the AEAD class name, either direct var or new()
        class_node = node.func.value
        class_name = None
        if isinstance(class_node, ast.Name):
            # either 'AESGCM' or an instance var like 'aead'
            if class_node.id in AEAD_CLASSES:
                class_name = class_node.id
            elif class_node.id in self.var_types:
                class_name = self.var_types[class_node.id]
        elif isinstance(class_node, ast.Call):
            # pattern: AESGCM(key).encrypt(...)
            func = class_node.func
            if isinstance(func, ast.Name) and func.id in AEAD_CLASSES:
                class_name = func.id

        if class_name not in AEAD_CLASSES:
            return self.generic_visit(node)

        # --- 1) Nonce checks ---
        if len(node.args) >= 1:
            nonce = node.args[0]
            # constant-literal
            if isinstance(nonce, ast.Constant) and isinstance(nonce.value, (bytes, str)):
                self.report(
                    node.lineno,
                    f"{class_name}.{method} uses a constant nonce; use a CSPRNG",
                    "CWE-338", "medium"
                )
            # wrong-length literal
            if isinstance(nonce, ast.Constant) and isinstance(nonce.value, bytes):
                if len(nonce.value) != 12:
                    self.report(
                        node.lineno,
                        f"{class_name}.{method} nonce is {len(nonce.value)} bytes; recommended 12 bytes",
                        "CWE-330", "low"
                    )
            # reused nonce variable
            if isinstance(nonce, ast.Name) and nonce.id in self.seen_nonces:
                self.report(
                    node.lineno,
                    f"{class_name}.{method} reuses nonce variable '{nonce.id}'",
                    "CWE-329", "high"
                )
        else:
            # missing nonce
            self.report(
                node.lineno,
                f"{class_name}.{method} called without a nonce argument",
                "CWE-330", "high"
            )

        # --- 2) AAD checks ---
        has_aad_kw = any(kw.arg == 'associated_data' for kw in node.keywords)
        if not has_aad_kw:
            self.report(
                node.lineno,
                f"{class_name}.{method} omits associated_data; consider authenticating AAD",
                "CWE-352", "medium"
            )

        # --- 3) decrypt return-value usage ---
        if method == 'decrypt':
            parent = getattr(node, 'parent', None)
            if not isinstance(parent, (ast.Assign, ast.Expr)):
                self.report(
                    node.lineno,
                    f"{class_name}.decrypt return value is not used; plaintext may be dropped",
                    "CWE-347", "high"
                )

        self.generic_visit(node)

    def analyze(self):
        with open(self.filename, 'r', encoding='utf-8') as f:
            source = f.read()
        tree = ast.parse(source, filename=self.filename)
        # set parent pointers
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                setattr(child, 'parent', parent)
        self.visit(tree)
        return self.issues

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <file_to_check.py>")
        sys.exit(1)
    checker = AEADMisuseChecker(sys.argv[1])
    issues = checker.analyze()
    if not issues:
        print("No AEAD misuse detected.")
    else:
        print("AEAD misuse issues detected:")
        for lineno, issue in issues:
            print(f"Line {lineno}: {issue}")
