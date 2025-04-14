import ast

BLOCK_CIPHER_MODES = {"MODE_CBC", "MODE_ECB", "MODE_CFB"}
HMAC_IMPORTS = {"hmac", "HMAC"}
CRYPTO_LIBS = {"Crypto", "cryptography"}
SUSPICIOUS_COMPOSITION = ["encrypt", "digest", "hexdigest", "update"]

class CustomCryptoProtocolChecker(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def report(self, lineno, message, cwe="CWE-327", severity="high"):
        self.issues.append((lineno, f"{message} [CWE: {cwe}, Severity: {severity}]"))

    def visit_Call(self, node):
        # Detect use of block modes that need manual integrity
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in BLOCK_CIPHER_MODES:
                self.report(
                    node.lineno,
                    f"Manual cipher mode used: {node.func.attr} — consider AEAD (GCM/ChaCha20-Poly1305)",
                    "CWE-327"
                )

        # Detect separate encrypt() + digest()/hmac() chains
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in SUSPICIOUS_COMPOSITION:
                if any(isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "encrypt"
                       for arg in node.args):
                    self.report(
                        node.lineno,
                        "Manual composition of encryption + MAC detected — use AEAD instead",
                        "CWE-294"
                    )

        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        # Warn if importing manual block ciphers from pycrypto/cryptography
        if node.module and any(lib in node.module for lib in CRYPTO_LIBS):
            for name in node.names:
                if name.name.lower() in {"cipher", "hmac"}:
                    self.report(
                        node.lineno,
                        f"Custom crypto primitive imported: {name.name}",
                        "CWE-327",
                        "medium"
                    )

    def analyze(self):
        with open(self.file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=self.file_path)
        self.visit(tree)
        return self.issues


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python detect_custom_crypto_protocols.py <file_to_check.py>")
        sys.exit(1)

    checker = CustomCryptoProtocolChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No custom crypto protocol misuse detected.")
    else:
        print("Potential misuse of crypto primitives:")
        for line, issue in results:
            print(f"Line {line}: {issue}")
