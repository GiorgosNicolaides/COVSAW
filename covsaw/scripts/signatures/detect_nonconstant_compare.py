import ast
import os
import toml

# Default configuration for names to check for non-constant-time compare
DEFAULT_CONFIG = {
    'compare_names': [
        'signature', 'sig', 'signed_data', 'provided_sig', 'received_sig',
        'mac', 'tag'
    ],
}

class SignatureChecker(ast.NodeVisitor):
    """
    Base class for signature-related AST checkers.
    """
    NAME = 'signature-checker'
    CWECODE = 'CWE-203'
    SEVERITY = 'MEDIUM'

    def __init__(self, path, config=None):
        self.path = path
        self.issues = []
        self.config = config or DEFAULT_CONFIG

    def report(self, lineno, message, cwe=None, severity=None):
        cwe = cwe or self.CWECODE
        severity = severity or self.SEVERITY
        self.issues.append((lineno, f"{message} [CWE {cwe}, Severity {severity}]"))

    def analyze(self):
        with open(self.path, encoding='utf-8') as f:
            source = f.read()
        tree = ast.parse(source, filename=self.path)
        self.visit(tree)
        return self.issues

class NonConstantSignatureCompareChecker(SignatureChecker):
    """
    Detect direct `==` or `!=` comparisons on signature-like variables.
    """
    NAME = 'nonconstant-signature-compare'

    def __init__(self, path, config=None):
        super().__init__(path, config)
        # Load optional user config
        cfg_path = os.getenv('SIG_CHECK_CONFIG')
        if cfg_path and os.path.isfile(cfg_path):
            try:
                user_cfg = toml.load(cfg_path)
                self.config.update(user_cfg)
            except Exception:
                pass
        self.compare_names = {n.lower() for n in self.config.get('compare_names', [])}

    def _extract_name(self, node):
        # Return the name or full attribute path of Name/Attribute nodes
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts = []
            cur = node
            while isinstance(cur, ast.Attribute):
                parts.insert(0, cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.insert(0, cur.id)
            return '.'.join(parts)
        return None

    def visit_Compare(self, node):
        # Only check == and != operators
        if any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            names = []
            left_name = self._extract_name(node.left)
            if left_name:
                names.append(left_name)
            for comp in node.comparators:
                cmp_name = self._extract_name(comp)
                if cmp_name:
                    names.append(cmp_name)
            for n in names:
                if n.lower() in self.compare_names:
                    self.report(
                        node.lineno,
                        f"Non-constant-time compare used for variable '{n}'; use secrets.compare_digest instead"
                    )
                    break
        self.generic_visit(node)

    def visit_Assert(self, node):
        # Catch asserts like assert sig == expected
        if isinstance(node.test, ast.Compare):
            self.visit_Compare(node.test)
        self.generic_visit(node)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python detect_nonconstant_compare.py <file_to_check.py>")
        sys.exit(1)

    checker = NonConstantSignatureCompareChecker(sys.argv[1])
    results = checker.analyze()

    if not results:
        print("No insecure signature comparisons found.")
    else:
        print("Insecure (non-constant-time) signature comparison detected:")
        for line, issue in results:
            print(f"Line {line}: {issue}")