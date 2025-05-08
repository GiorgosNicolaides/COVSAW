import ast
import os
import toml

# Default configuration for signature operations
DEFAULT_CONFIG = {
    'sign_functions': ['sign', 'sign_deterministic'],
    'verify_functions': ['verify', 'public_key.verify'],
}

class SignatureChecker(ast.NodeVisitor):
    """
    Base class for signature-related AST checkers.
    """
    NAME = 'signature-checker'
    CWECODE = 'CWE-347'
    SEVERITY = 'HIGH'

    def __init__(self, path, config=None):
        self.path = path
        self.issues = []
        self.config = config or DEFAULT_CONFIG
        # Store import aliases for modules and functions
        self.aliases = {}

    def report(self, lineno, message, cwe=None, severity=None):
        cwe = cwe or self.CWECODE
        severity = severity or self.SEVERITY
        self.issues.append((lineno, f"{message} [CWE {cwe}, Severity {severity}]") )

    def analyze(self):
        with open(self.path, encoding='utf-8') as f:
            source = f.read()
        tree = ast.parse(source, filename=self.path)
        self.visit(tree)
        return self.issues

class MissingSignatureVerificationChecker(SignatureChecker):
    """
    Detect cases where signatures are generated without corresponding verification.
    """
    NAME = 'missing-signature-verification'

    def __init__(self, path, config=None):
        super().__init__(path, config)
        # Override with user config if provided
        cfg_path = os.getenv('SIG_CHECK_CONFIG')
        if cfg_path and os.path.isfile(cfg_path):
            try:
                user_cfg = toml.load(cfg_path)
                self.config.update(user_cfg)
            except Exception:
                pass

        # Signature and verification function names
        self.sign_funcs = {fn.lower() for fn in self.config.get('sign_functions', [])}
        self.verify_funcs = {fn.lower() for fn in self.config.get('verify_functions', [])}

        # Track signatures: var_name -> line_no
        self.signatures = {}
        # Track verified signatures: var_name set
        self.verified = set()
        # Lines where signatures created without assignment
        self.anonymous_signs = []
        # Generic verify calls
        self.generic_verify = False

    def visit_Import(self, node):
        # import module as alias
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            self.aliases[asname] = name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        # from module import func as alias
        module = node.module or ''
        for alias in node.names:
            full = f"{module}.{alias.name}" if module else alias.name
            self.aliases[alias.asname or alias.name] = full
        self.generic_visit(node)

    def _get_qualname(self, func_node):
        # Build fully qualified name for a Call.func node
        if isinstance(func_node, ast.Name):
            return self.aliases.get(func_node.id, func_node.id).lower()
        elif isinstance(func_node, ast.Attribute):
            parts = []
            cur = func_node
            while isinstance(cur, ast.Attribute):
                parts.insert(0, cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.insert(0, self.aliases.get(cur.id, cur.id))
            return '.'.join(parts).lower()
        return ''

    def visit_Assign(self, node):
        # Detect assignments of signature: sig = key.sign(msg)
        if isinstance(node.value, ast.Call):
            qual = self._get_qualname(node.value.func)
            for alg in self.sign_funcs:
                if qual.endswith(f".{alg}") or qual == alg:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.signatures[target.id] = node.lineno
                    # break after first match
                    break
        self.generic_visit(node)

    def visit_Call(self, node):
        qual = self._get_qualname(node.func)

        # Detect unassigned signature calls
        for alg in self.sign_funcs:
            if qual.endswith(f".{alg}") or qual == alg:
                self.anonymous_signs.append(node.lineno)
                break

        # Detect verification calls
        for vf in self.verify_funcs:
            if qual.endswith(f".{vf}") or qual == vf:
                # Mark generic verify
                self.generic_verify = True
                # If signature variable passed, mark verified
                if node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Name) and first.id in self.signatures:
                        self.verified.add(first.id)
                break

        self.generic_visit(node)

    def analyze(self):
        issues = super().analyze()
        # Report unverified assigned signatures
        for var, lineno in self.signatures.items():
            if var not in self.verified:
                self.report(lineno, f"Signature '{var}' created without verification")

        # Report anonymous signs if no generic verify
        if self.anonymous_signs and not (self.generic_verify or self.verified):
            for ln in self.anonymous_signs:
                self.report(ln, "Signature created without verification")

        return self.issues
