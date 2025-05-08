import ast
import math
import re
import sys

class HardcodedSecretsChecker(ast.NodeVisitor):
    SECRET_VAR_PATTERN = re.compile(r'pass(word)?|token|secret|key', re.IGNORECASE)
    HEX_SECRET_PATTERN = re.compile(r'^[A-Fa-f0-9]{32,}$')
    BASE64_SECRET_PATTERN = re.compile(r'^[A-Za-z0-9+/]{40,}={0,2}$')
    MIN_SECRET_LENGTH = 8

    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'r', encoding='utf-8') as f:
            self.lines = f.readlines()
        self.issues = []

    def report(self, lineno, message, severity='medium'):
        snippet = self.lines[lineno - 1].rstrip() if 0 <= lineno - 1 < len(self.lines) else ''
        meta = f" [Severity: {severity}]"
        self.issues.append((lineno, f"{message}{meta}: '{snippet}'"))

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name) and self.SECRET_VAR_PATTERN.search(target.id):
                self._check_value(node.value, target.id, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and self.SECRET_VAR_PATTERN.search(node.target.id):
            self._check_value(node.value, node.target.id, node.lineno)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        defaults = node.args.defaults
        args = node.args.args
        for arg, default in zip(args[-len(defaults):], defaults):
            if isinstance(default, ast.Constant) and isinstance(default.value, str):
                if self.SECRET_VAR_PATTERN.search(arg.arg):
                    self.report(
                        node.lineno,
                        f"parameter '{arg.arg}' has hardcoded default secret",
                        'high'
                    )
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        literal = ''.join(
            v.value for v in node.values
            if isinstance(v, ast.Constant) and isinstance(v.value, str)
        )
        if len(literal) >= self.MIN_SECRET_LENGTH:
            self.report(
                node.lineno,
                "f-string contains literal with secret-like content",
                'medium'
            )
        self.generic_visit(node)

    def visit_Call(self, node):
        # os.getenv fallback with literal default
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == 'os'
            and node.func.attr == 'getenv'
        ):
            args = node.args
            if (
                len(args) >= 2
                and isinstance(args[1], ast.Constant)
                and isinstance(args[1].value, str)
            ):
                self.report(
                    node.lineno,
                    "os.getenv fallback provides hardcoded default",
                    'medium'
                )
        self.generic_visit(node)

    def _check_value(self, val, varname, lineno):
        if isinstance(val, ast.Constant) and isinstance(val.value, str):
            # Variable name implies secret
            if self.SECRET_VAR_PATTERN.search(varname):
                self.report(
                    lineno,
                    f"{varname} assigned hardcoded secret",
                    'high'
                )
            else:
                s = val.value
                if len(s) >= self.MIN_SECRET_LENGTH and self._looks_like_secret(s):
                    self.report(
                        lineno,
                        f"{varname} assigned hardcoded secret",
                        'medium'
                    )
        elif isinstance(val, ast.BinOp):
            parts = []
            self._gather_strings(val, parts)
            combined = ''.join(parts)
            if len(combined) >= self.MIN_SECRET_LENGTH and self._looks_like_secret(combined):
                self.report(
                    lineno,
                    f"{varname} assigned concatenated literal secret",
                    'medium'
                )

    def _gather_strings(self, node, parts):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            self._gather_strings(node.left, parts)
            self._gather_strings(node.right, parts)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            parts.append(node.value)

    def _looks_like_secret(self, s: str) -> bool:
        if self.HEX_SECRET_PATTERN.match(s) or self.BASE64_SECRET_PATTERN.match(s):
            return True
        return self._shannon_entropy(s) >= 4.0

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        probs = [count / len(s) for count in freq.values()]
        return -sum(p * math.log2(p) for p in probs) / len(s)

    def analyze(self):
        with open(self.filename, 'r', encoding='utf-8') as f:
            source = f.read()
        tree = ast.parse(source, filename=self.filename)
        self.visit(tree)
        return self.issues


if __name__ == '__main__':
    checker = HardcodedSecretsChecker(sys.argv[1])
    issues = checker.analyze()
    if not issues:
        print("No hardcoded secrets detected.")
    else:
        print("Hardcoded secret issues detected:")
        for lineno, issue in issues:
            print(f"Line {lineno}: {issue}")
