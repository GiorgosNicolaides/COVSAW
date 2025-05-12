import ast
import re
import sys

class PlaintextPasswordChecker(ast.NodeVisitor):
    PASSWORD_VAR_PATTERN = re.compile(
        r"pass(word|wd|phrase|code)?|pw|cred(s|entials)?",
        re.IGNORECASE
    )

    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'r', encoding='utf-8') as f:
            self.lines = f.readlines()
        self.issues = []
        self.context_stack = []  # track class/function context

    def report(self, lineno, varname, reason):
        snippet = self.lines[lineno - 1].rstrip() if lineno <= len(self.lines) else ''
        self.issues.append((lineno, f"Variable '{varname}' {reason}: '{snippet}'"))

    def visit_FunctionDef(self, node):
        self.context_stack.append(f"function '{node.name}'")
        self.generic_visit(node)
        self.context_stack.pop()

    def visit_ClassDef(self, node):
        self.context_stack.append(f"class '{node.name}'")
        self.generic_visit(node)
        self.context_stack.pop()

    def visit_Assign(self, node):
        # Detect assignments to password‐looking variables
        for target in node.targets:
            if isinstance(target, ast.Name) and \
               self.PASSWORD_VAR_PATTERN.fullmatch(target.id):
                self.report(
                    node.lineno,
                    target.id,
                    "assigned plaintext value"
                )
        self.generic_visit(node)

    def visit_Call(self, node):
        # Detect passing plaintext variables into functions
        for arg in node.args:
            if isinstance(arg, ast.Name) and \
               self.PASSWORD_VAR_PATTERN.fullmatch(arg.id):
                func_name = (
                    node.func.attr
                    if hasattr(node.func, 'attr')
                    else getattr(node.func, 'id', '')
                )
                self.report(
                    node.lineno,
                    arg.id,
                    f"passed to {func_name}()"
                )
        self.generic_visit(node)

    def analyze(self):
        """Parse the file, visit the AST, and return all findings."""
        with open(self.filename, 'r', encoding='utf-8') as f:
            source = f.read()
        tree = ast.parse(source, filename=self.filename)
        self.visit(tree)
        return self.issues


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.py>")
        sys.exit(1)

    checker = PlaintextPasswordChecker(sys.argv[1])
    results = checker.analyze()
    for lineno, issue in results:
        print(f"Line {lineno}: {issue}")
