import ast
import re
import sys

class PlaintextPasswordChecker(ast.NodeVisitor):
    PASSWORD_VAR_PATTERN = re.compile(r"pass(word|wd|phrase|code)?|pw|cred(s|entials)?", re.IGNORECASE)

    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'r', encoding='utf-8') as f:
            self.lines = f.readlines()
        self.issues = []
        self.context_stack = []  # track class/function context

    def report(self, lineno, varname, reason):
        # Extract snippet
        snippet = self.lines[lineno - 1].rstrip() if lineno <= len(self.lines) else ''
        # Build context string
        context = ".".join(self.context_stack) if self.context_stack else '<module>'
        message = f"{self.filename}:{lineno} [{context}] variable '{varname}' {reason}: '{snippet}'"
        self.issues.append(message)

    def visit_FunctionDef(self, node):
        self.context_stack.append(f"func {node.name}")
        self.generic_visit(node)
        self.context_stack.pop()

    def visit_ClassDef(self, node):
        self.context_stack.append(f"class {node.name}")
        self.generic_visit(node)
        self.context_stack.pop()

    def visit_Assign(self, node):
        # Check each assignment target
        for target in node.targets:
            if isinstance(target, ast.Name) and self.PASSWORD_VAR_PATTERN.search(target.id):
                # Check for literal string
                val = node.value
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    self.report(node.lineno, target.id, 'assigned a hard-coded string literal')
                # Check f-strings with embedded literals
                elif isinstance(val, ast.JoinedStr):
                    for part in val.values:
                        if isinstance(part, ast.Constant) and isinstance(part.value, str) and part.value.strip():
                            self.report(node.lineno, target.id, 'assigned an f-string containing a literal')
                            break
        self.generic_visit(node)

    def visit_Call(self, node):
        # Detect print() or write() usage of password vars
        is_print = isinstance(node.func, ast.Name) and node.func.id == 'print'
        is_attr  = isinstance(node.func, ast.Attribute) and node.func.attr in ('print', 'write')
        if is_print or is_attr:
            func_name = node.func.id if is_print else node.func.attr
            for arg in node.args:
                if isinstance(arg, ast.Name) and self.PASSWORD_VAR_PATTERN.search(arg.id):
                    self.report(node.lineno, arg.id, f"passed to {func_name}()")
        self.generic_visit(node)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.py>")
        sys.exit(1)

    checker = PlaintextPasswordChecker(sys.argv[1])
    tree = ast.parse(open(sys.argv[1], 'r', encoding='utf-8').read(), sys.argv[1])
    checker.visit(tree)
    for issue in checker.issues:
        print(issue)
