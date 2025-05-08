import ast
import sys
import re

class InsecureStorageChecker(ast.NodeVisitor):
    """
    Detects insecure handling of sensitive data, including prints, logs, file writes,
    subprocess calls, environment leaks, and clipboard usage.
    """
    SECRET_VAR_PATTERN = re.compile(r'pass(word)?|token|secret|key', re.IGNORECASE)
    LOGGING_FUNCS = {'debug', 'info', 'warning', 'error', 'critical', 'exception'}
    SUBPROCESS_FUNCS = {'run', 'Popen', 'call', 'check_output', 'system'}

    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'r', encoding='utf-8') as f:
            self.lines = f.readlines()
        self.issues = []
        self.with_files = set()

    def report(self, lineno, message, cwe=None, severity='medium'):
        snippet = self.lines[lineno - 1].rstrip() if lineno <= len(self.lines) else ''
        parts = []
        if cwe:
            parts.append(f"CWE: {cwe}")
        if severity:
            parts.append(f"Severity: {severity}")
        meta = f" [{' | '.join(parts)}]" if parts else ''
        self.issues.append((lineno, f"{message}{meta}: '{snippet}'"))

    def visit_Call(self, node):
        # print(secret)
        if isinstance(node.func, ast.Name) and node.func.id == 'print':
            for arg in node.args:
                if isinstance(arg, ast.Name) and self.SECRET_VAR_PATTERN.search(arg.id):
                    self.report(node.lineno,
                                f"Printing sensitive variable '{arg.id}'",
                                'CWE-319','medium')
        # logger.info(secret)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            cname = node.func.value.id
            mname = node.func.attr
            if mname in self.LOGGING_FUNCS and cname in ('logger', 'logging'):
                for arg in node.args:
                    if isinstance(arg, ast.Name) and self.SECRET_VAR_PATTERN.search(arg.id):
                        self.report(node.lineno,
                                    f"Logging sensitive variable '{arg.id}'",
                                    'CWE-319','medium')
        # file.write(secret)
        if isinstance(node.func, ast.Attribute) and node.func.attr in ('write','writelines'):
            owner = node.func.value
            if isinstance(owner, ast.Name) and owner.id in self.with_files:
                for arg in node.args:
                    if isinstance(arg, ast.Name) and self.SECRET_VAR_PATTERN.search(arg.id):
                        self.report(node.lineno,
                                    f"Writing sensitive variable '{arg.id}' to file",
                                    'CWE-312','high')
        # open(...).write() without context manager
        if isinstance(node.func, ast.Attribute) and node.func.attr in ('write','writelines'):
            if (isinstance(node.func.value, ast.Call)
                    and isinstance(node.func.value.func, ast.Name)
                    and node.func.value.func.id == 'open'):
                for arg in node.args:
                    if isinstance(arg, ast.Name) and self.SECRET_VAR_PATTERN.search(arg.id):
                        self.report(node.lineno,
                                    f"Writing sensitive variable '{arg.id}' with open() call",
                                    'CWE-312','high')
        # subprocess calls with secret in args
        if isinstance(node.func, ast.Attribute):
            if ((isinstance(node.func.value, ast.Name)
                    and node.func.value.id == 'subprocess'
                    and node.func.attr in self.SUBPROCESS_FUNCS)
                or (isinstance(node.func.value, ast.Name)
                    and node.func.value.id == 'os'
                    and node.func.attr == 'system')):
                for arg in node.args:
                    # direct name
                    if isinstance(arg, ast.Name) and self.SECRET_VAR_PATTERN.search(arg.id):
                        self.report(node.lineno,
                                    f"Passing sensitive variable '{arg.id}' to system call",
                                    'CWE-78','high')
                    # list/tuple unpack
                    elif isinstance(arg, (ast.List, ast.Tuple)):
                        for el in arg.elts:
                            if isinstance(el, ast.Name) and self.SECRET_VAR_PATTERN.search(el.id):
                                self.report(node.lineno,
                                            f"Passing sensitive variable '{el.id}' to system call",
                                            'CWE-78','high')
        # pyperclip.copy(secret)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == 'pyperclip' and node.func.attr == 'copy':
                for arg in node.args:
                    if isinstance(arg, ast.Name) and self.SECRET_VAR_PATTERN.search(arg.id):
                        self.report(node.lineno,
                                    f"Copying sensitive variable '{arg.id}' to clipboard",
                                    'CWE-200','medium')
        self.generic_visit(node)

    def visit_With(self, node):
        for item in node.items:
            ctx = item.context_expr
            if isinstance(ctx, ast.Call) and isinstance(ctx.func, ast.Name) and ctx.func.id == 'open':
                if isinstance(item.optional_vars, ast.Name):
                    self.with_files.add(item.optional_vars.id)
        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Subscript):
                val = target.value
                if isinstance(val, ast.Attribute) and isinstance(val.value, ast.Name):
                    if val.value.id == 'os' and val.attr == 'environ':
                        if isinstance(node.value, ast.Name) and self.SECRET_VAR_PATTERN.search(node.value.id):
                            self.report(node.lineno,
                                        f"Storing sensitive variable '{node.value.id}' in environment",
                                        'CWE-532','high')
        self.generic_visit(node)

    def analyze(self):
        with open(self.filename, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=self.filename)
        self.visit(tree)
        return self.issues

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <file_to_check.py>")
        sys.exit(1)
    checker = InsecureStorageChecker(sys.argv[1])
    issues = checker.analyze()
    if not issues:
        print("No insecure storage detected.")
    else:
        print("Insecure storage issues detected:")
        for lineno, issue in issues:
            print(f"Line {lineno}: {issue}")
