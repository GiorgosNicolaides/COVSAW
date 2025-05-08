"""
Signature Scheme Static Analysis Runner

Dynamically discovers all *Checker classes in this directory and runs them
on specified files or directories, reporting insecure signature issues.
Supports text and JSON output and returns non-zero exit code on findings.
"""
import os
import sys
import json
import argparse
import importlib.util


def discover_checkers():
    """
    Load all Checker classes from detect_*.py modules in this directory.
    """
    checkers = []
    runner_dir = os.path.dirname(__file__)
    for fname in os.listdir(runner_dir):
        if not fname.startswith("detect_") or not fname.endswith(".py"):
            continue
        path = os.path.join(runner_dir, fname)
        module_name = fname[:-3]
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for attr in dir(module):
            cls = getattr(module, attr)
            if isinstance(cls, type) and attr.endswith("Checker"):
                checkers.append(cls)
    return checkers


def scan_py_files(path):
    """
    Yield all .py file paths under the given path.
    """
    if os.path.isfile(path) and path.endswith(".py"):
        yield path
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for fname in files:
                if fname.endswith(".py"):
                    yield os.path.join(root, fname)


def analyze_file(path, checker_classes, verbose=False):
    """
    Run each checker on the given file and collect issues.
    """
    issues = []
    for Checker in checker_classes:
        checker = Checker(path)
        try:
            found = checker.analyze()
        except Exception as e:
            issues.append((path, 0, f"{Checker.__name__} crashed: {e}"))
            continue
        for lineno, msg in found:
            issues.append((path, lineno, f"[{Checker.NAME}] {msg}"))
    if verbose and not issues:
        print(f"OK: {path}")
    return issues


def main():
    parser = argparse.ArgumentParser(
        description="Static analysis for signature vulnerabilities"
    )
    parser.add_argument(
        "path",
        help="File or directory to analyze"
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress OK messages"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show OK messages for files without issues"
    )
    args = parser.parse_args()

    checker_classes = discover_checkers()
    if not checker_classes:
        print("No signature checkers found.")
        sys.exit(2)

    all_issues = []
    for file_path in scan_py_files(args.path):
        is_verbose = args.verbose and not args.quiet
        issues = analyze_file(file_path, checker_classes, verbose=is_verbose)
        all_issues.extend(issues)

    if args.format == "json":
        print(json.dumps([
            {"file": f, "line": ln, "message": msg}
            for f, ln, msg in all_issues
        ], indent=2))
    else:
        if not all_issues:
            print("No signature issues detected.")
        else:
            for f, ln, msg in sorted(all_issues):
                print(f"{f}:{ln}: {msg}")

    sys.exit(1 if all_issues else 0)


if __name__ == "__main__":
    main()
