import os
import sys
import argparse
import pkgutil
import importlib
import json

def discover_checkers():
    # Find and return all Checker classes in this package
    checkers = []
    pkg = __package__  # e.g. 'scripts.passwords'
    pkgpath = os.path.dirname(__file__)
    for _, module_name, _ in pkgutil.iter_modules([pkgpath]):
        if module_name.startswith("detect_") and module_name.endswith("_misuse"):
            module = importlib.import_module(f"{pkg}.{module_name}")
            for attr in dir(module):
                if attr.endswith("Checker"):
                    cls = getattr(module, attr)
                    if isinstance(cls, type):
                        checkers.append(cls)
    return checkers

def scan_py_files(path):
    # Yield all .py files under `path` (file or directory)
    if os.path.isfile(path) and path.endswith(".py"):
        yield path
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for fname in files:
                if fname.endswith(".py"):
                    yield os.path.join(root, fname)

def analyze_file(file_path, checkers, verbose=False):
    issues = []
    for Checker in checkers:
        checker = Checker(file_path)
        try:
            found = checker.analyze()
        except Exception as e:
            # If a checker itself errors out, report it rather than crash
            issues.append((file_path, 0, f"Checker {Checker.__name__} crashed: {e}"))
            continue
        for lineno, msg in found:
            issues.append((file_path, lineno, msg))
    if verbose and not issues:
        print(f"OK: {file_path}")
    return issues

def main():
    parser = argparse.ArgumentParser(
        description="Static analysis for crypto-misuse detectors"
    )
    parser.add_argument("path", help="File or directory to analyze")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Only show issues (suppress OK messages)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show OK messages for files with no issues"
    )
    args = parser.parse_args()

    checkers = discover_checkers()
    if not checkers:
        print("No misuse checkers found.")
        sys.exit(2)

    all_issues = []
    for file_path in scan_py_files(args.path):
        issues = analyze_file(file_path, checkers, verbose=args.verbose)
        all_issues.extend(issues)

    if args.format == "json":
        output = []
        for f, lineno, msg in all_issues:
            output.append({"file": f, "line": lineno, "message": msg})
        print(json.dumps(output, indent=2))
    else:
        if not all_issues:
            print("No cryptographic misuse detected.")
        else:
            for f, lineno, msg in sorted(all_issues):
                print(f"{f}:{lineno}: {msg}")

    # Exit non-zero if any issues were found
    sys.exit(1 if all_issues else 0)

if __name__ == "__main__":
    main()
