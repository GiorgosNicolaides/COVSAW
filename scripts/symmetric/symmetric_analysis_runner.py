#!/usr/bin/env python3
"""
Symmetric Encryption Static Analysis Runner

Discovers all *Checker classes in this directory and runs them
on specified files or directories, reporting insecure symmetric encryption issues.
Supports text and JSON output and returns non-zero exit code on findings.
"""
import os
import sys
import json
import argparse
import importlib.util

def discover_checkers():
    """
    Dynamically load all Checker classes from detect_*.py modules in this directory.
    """
    checkers = []
    runner_dir = os.path.dirname(__file__)
    for fname in os.listdir(runner_dir):
        if not fname.startswith("detect_") or not fname.endswith(".py"):
            continue
        path = os.path.join(runner_dir, fname)
        spec = importlib.util.spec_from_file_location(fname[:-3], path)
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
    if os.path.isfile(path) and path.endswith('.py'):
        yield path
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in files:
                if f.endswith('.py'):
                    yield os.path.join(root, f)

def analyze_file(file_path, checker_classes, verbose=False):
    """
    Run all checker classes on a file, collecting issues.
    """
    issues = []
    for Checker in checker_classes:
        checker = Checker(file_path)
        try:
            found = checker.analyze()
        except Exception as e:
            issues.append((file_path, 0, f"⚠️ {Checker.NAME} crashed: {e}"))
            continue
        for lineno, msg in found:
            issues.append((file_path, lineno, f"[{Checker.NAME}] {msg}"))
    if verbose and not issues:
        print(f"✅ OK: {file_path}")
    return issues

def main():
    parser = argparse.ArgumentParser(
        description="Static analysis for insecure symmetric encryption patterns"
    )
    parser.add_argument(
        'path',
        help='File or directory to analyze'
    )
    parser.add_argument(
        '--format', '-f', choices=['text', 'json'], default='text',
        help='Output format'
    )
    parser.add_argument(
        '-q', '--quiet', action='store_true',
        help='Suppress OK messages'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Show OK messages for files without issues'
    )
    args = parser.parse_args()

    checker_classes = discover_checkers()
    if not checker_classes:
        print('No symmetric checkers found.')
        sys.exit(2)

    all_issues = []
    for file_path in scan_py_files(args.path):
        is_verbose = args.verbose and not args.quiet
        all_issues.extend(analyze_file(file_path, checker_classes, verbose=is_verbose))

    if args.format == 'json':
        output = []
        for f, ln, msg in all_issues:
            # Strip leading "[CheckerName] " from the message
            if msg.startswith('[') and '] ' in msg:
                _, rest = msg.split('] ', 1)
            else:
                rest = msg
            output.append({'file': f, 'line': ln, 'message': rest})
        print(json.dumps(output, indent=2))
    else:
        if not all_issues:
            print('No symmetric encryption issues detected.')
        else:
            for f, ln, msg in sorted(all_issues):
                print(f"{f}:{ln}: {msg}")

    sys.exit(1 if all_issues else 0)

if __name__ == '__main__':
    main()
