import os

from .detect_insecure_signature_algos import InsecureSignatureAlgoChecker
from .detect_missing_verification import MissingSignatureVerificationChecker
from .detect_nonconstant_compare import NonConstantSignatureCompareChecker

def analyze_file(file_path):
    if not os.path.isfile(file_path):
        print(f"Error: File not found: {file_path}")
        return

    print(f"\n[+] Analyzing digital signature scheme usage in: {file_path}")

    all_issues = []

    checkers = [
        InsecureSignatureAlgoChecker(file_path),
        MissingSignatureVerificationChecker(file_path),
        NonConstantSignatureCompareChecker(file_path)
    ]

    for checker in checkers:
        issues = checker.analyze()
        all_issues.extend(issues)

    if not all_issues:
        print("No digital signature implementation issues detected.")
    else:
        print("Digital signature issues detected:")
        for line, issue in sorted(all_issues, key=lambda x: x[0]):
            print(f"Line {line}: {issue}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python signature_scheme_runner.py <file_to_check.py>")
        sys.exit(1)

    analyze_file(sys.argv[1])
