import os

from .detect_plaintext_passwords import PlaintextPasswordChecker
from .detect_weak_password_hashing import WeakPasswordHashingChecker
from .detect_missing_salt_or_kdf import MissingSaltOrKDFChecker

def analyze_file(file_path):
    if not os.path.isfile(file_path):
        print(f"Error: File not found: {file_path}")
        return

    print(f"\n[+] Analyzing password storage practices in: {file_path}")

    all_issues = []

    checkers = [
        PlaintextPasswordChecker(file_path),
        WeakPasswordHashingChecker(file_path),
        MissingSaltOrKDFChecker(file_path)
    ]

    for checker in checkers:
        issues = checker.analyze()
        all_issues.extend(issues)

    if not all_issues:
        print("✅ No password storage issues found.")
    else:
        print("⚠️  Password storage issues detected:")
        for line, issue in sorted(all_issues, key=lambda x: x[0]):
            print(f"Line {line}: {issue}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python password_storage_runner.py <file_to_check.py>")
        sys.exit(1)

    analyze_file(sys.argv[1])
