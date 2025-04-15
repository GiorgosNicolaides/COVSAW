import os
from .detect_hardcoded_secrets import HardcodedSecretsChecker
from .detect_insecure_storage import InsecureStorageChecker

def analyze_file(file_path):
    if not os.path.isfile(file_path):
        print(f"Error: File not found: {file_path}")
        return

    print(f"\n[+] Analyzing file for key management issues: {file_path}")

    all_issues = []

    checkers = [
        HardcodedSecretsChecker(file_path),
        InsecureStorageChecker(file_path)
    ]

    for checker in checkers:
        issues = checker.analyze()
        all_issues.extend(issues)

    if not all_issues:
        print("No key management or secret handling issues found.")
    else:
        print("Issues detected:")
        for line, issue in sorted(all_issues, key=lambda x: x[0]):
            print(f"Line {line}: {issue}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python key_management_runner.py <file_to_check.py>")
        sys.exit(1)

    analyze_file(sys.argv[1])
