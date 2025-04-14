import os
from detect_ecb_des import ECBAndDESChecker
from detect_xor_encryption import XORBasedEncryptionChecker
from detect_hardcoded_keys import HardcodedKeyChecker
from detect_weak_iv import WeakIVChecker

def analyze_file(file_path):
    if not os.path.isfile(file_path):
        print(f"Error: {file_path} does not exist.")
        return

    print(f"\n[+] Analyzing: {file_path}")

    all_issues = []

    # Run each checker
    checkers = [
        ECBAndDESChecker(file_path),
        XORBasedEncryptionChecker(file_path),
        HardcodedKeyChecker(file_path),
        WeakIVChecker(file_path)
    ]

    for checker in checkers:
        issues = checker.analyze()
        all_issues.extend(issues)

    if not all_issues:
        print("No symmetric encryption issues found.")
    else:
        print("Symmetric encryption issues found:")
        for line, message in sorted(all_issues, key=lambda x: x[0]):
            print(f"Line {line}: {message}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python symmetric_analysis_runner.py <file_to_check.py>")
        sys.exit(1)

    analyze_file(sys.argv[1])
