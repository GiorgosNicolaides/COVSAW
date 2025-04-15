import os
from .detect_custom_crypto_protocols import CustomCryptoProtocolChecker
from .detect_aead_misuse import AEADMisuseChecker
from .detect_hybrid_crypto_misuse import HybridCryptoMisuseChecker


def analyze_file(file_path):
    if not os.path.isfile(file_path):
        print(f"❌ Error: File not found — {file_path}")
        return

    print(f"\n🔍 Analyzing for cryptographic protocol misuse: {file_path}")
    all_issues = []

    checkers = [
        CustomCryptoProtocolChecker(file_path),
        AEADMisuseChecker(file_path),
        HybridCryptoMisuseChecker(file_path),
    ]

    for checker in checkers:
        issues = checker.analyze()
        all_issues.extend(issues)

    if not all_issues:
        print("No cryptographic misuse patterns detected.")
    else:
        print("Potential cryptographic protocol misuse detected:")
        for line, issue in sorted(all_issues, key=lambda x: x[0]):
            print(f"Line {line}: {issue}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python misuse_runner.py <file_to_check.py>")
        sys.exit(1)

    analyze_file(sys.argv[1])
