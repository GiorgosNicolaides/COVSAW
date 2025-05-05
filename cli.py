import argparse
from ascii_art import print_banner

# TLS
from scripts.tls.tls_runner import analyze_tls

# Passwords
from scripts.passwords.password_storage_runner import analyze_file as analyze_passwords

# Signatures
from scripts.signatures.signature_scheme_runner import analyze_file as analyze_signatures

# Symmetric crypto
from scripts.symmetric.symmetric_analysis_runner import analyze_file as analyze_symmetric

# Protocol misuse
from scripts.misuse.misuse_runner import analyze_file as analyze_misuse

# Key management
from scripts.key.key_management_runner import analyze_file as analyze_key_mgmt

# PKI / Certificate Transparency
from scripts.pki.pki_runner import analyze_pki


def main():
    parser = argparse.ArgumentParser(
        description="CovS.A.W. — Cryptographic Vulnerability Static Analysis Workshop"
    )
    parser.add_argument("--tls", metavar="HOST", help="Run TLS analysis on a live host")
    parser.add_argument("--pki", metavar="HOST", help="Check PKI chain & CT logs")
    parser.add_argument("--passwords", metavar="FILE", help="Analyze password storage")
    parser.add_argument("--signatures", metavar="FILE", help="Analyze digital signature usage")
    parser.add_argument("--symmetric", metavar="FILE", help="Analyze symmetric encryption practices")
    parser.add_argument("--misuse", metavar="FILE", help="Detect protocol misuse")
    parser.add_argument("--keymgmt", metavar="FILE", help="Analyze key management and secrets")
    parser.add_argument("--all", metavar="FILE", help="Run all static checks on one Python file")

    args = parser.parse_args()

    print_banner()

    if args.tls:
        analyze_tls(args.tls)

    if args.pki:
        analyze_pki(args.pki)

    if args.passwords:
        analyze_passwords(args.passwords)

    if args.signatures:
        analyze_signatures(args.signatures)

    if args.symmetric:
        analyze_symmetric(args.symmetric)

    if args.misuse:
        analyze_misuse(args.misuse)

    if args.keymgmt:
        analyze_key_mgmt(args.keymgmt)

    if args.all:
        print(f"\n🔎 Running full audit on: {args.all}")
        analyze_passwords(args.all)
        analyze_signatures(args.all)
        analyze_symmetric(args.all)
        analyze_misuse(args.all)
        analyze_key_mgmt(args.all)


if __name__ == "__main__":
    main()
