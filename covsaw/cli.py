#!/usr/bin/env python3
import argparse
import subprocess
import sys
from covsaw.ascii_art import print_banner

# Use the same Python interpreter in this venv
PYTHON = sys.executable

def run_cmd(cmd):
    print(f"→ Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"[!] Command exited with code {result.returncode}\n", file=sys.stderr)


def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="COVSAW Multi-Suite Cryptography Audit CLI"
    )
    parser.add_argument('target',
        help='File/directory path (for static scans) or hostname/URL (for TLS)')
    parser.add_argument('--format',
        choices=['text','json'], default='text',
        help='Output format for tls runner only')
    parser.add_argument('-t','--tls',       action='store_true', help='Run TLS audit')
    parser.add_argument('-p','--passwords', action='store_true', help='Run password-storage checks')
    parser.add_argument('-s','--signatures',action='store_true', help='Run signature-scheme checks')
    parser.add_argument('-y','--symmetric', action='store_true', help='Run symmetric-crypto checks')
    parser.add_argument('-k','--key',   action='store_true', help='Run key-management checks')
    parser.add_argument('-m','--misuse', action='store_true', help='Run misuse checks')
    parser.add_argument('-a','--all',       action='store_true', help='Run all modules')
    args = parser.parse_args()

    # Determine which modules to run, invoking them as package modules
    to_run = []
    if args.tls:
        cmd = [PYTHON, '-m', 'covsaw.scripts.tls.tls_runner', args.target, '-f', args.format]
        to_run.append(("🔒 TLS Audit", cmd))

    if args.all or args.passwords:
        to_run.append(("🔐 Password-Storage Audit", [
            PYTHON, '-m', 'covsaw.scripts.passwords.password_storage_runner',
            args.target
        ]))

    if args.all or args.signatures:
        to_run.append(("✍️  Signature-Scheme Audit", [
            PYTHON, '-m', 'covsaw.scripts.signatures.signature_scheme_runner',
            '--format', args.format, args.target
        ]))

    if args.all or args.symmetric:
        to_run.append(("🔑 Symmetric-Crypto Audit", [
            PYTHON, '-m', 'covsaw.scripts.symmetric.symmetric_analysis_runner',
            '--format', args.format, args.target
        ]))

    if args.all or args.key:
        to_run.append(("🔐 Key-Management Audit", [
            PYTHON, '-m', 'covsaw.scripts.key.key_management_runner',
            '--format', args.format, args.target
        ]))
    if args.all or args.misuse:
        to_run.append(("⚠️  Misuse Audit", [
            PYTHON, '-m', 'covsaw.scripts.misuse.misuse_runner',
            '--format', args.format, args.target
        ]))

    if not to_run:
        sys.stderr.write("No modules selected. Use --help for options.\n")
        sys.exit(1)

    # Run each selected module
    for title, cmd in to_run:
        print(f"\n{title} on {args.target}")
        run_cmd(cmd)


if __name__ == "__main__":
    main()