#!/usr/bin/env python3
import os
import sys
import json
import argparse
import importlib.util
from urllib.parse import urlparse

# Base class for all checks
from covsaw.scripts.tls.tls_base import TLSChecker

def discover_checkers():
    """
    Discover all TLSChecker subclasses in this directory.
    Skips tls_base.py and this runner itself.
    """
    basedir = os.path.dirname(__file__)
    checkers = []
    for fn in os.listdir(basedir):
        # only .py modules
        if not fn.endswith('.py'):
            continue
        # skip the base class and runner
        if fn in ('tls_base.py', os.path.basename(__file__)):
            continue
        # only include files starting with tls_ or detect_tls_
        if not (fn.startswith('tls_') or fn.startswith('detect_tls_')):
            continue

        path = os.path.join(basedir, fn)
        try:
            spec = importlib.util.spec_from_file_location(fn[:-3], path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception:
            # broken checker: skip
            continue

        # collect any TLSChecker subclasses (except the base)
        for attr in dir(module):
            cls = getattr(module, attr)
            if isinstance(cls, type) and issubclass(cls, TLSChecker) and cls is not TLSChecker:
                checkers.append(cls)

    return checkers


def main():
    parser = argparse.ArgumentParser(description="TLS audit runner")
    parser.add_argument('host', help="Hostname or URL to audit")
    parser.add_argument('-p','--port',     type=int, default=None,    help="TCP port")
    parser.add_argument('-t','--timeout',  type=int, default=5,       help="Connection timeout (s)")
    parser.add_argument('-c','--trusted-ca',                help="Path to trusted CA file")
    parser.add_argument('-f','--format',   choices=['text','json'], default='text', help="Output format")
    args = parser.parse_args()

    # normalize host & port
    parsed = urlparse(args.host if '://' in args.host else '//' + args.host)
    host = parsed.hostname or args.host
    port = args.port or (parsed.port or 443)

    # discover all checkers
    checker_classes = discover_checkers()
    if not checker_classes:
        print("No TLS checkers found.", file=sys.stderr)
        sys.exit(2)

    all_results = []
    # Execute each check and collect results
    for Checker in checker_classes:
        inst = Checker(host, port=port, timeout=args.timeout, trusted_ca_file=args.trusted_ca)
        for name, code, msg in inst.report():
            result = {'check': name, 'code': code, 'message': msg}
            all_results.append(result)
            if args.format == 'text':
                print(f"[{name}] {code}: {msg}")

    # JSON output
    if args.format == 'json':
        output = {
            'host':    host,
            'port':    port,
            'results': all_results
        }
        print(json.dumps(output, indent=2))

    # determine exit code: any non-ok result is failure
    exit_code = 0
    for r in all_results:
        if r['code'] != 'ok':
            exit_code = 1
            break

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
