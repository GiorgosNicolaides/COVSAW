#!/usr/bin/env python3
import os
import sys
import json
import argparse
import importlib.util
from urllib.parse import urlparse

def discover_checkers():
    base = os.path.dirname(__file__)
    checkers = []
    for fn in os.listdir(base):
        if fn.startswith('tls_') and fn.endswith('.py'):
            spec = importlib.util.spec_from_file_location(fn[:-3], os.path.join(base, fn))
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for attr in dir(mod):
                cls = getattr(mod, attr)
                if isinstance(cls, type) and issubclass(cls, TLSChecker) and cls is not TLSChecker:
                    checkers.append(cls)
    return checkers

def main():
    parser = argparse.ArgumentParser(description="TLS audit runner")
    parser.add_argument('host', help="Hostname or URL to audit")
    parser.add_argument('-p','--port',      type=int, default=None, help="TCP port")
    parser.add_argument('-t','--timeout',   type=int, default=5,   help="Timeout (s)")
    parser.add_argument('-c','--trusted-ca',           help="Trusted CA file")
    parser.add_argument('-f','--format',    choices=['text','json'], default='text')
    args = parser.parse_args()

    # normalize host & port
    parsed = urlparse(args.host if '://' in args.host else '//' + args.host)
    host = parsed.hostname or args.host
    port = args.port or (parsed.port or 443)

    checkers = discover_checkers()
    if not checkers:
        print("No TLS checkers found.", file=sys.stderr)
        sys.exit(2)

    results = []
    for C in checkers:
        inst  = C(host, port=port, timeout=args.timeout, trusted_ca_file=args.trusted_ca)
        for name, code, msg in inst.report():
            if args.format == 'text':
                print(f"[{name}] {code}: {msg}")
            else:
                results.append({'check': name, 'code': code, 'message': msg})

    if args.format == 'json':
        output = {'host': host, 'port': port, 'results': results}
        print(json.dumps(output, indent=2))

    # exit non-zero if any failure
    exit_code = 0
    for r in (results if args.format=='json' else []):
        if r['code'] != 'ok':
            exit_code = 1
            break
    if args.format=='text':
        # in text mode, look for any “[<checker>]” not ending in “ok:”
        for line in sys.stdout.getvalue().splitlines() if hasattr(sys.stdout,"getvalue") else []:
            if not line.endswith(":") and " code: ok" in line.lower():
                continue
            if "ok:" not in line:
                exit_code = 1
                break
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
