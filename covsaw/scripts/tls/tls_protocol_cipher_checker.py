from covsaw.scripts.tls.tls_base import TLSChecker

class TLSProtocolCipherChecker(TLSChecker):
    NAME = 'protocol-cipher'

    def run_check(self):
        issues = []
        version, cipher, bits = self.negotiated_cipher

        # 1) TLS version
        if version in {'SSLv2','SSLv3','TLSv1','TLSv1.1'}:
            issues.append(('old_tls_version', f"Server uses {version}"))

        # 2) Weak ciphers
        for w in ('RC4','3DES','NULL','DES'):
            if w in cipher:
                issues.append(('weak_cipher', f"Cipher suite {cipher}"))

        # 3) Forward secrecy
        # TLS 1.3 always FS; earlier must contain DHE/ECDHE
        if '1.3' not in version:
            if not any(k in cipher for k in ('DHE','ECDHE')):
                issues.append(('no_forward_secrecy', f"{cipher} lacks FS"))

        return issues

    def summary(self):
        version, cipher, bits = self.negotiated_cipher
        return ('ok', f"Negotiated {version} with {cipher} ({bits} bits)")
