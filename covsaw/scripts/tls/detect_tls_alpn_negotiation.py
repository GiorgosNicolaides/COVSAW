"""
ALPN/NPN negotiation checker for TLS package.
"""
import socket
import ssl
from covsaw.scripts.tls.tls_base import TLSChecker

class ALPNNegotiationChecker(TLSChecker):
    """
    Checks that the server advertises and negotiates ALPN (e.g., h2 or http/1.1).
    """
    NAME     = "no_alpn"
    CWECODE  = "CWE-300"
    SEVERITY = "MEDIUM"

    def run_check(self):
        issues = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        # advertise HTTP/1.1 and HTTP/2
        ctx.set_alpn_protocols(['h2', 'http/1.1'])

        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                proto = ssock.selected_alpn_protocol()
                if proto is None:
                    issues.append((self.NAME, 'Server did not negotiate ALPN protocol'))
        return issues

    def summary(self):
        return ('ok', 'ALPN negotiation supported')
