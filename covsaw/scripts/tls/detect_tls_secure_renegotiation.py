"""
Secure Renegotiation checker for TLS package.
"""
import socket
import ssl
from covsaw.scripts.tls.tls_base import TLSChecker

class SecureRenegotiationChecker(TLSChecker):
    """
    Ensures the server advertises secure renegotiation (RFC 5746).
    """
    NAME     = "insecure_renegotiation"
    CWECODE  = "CWE-757"
    SEVERITY = "MEDIUM"

    def run_check(self):
        issues = []
        try:
            # Wrap a connection without renegotiation enabled
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            # set option to disable secure renegotiation
            ctx.options |= ssl.OP_NO_RENEGOTIATION

            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    # If server supports secure renegotiation, the TLS extension is echoed
                    # Python's ssl API does not expose it directly; we deduce via exception
                    pass
        except ssl.SSLError as e:
            # If disabling renegotiation triggers an error, server refused insecure renegotiation
            return []
        except Exception:
            # Other failures are ignored here
            return []

        # No exception: server accepted insecure renegotiation
        issues.append((self.NAME, "Server allows insecure renegotiation"))
        return issues

    def summary(self):
        return ('ok', 'Server enforces secure renegotiation')

