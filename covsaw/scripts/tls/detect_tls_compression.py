"""
TLS compression (CRIME) checker for TLS package.
"""
import socket
import ssl
from covsaw.scripts.tls.tls_base import TLSChecker

class TLSCompressionChecker(TLSChecker):
    """
    Detects if the server supports TLS-level compression (CRIME risk).
    """
    NAME     = "tls_compression_enabled"
    CWECODE  = "CWE-400"
    SEVERITY = "HIGH"

    def run_check(self):
        issues = []
        # Create context with compression enabled
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.options |= 0  # no disable of compression

        # Enable compression (if supported by OpenSSL)
        try:
            ctx.options &= ~ssl.OP_NO_COMPRESSION
        except AttributeError:
            # older Python may not support OP_NO_COMPRESSION
            pass

        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                comp = ssock.compression()
                if comp is not None:
                    issues.append((self.NAME, f"Compression active: {comp}"))
        return issues

    def summary(self):
        return ('ok', 'TLS compression not enabled')

