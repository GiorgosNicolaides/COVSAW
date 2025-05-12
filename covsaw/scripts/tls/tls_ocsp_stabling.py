# detect_tls_ocsp_stapling.py
"""
OCSP Stapling checker for TLS package.
"""
import ssl
from covsaw.scripts.tls.tls_base import TLSChecker


class OCSPStaplingChecker(TLSChecker):
    """
    Verifies that the server staples a valid OCSP response
    in its TLS handshake (RFC 6066 section 8).
    """
    NAME = "no_ocsp_stapling"
    CWECODE = "CWE-299"
    SEVERITY = "MEDIUM"

    def run_check(self):
        import socket, ssl
        # Re-establish a TLS connection to inspect ocsp_response
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    try:
                        stapled = ssock.ocsp_response()
                    except AttributeError:
                        return [("ocsp_not_supported",
                                 "OCSP stapling query not supported by client library")]
        except Exception as e:
            return [("ocsp_conn_error", f"Error connecting to server for OCSP check: {e}")]

        if stapled is None or len(stapled) == 0:
            return [(self.NAME, "Server did not staple an OCSP response")]

        # Optionally, further parse and validate `stapled` here
        return []  # OK

    def summary(self):
        return ("ok", "OCSP stapling is present.")
