# detect_tls_session_resumption.py
"""
Session Resumption & Ticket Security checker for TLS package.
"""
import socket
import ssl
from covsaw.scripts.tls.tls_base import TLSChecker

class SessionResumptionChecker(TLSChecker):
    """
    Checks server TLS session resumption via tickets and lifetime hints.
    """
    NAME     = "weak_session_ticket"
    CWECODE  = "CWE-319"
    SEVERITY = "MEDIUM"

    def run_check(self):
        issues = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    sess = ssock.session()
        except Exception as e:
            return [("session_conn_error", f"Error connecting for session resumption check: {e}")]

        if sess is None:
            issues.append(("no_session_ticket", "Server did not issue a session ticket"))
            return issues

        # Check ticket lifetime hint
        lifetime = getattr(sess, "ticket_lifetime_hint", None)
        if lifetime is None:
            issues.append((self.NAME, "Server did not provide a session ticket lifetime hint"))
        else:
            # If lifetime hint exceeds 24 hours
            if lifetime > 24 * 3600:
                issues.append((self.NAME, f"Session ticket lifetime hint is too long: {lifetime} seconds"))

        return issues

    def summary(self):
        return ("ok", "Session resumption via ticket with acceptable lifetime hint")
