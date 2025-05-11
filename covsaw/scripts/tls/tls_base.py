import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class TLSChecker:
    """
    Base class for TLS checkers. Establishes a TLS connection, retrieves
    the leaf certificate, and records the negotiated cipher.
    Subclasses implement run_check() to return a list of (code, message).
    And summary() to describe the successful case.
    """
    NAME = 'tls-checker'

    def __init__(self, host, port=443, timeout=5, trusted_ca_file=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.trusted_ca_file = trusted_ca_file
        self.cert_chain = []           # list of x509.Certificate objects
        self.negotiated_cipher = None  # tuple (version, cipher_name, bits)
        self._fetch_chain()

    def _fetch_chain(self):
        ctx = ssl.create_default_context()
        if self.trusted_ca_file:
            ctx.load_verify_locations(self.trusted_ca_file)
        ctx.check_hostname  = False
        ctx.verify_mode     = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der, default_backend())
                self.cert_chain.append(cert)
                self.negotiated_cipher = ssock.cipher()

    @property
    def leaf(self):
        return self.cert_chain[0] if self.cert_chain else None

    def run_check(self):
        """
        Override in subclasses: return list of (code, message) tuples for failures.
        """
        raise NotImplementedError

    def summary(self):
        """
        Override in subclasses: return (code, message) for success.
        Default: generic OK.
        """
        return ('ok', 'Check passed with no detected issues')

    def report(self):
        """
        Execute run_check(). If failures found, return them.
        Otherwise call summary() and return a single ok entry.
        """
        failures = self.run_check()
        out = []
        if failures:
            for code, msg in failures:
                out.append((self.NAME, code, msg))
        else:
            code, msg = self.summary()
            out.append((self.NAME, code, msg))
        return out
