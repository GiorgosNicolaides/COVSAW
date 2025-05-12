# detect_tls_certificate_transparency.py
"""
Certificate Transparency (SCT) checker for TLS package.
"""
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from covsaw.scripts.tls.tls_base import TLSChecker

class CertificateTransparencyChecker(TLSChecker):
    """
    Verifies that the leaf certificate contains Signed Certificate Timestamps (SCTs)
    as per RFC 6962 (Certificate Transparency).
    """
    NAME = "no_ct_scts"
    CWECODE = "CWE-346"
    SEVERITY = "MEDIUM"

    def run_check(self):
        issues = []
        # After initialization, self.leaf is loaded
        try:
            # Try to retrieve SCT list extension
            ext = self.leaf.extensions.get_extension_for_oid(
                ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS
            )
        except x509.ExtensionNotFound:
            issues.append((self.NAME, "Certificate is missing SCT list (Certificate Transparency not enforced)"))
            return issues
        # SCT extension present; ensure list is non-empty
        sct_list = ext.value
        if not getattr(sct_list, 'value', None):
            issues.append((self.NAME, "SCT list extension contains no timestamps"))
        return issues

    def summary(self):
        return ('ok', 'Certificate contains Signed Certificate Timestamps (SCTs)')
