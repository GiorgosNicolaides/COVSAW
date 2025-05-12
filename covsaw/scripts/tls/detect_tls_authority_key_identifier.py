# detect_tls_authority_key_identifier.py
"""
Authority Key Identifier checker for TLS package.
"""
import socket
import ssl
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from covsaw.scripts.tls.tls_base import TLSChecker

class AuthorityKeyIdentifierChecker(TLSChecker):
    """
    Ensures all certificates in the chain include an AuthorityKeyIdentifier extension.
    """
    NAME     = "no_authority_key_id"
    CWECODE  = "CWE-327"
    SEVERITY = "MEDIUM"

    def run_check(self):
        issues = []
        # cert_chain includes the leaf at index 0 and intermediates thereafter
        for idx, cert in enumerate(self.cert_chain):
            try:
                cert.extensions.get_extension_for_oid(
                    ExtensionOID.AUTHORITY_KEY_IDENTIFIER
                )
            except x509.ExtensionNotFound:
                if idx == 0:
                    entity = "Leaf certificate"
                else:
                    entity = f"Intermediate #{idx}"
                issues.append((
                    self.NAME,
                    f"{entity} missing AuthorityKeyIdentifier extension"
                ))
        return issues

    def summary(self):
        return ("ok", "All certificates include AuthorityKeyIdentifier extension")
