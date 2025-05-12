# detect_tls_chain_depth_and_path_constraints.py
"""
Certificate Chain Depth & Path Constraints checker for TLS package.
"""
import socket
import ssl
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from covsaw.scripts.tls.tls_base import TLSChecker

class ChainDepthPathConstraintChecker(TLSChecker):
    """
    Ensures certificate chain depth is within limits and intermediates have
    proper BasicConstraints with path_length constraints.
    """
    NAME     = "chain_depth_or_path_constraints"
    CWECODE  = "CWE-295"
    SEVERITY = "MEDIUM"

    def run_check(self):
        issues = []
        chain = self.cert_chain
        # 1. Check chain length
        max_depth = 5
        if len(chain) > max_depth:
            issues.append(("chain_too_long",
                           f"Certificate chain depth {len(chain)} exceeds maximum {max_depth}"))
        # 2. Check each intermediate for BasicConstraints
        for idx, cert in enumerate(chain[1:], start=1):  # skip leaf at index 0
            issuer = cert.issuer.rfc4514_string()
            try:
                ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            except x509.ExtensionNotFound:
                issues.append(("missing_basic_constraints",
                               f"Intermediate #{idx} ({issuer}) missing BasicConstraints extension"))
                continue
            bc = ext.value
            # Must be a CA
            if not bc.ca:
                issues.append(("invalid_basic_constraints_ca",
                               f"Intermediate #{idx} ({issuer}) has CA=False in BasicConstraints"))
            # Path length constraint must be present and non-negative
            if bc.path_length is None:
                issues.append(("missing_pathlen",
                               f"Intermediate #{idx} ({issuer}) missing path_length constraint"))
        return issues

    def summary(self):
        return ('ok', 'Certificate chain depth and path constraints are acceptable.')
