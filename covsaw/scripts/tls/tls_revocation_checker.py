# tls_revocation_checker.py
from tls_base import TLSChecker
from cryptography import x509
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response, OCSPCertStatus
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
import requests

class TLSRevocationChecker(TLSChecker):
    """
    Performs OCSP-based revocation checking of the leaf certificate.
    """
    NAME = 'revocation'

    def run_check(self):
        issues = []
        cert = self.leaf

        # 1) Locate OCSP and CA Issuers URLs in AIA extension
        try:
            aia = cert.extensions.get_extension_for_class(
                x509.AuthorityInformationAccess
            ).value
            ocsp_urls = [
                desc.access_location.value
                for desc in aia
                if desc.access_method == AuthorityInformationAccessOID.OCSP
            ]
            issuer_urls = [
                desc.access_location.value
                for desc in aia
                if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            ]
        except x509.ExtensionNotFound:
            issues.append((
                'no_ocsp_extension',
                'No Authority Information Access extension (OCSP/CA Issuers)'
            ))
            return issues

        if not ocsp_urls:
            issues.append(('no_ocsp_url', 'No OCSP responder URL found in AIA'))
            return issues
        if not issuer_urls:
            issues.append(('no_ca_issuer_url', 'No CA Issuers URL found in AIA'))
            return issues

        # 2) Fetch the issuer certificate via CA Issuers URL
        try:
            res = requests.get(issuer_urls[0], timeout=self.timeout)
            res.raise_for_status()
            issuer_cert = x509.load_der_x509_certificate(res.content, default_backend())
        except Exception as e:
            issues.append((
                'issuer_fetch_error',
                f'Failed to fetch issuer certificate: {e}'
            ))
            return issues

        # 3) Build an OCSP request for the leaf certificate
        try:
            builder = OCSPRequestBuilder().add_certificate(
                cert,
                issuer_cert,
                hashes.SHA1()
            )
            req = builder.build()
            data = req.public_bytes(Encoding.DER)
        except Exception as e:
            issues.append((
                'ocsp_build_error',
                f'Failed to build OCSP request: {e}'
            ))
            return issues

        # 4) Send the OCSP request to the responder URL
        try:
            headers = {'Content-Type': 'application/ocsp-request'}
            resp = requests.post(
                ocsp_urls[0], data=data, headers=headers, timeout=self.timeout
            )
            resp.raise_for_status()
            ocsp_resp = load_der_ocsp_response(resp.content)
        except Exception as e:
            issues.append((
                'ocsp_request_error',
                f'OCSP request failed: {e}'
            ))
            return issues

        # 5) Interpret the OCSP response status
        status = ocsp_resp.certificate_status
        if status == OCSPCertStatus.REVOKED:
            issues.append((
                'revoked',
                'Certificate has been revoked according to OCSP'
            ))
        elif status == OCSPCertStatus.GOOD:
            # Save OCSP response for summary
            self._ocsp_response = ocsp_resp
        else:
            issues.append((
                'ocsp_unknown',
                'OCSP responder returned unknown status'
            ))

        return issues

    def summary(self):
        """
        Provides a detailed summary when OCSP status is good,
        including thisUpdate and nextUpdate timestamps.
        """
        if hasattr(self, '_ocsp_response'):
            resp = self._ocsp_response
            this_update = resp.this_update.isoformat()
            next_update = resp.next_update.isoformat() if resp.next_update else 'N/A'
            return (
                'ok',
                f"OCSP status: good (thisUpdate={this_update}, nextUpdate={next_update})"
            )
        return ('ok', 'OCSP status: good')