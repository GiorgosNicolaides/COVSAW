import ssl
import socket
import idna
from cryptography import x509 # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus # type: ignore
from cryptography.x509.oid import ExtensionOID
import requests


class TLSRevocationChecker:
    def __init__(self, hostname, port=443):
        self.hostname = hostname
        self.port = port
        self.cert = None
        self.issuer_cert = None
        self.parsed_cert = None

    def _fetch_certificate_chain(self):
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=self.hostname)
        conn.settimeout(5)
        conn.connect((self.hostname, self.port))
        der_cert = conn.getpeercert(binary_form=True)
        self.parsed_cert = x509.load_der_x509_certificate(der_cert, default_backend())
        return self.parsed_cert

    def _get_ocsp_url(self, cert):
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            for access_desc in aia:
                if access_desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":  # OCSP
                    return access_desc.access_location.value
        except Exception:
            pass
        return None

    def _build_ocsp_request(self, cert, issuer_cert):
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer_cert, cert.signature_hash_algorithm)
        return builder.build()

    def _fetch_issuer_cert(self, cert):
        # This method assumes issuer cert is self-signed (works best with intermediate CA responses preloaded)
        return cert  # fallback (can be replaced with cache of known CAs if needed)

    def check_ocsp_revocation(self):
        cert = self._fetch_certificate_chain()
        issuer_cert = self._fetch_issuer_cert(cert)
        ocsp_url = self._get_ocsp_url(cert)

        if not ocsp_url:
            return False, "No OCSP responder URL found in certificate"

        try:
            req = self._build_ocsp_request(cert, issuer_cert)
            headers = {'Content-Type': 'application/ocsp-request', 'Accept': 'application/ocsp-response'}
            response = requests.post(ocsp_url, data=req.public_bytes(), headers=headers, timeout=5)

            if response.status_code != 200:
                return False, f"OCSP responder error: {response.status_code}"

            ocsp_resp = x509.ocsp.load_der_ocsp_response(response.content)

            if ocsp_resp.response_status != OCSPResponseStatus.SUCCESSFUL:
                return False, f"OCSP response unsuccessful: {ocsp_resp.response_status}"

            cert_status = ocsp_resp.certificate_status
            if cert_status == x509.ocsp.OCSPCertStatus.REVOKED:
                return False, f"Certificate has been revoked (OCSP)"
            elif cert_status == x509.ocsp.OCSPCertStatus.GOOD:
                return True, "Certificate is valid (OCSP)"
            else:
                return False, "OCSP returned unknown certificate status"
        except Exception as e:
            return False, f"OCSP check failed: {e}"


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python tls_revocation_checker.py <hostname>")
        sys.exit(1)

    checker = TLSRevocationChecker(sys.argv[1])
    success, message = checker.check_ocsp_revocation()
    status = "success" if success else "fail"
    print(f"{status} {message}")
