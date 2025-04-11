import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import requests
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus, ExtensionOID
import json
import csv
import os

class TLSCertificateChecker:
    def __init__(self, hostname, port=443, trusted_ca_file="greek_trusted_cas.txt"):
        self.hostname = hostname
        self.port = port
        self.trusted_ca_file = trusted_ca_file
        self.cert = None
        self.pem_cert = None
        self.issuer = None
        self.subject = None

    def fetch_certificate(self):
        """Fetch the PEM-formatted certificate from the server."""
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=self.hostname) as conn:
            conn.settimeout(5)
            conn.connect((self.hostname, self.port))
            der_cert = conn.getpeercert(binary_form=True)
            self.pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
            self.cert = x509.load_pem_x509_certificate(self.pem_cert.encode(), default_backend())
            self.issuer = self.cert.issuer.rfc4514_string()
            self.subject = self.cert.subject.rfc4514_string()

    def check_expiry(self):
        """Check if the certificate is expired or expiring soon."""
        not_after = self.cert.not_valid_after
        now = datetime.utcnow()
        days_remaining = (not_after - now).days

        if now > not_after:
            return False, f"Certificate expired on {not_after}"
        elif days_remaining < 30:
            return True, f"Certificate expires soon: {not_after} ({days_remaining} days left)"
        return True, f"Certificate is valid until {not_after}"

    def is_self_signed(self):
        """Check if the certificate is self-signed."""
        return self.cert.issuer == self.cert.subject

    def check_hostname(self):
        """Verify the certificate matches the hostname."""
        try:
            alt_names = []
            try:
                ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                alt_names = ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass

            if self.hostname in alt_names:
                return True, f"Hostname {self.hostname} matches SAN entry."
            
            common_names = [
                attr.value for attr in self.cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            ]
            if self.hostname in common_names:
                return True, f"Hostname {self.hostname} matches CN field."

            return False, f"Hostname {self.hostname} does not match CN or SAN."
        except Exception as e:
            return False, f"Hostname validation failed: {e}"

    def load_trusted_cas(self):
        """Load trusted CA names from file."""
        with open(self.trusted_ca_file, encoding='utf-8') as f:
            return [line.strip().lower() for line in f if line.strip()]

    def is_issuer_trusted(self):
        """Check if the issuer matches any entry in the trusted CA list."""
        trusted_cas = self.load_trusted_cas()
        return any(ca in self.issuer.lower() for ca in trusted_cas)

        
    def check_revocation(self):
        """
        Perform OCSP revocation checking using the certificate's AIA extension and issuer certificate.
        Returns a tuple (status: bool or None, message: str)
        """
        try:
        # Step 1: Extract OCSP responder URL from the AIA extension
            try:
                aia = self.cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            except x509.ExtensionNotFound:
                return None, "No Authority Information Access (AIA) extension found in certificate."

            ocsp_url = None
            for access_desc in aia:
                if access_desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":
                    ocsp_url = access_desc.access_location.value
                    break
            if not ocsp_url:
                return None, "No OCSP responder URL found in certificate."

            # Step 2: Retrieve the full certificate chain
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=self.hostname) as conn:
                conn.settimeout(5)
                conn.connect((self.hostname, self.port))
                chain = conn.getpeercert(binary_form=True)
                der_chain = conn.getpeercertchain()

            if len(der_chain) < 2:
                return None, "Issuer certificate not provided in server's certificate chain."

            # Step 3: Parse issuer certificate
            issuer_cert = x509.load_der_x509_certificate(der_chain[1], default_backend())

            # Step 4: Build OCSP request
            builder = OCSPRequestBuilder()
            builder = builder.add_certificate(self.cert, issuer_cert, self.cert.signature_hash_algorithm)
            req = builder.build()

            headers = {'Content-Type': 'application/ocsp-request', 'Accept': 'application/ocsp-response'}
            response = requests.post(ocsp_url, data=req.public_bytes(), headers=headers, timeout=5)

            if response.status_code != 200:
                return None, f"OCSP responder returned HTTP {response.status_code}"

            ocsp_response = x509.ocsp.load_der_ocsp_response(response.content)

            # Step 5: Interpret the OCSP response
            if ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
                return None, f"OCSP responder returned an unsuccessful status: {ocsp_response.response_status}"

            cert_status = ocsp_response.certificate_status

            if cert_status == x509.ocsp.OCSPCertStatus.REVOKED:
                return False, "Certificate has been revoked (OCSP)."
            elif cert_status == x509.ocsp.OCSPCertStatus.GOOD:
                return True, "Certificate is valid (OCSP)."
            elif cert_status == x509.ocsp.OCSPCertStatus.UNKNOWN:
                return None, "Certificate status is unknown (OCSP)."
            else:
                return None, "Unexpected OCSP certificate status."

        except Exception as e:
            return None, f"OCSP check failed: {e}"

    def run_all_checks(self):
        """Run all checks and return results as a dict."""
        results = {}
        self.fetch_certificate()

        results['issuer'] = self.issuer
        results['subject'] = self.subject

        valid_expiry, expiry_msg = self.check_expiry()
        results['expiry'] = expiry_msg

        results['self_signed'] = "Not self-signed" if not self.is_self_signed() else "Self-signed certificate"

        hostname_ok, hostname_msg = self.check_hostname()
        results['hostname'] = hostname_msg

        results['trusted_issuer'] = (
            "Issued by trusted Greek CA" if self.is_issuer_trusted()
            else "Not issued by a trusted Greek CA"
        )

        _, revocation_msg = self.check_revocation()
        results['revocation'] = revocation_msg

        key_ok, key_msg = self.check_key_strength()
        results['key_strength'] = key_msg

        sig_ok, sig_msg = self.check_signature_algorithm()
        results['signature_algorithm'] = sig_msg

        return results


    def export_results(self, results: dict, output_path=None, format="json"):
        """
        Export the certificate check results to a JSON or CSV file.
        
        :param results: The dictionary returned from run_all_checks()
        :param output_path: Optional full path to save file. If None, will use hostname_timestamp.ext
        :param format: 'json' or 'csv'
        """
        format = format.lower()
        if format not in {"json", "csv"}:
            raise ValueError("Unsupported format. Use 'json' or 'csv'.")

        if output_path is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_path = f"{self.hostname}_{timestamp}.{format}"

        if format == "json":
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
        elif format == "csv":
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Check", "Result"])
                for key, value in results.items():
                    writer.writerow([key, value])

    def check_key_strength(self):
        """
        Check if the public key is strong enough (RSA >= 2048 bits, ECDSA >= 256 bits).
        """
        key = self.cert.public_key()

        if hasattr(key, "key_size"):  # RSA or DSA
            if key.key_size < 2048:
                return False, f"Key size too small: {key.key_size} bits (expected >= 2048 bits)"
            return True, f"Key size is sufficient: {key.key_size} bits"
        
        elif hasattr(key, "curve"):  # Elliptic Curve
            curve_name = key.curve.name
            if "256" not in curve_name and "384" not in curve_name and "521" not in curve_name:
                return False, f"Curve {curve_name} may be too weak (expected at least secp256r1)"
            return True, f"Curve {curve_name} is acceptable"
        
        else:
            return None, "Unknown key type. Unable to evaluate strength."

    def check_signature_algorithm(self):
        """
        Check if the certificate uses a strong signature algorithm.
        """
        sig_algo = self.cert.signature_hash_algorithm.name.lower()
        if "md5" in sig_algo or "sha1" in sig_algo:
            return False, f"Weak signature algorithm used: {sig_algo}"
        return True, f"Signature algorithm is strong: {sig_algo}"
