import ssl
import socket
from cryptography import x509 # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore
from datetime import datetime
import os


class TLSCertificateChecker:
    def __init__(self, hostname, port=443, trusted_ca_path="greek_trusted_cas.txt"):
        self.hostname = hostname
        self.port = port
        self.trusted_ca_path = trusted_ca_path
        self.cert = None
        self.parsed_cert = None
        self.issuer = None
        self.subject = None

    def fetch_certificate(self):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.socket(), server_hostname=self.hostname
            ) as s:
                s.settimeout(5)
                s.connect((self.hostname, self.port))
                der_cert = s.getpeercert(binary_form=True)
                self.cert = der_cert
                self.parsed_cert = x509.load_der_x509_certificate(der_cert, default_backend())
                self.issuer = self.parsed_cert.issuer.rfc4514_string()
                self.subject = self.parsed_cert.subject.rfc4514_string()
        except Exception as e:
            raise RuntimeError(f"Failed to fetch certificate: {e}")

    def check_expiry(self):
        if not self.parsed_cert:
            return False, "Certificate not loaded"

        now = datetime.utcnow()
        not_after = self.parsed_cert.not_valid_after
        not_before = self.parsed_cert.not_valid_before

        if now < not_before:
            return False, "Certificate is not yet valid"
        elif now > not_after:
            return False, f"Certificate expired on {not_after}"
        elif (not_after - now).days <= 30:
            return True, f"Certificate expires soon: {not_after}"
        else:
            return True, f"Certificate is valid until {not_after}"

    def is_self_signed(self):
        if not self.parsed_cert:
            return False
        return self.parsed_cert.issuer == self.parsed_cert.subject

    def check_hostname(self):
        try:
            ssl.match_hostname({'subjectAltName': [
                ('DNS', name.value) for name in self.parsed_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            ]}, self.hostname)
            return True, "Hostname matches certificate"
        except Exception as e:
            return False, f"Hostname mismatch: {e}"

    def check_trusted_greek_ca(self):
        if not self.issuer or not os.path.exists(self.trusted_ca_path):
            return False

        with open(self.trusted_ca_path, "r", encoding="utf-8") as f:
            trusted_names = [line.strip() for line in f if line.strip()]

        for trusted in trusted_names:
            if trusted.lower() in self.issuer.lower():
                return True
        return False

    def run(self):
        self.fetch_certificate()

        results = {
            "subject": self.subject,
            "issuer": self.issuer,
            "self_signed": self.is_self_signed(),
        }

        valid_expiry, expiry_status = self.check_expiry()
        results["expiry_status"] = expiry_status

        hostname_valid, hostname_status = self.check_hostname()
        results["hostname_check"] = hostname_status

        results["trusted_greek_ca"] = (
            "Yes" if self.check_trusted_greek_ca() else "No"
        )

        return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python tls_certificate_checker.py <hostname>")
        sys.exit(1)

    checker = TLSCertificateChecker(sys.argv[1])
    result = checker.run()
    for key, value in result.items():
        print(f"{key}: {value}")
