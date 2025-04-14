import ssl
import socket
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend


class CTSCTChecker:
    def __init__(self, hostname, port=443):
        self.hostname = hostname
        self.port = port
        self.parsed_cert = None

    def fetch_certificate(self):
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=self.hostname) as conn:
            conn.settimeout(5)
            conn.connect((self.hostname, self.port))
            der_cert = conn.getpeercert(binary_form=True)
            self.parsed_cert = x509.load_der_x509_certificate(der_cert, default_backend())

    def check_sct_extension(self):
        try:
            ext = self.parsed_cert.extensions.get_extension_for_oid(
                ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS
            )
            scts = ext.value
            count = len(scts)
            return True, f"{count} SCT(s) found in certificate (CT logged)"
        except x509.ExtensionNotFound:
            return False, "❌ No SCT (Signed Certificate Timestamps) found — certificate may not be logged to CT"
        except Exception as e:
            return False, f"❌ SCT check failed: {e}"

    def run(self):
        self.fetch_certificate()
        ok, msg = self.check_sct_extension()
        return {
            "sct_status": msg,
            "sct_ok": ok
        }


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python ct_sct_checker.py <hostname>")
        sys.exit(1)

    checker = CTSCTChecker(sys.argv[1])
    result = checker.run()
    print("🔍 Certificate Transparency Check:")
    for key, value in result.items():
        if not key.endswith("_ok"):
            print(f"{key}: {value}")
