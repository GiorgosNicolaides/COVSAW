import ssl
import socket
from cryptography import x509 # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, KeyUsage # type: ignore


class TLSExtensionChecker:
    def __init__(self, hostname, port=443):
        self.hostname = hostname
        self.port = port
        self.cert = None
        self.parsed_cert = None

    def fetch_certificate(self):
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=self.hostname) as s:
            s.settimeout(5)
            s.connect((self.hostname, self.port))
            self.cert = s.getpeercert(binary_form=True)
            self.parsed_cert = x509.load_der_x509_certificate(self.cert, default_backend())

    def check_basic_constraints(self):
        try:
            ext = self.parsed_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            if ext.value.ca:
                return False, "End-entity certificate incorrectly marked as a CA (basicConstraints: CA=TRUE)"
            return True, "Certificate is correctly marked as CA=FALSE"
        except x509.ExtensionNotFound:
            return False, "Missing basicConstraints extension"

    def check_key_usage(self):
        try:
            ext = self.parsed_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            usage: KeyUsage = ext.value
            if not (usage.digital_signature or usage.key_encipherment):
                return False, "Missing digitalSignature and keyEncipherment in keyUsage"
            return True, f"keyUsage: digitalSignature={usage.digital_signature}, keyEncipherment={usage.key_encipherment}"
        except x509.ExtensionNotFound:
            return False, "Missing keyUsage extension"

    def check_extended_key_usage(self):
        try:
            ext = self.parsed_cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            eku_oids = ext.value
            if ExtendedKeyUsageOID.SERVER_AUTH not in eku_oids:
                return False, "Missing serverAuth in extendedKeyUsage"
            return True, "extendedKeyUsage includes serverAuth"
        except x509.ExtensionNotFound:
            return False, "Missing extendedKeyUsage extension"

    def run(self):
        self.fetch_certificate()

        bc_ok, bc_msg = self.check_basic_constraints()
        ku_ok, ku_msg = self.check_key_usage()
        eku_ok, eku_msg = self.check_extended_key_usage()

        return {
            "basic_constraints": bc_msg,
            "key_usage": ku_msg,
            "extended_key_usage": eku_msg,
            "basic_ok": bc_ok,
            "keyusage_ok": ku_ok,
            "extkeyusage_ok": eku_ok
        }


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python tls_extension_checker.py <hostname>")
        sys.exit(1)

    checker = TLSExtensionChecker(sys.argv[1])
    result = checker.run()
    for key, value in result.items():
        if not key.endswith("_ok"):
            print(f"{key}: {value}")
