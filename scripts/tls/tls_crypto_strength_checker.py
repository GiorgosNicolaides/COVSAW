import ssl
import socket
from cryptography import x509 # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa, ec # type: ignore


WEAK_SIGNATURE_ALGOS = {"md5", "sha1", "md2", "md4"}
DISALLOWED_CURVES = {"secp192r1", "sect163k1", "secp160r1"}  # Deprecated or too small


class TLSCryptoStrengthChecker:
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

    def check_key_size(self):
        pubkey = self.parsed_cert.public_key()

        if isinstance(pubkey, rsa.RSAPublicKey):
            key_size = pubkey.key_size
            if key_size < 2048:
                return False, f"Weak RSA key size: {key_size} bits"
            return True, f"RSA key size: {key_size} bits"

        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            curve_name = pubkey.curve.name
            if curve_name in DISALLOWED_CURVES:
                return False, f"Weak elliptic curve used: {curve_name}"
            return True, f"Elliptic curve: {curve_name}"

        return False, "Unsupported or unknown public key type"

    def check_signature_algorithm(self):
        sig_algo = self.parsed_cert.signature_hash_algorithm.name.lower()
        if sig_algo in WEAK_SIGNATURE_ALGOS:
            return False, f"Weak signature algorithm: {sig_algo}"
        return True, f"Signature algorithm: {sig_algo}"

    def run(self):
        self.fetch_certificate()
        key_ok, key_msg = self.check_key_size()
        sig_ok, sig_msg = self.check_signature_algorithm()

        return {
            "key_strength": key_msg,
            "signature_algorithm": sig_msg,
            "key_ok": key_ok,
            "signature_ok": sig_ok
        }


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python tls_crypto_strength_checker.py <hostname>")
        sys.exit(1)

    checker = TLSCryptoStrengthChecker(sys.argv[1])
    result = checker.run()
    for key, value in result.items():
        if not key.endswith("_ok"):
            print(f"{key}: {value}")
