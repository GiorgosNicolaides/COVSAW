import ssl
import socket


WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1"}
WEAK_CIPHERS = {"RC4", "3DES", "NULL", "EXP", "DES", "MD5"}
FS_KEYWORDS = {"DHE", "ECDHE"}  # Indicates forward secrecy


class TLSProtocolCipherChecker:
    def __init__(self, hostname, port=443):
        self.hostname = hostname
        self.port = port
        self.protocol = None
        self.cipher = None

    def connect_and_extract(self):
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=self.hostname) as s:
            s.settimeout(5)
            s.connect((self.hostname, self.port))
            self.protocol = s.version()
            self.cipher = s.cipher()  # tuple: (cipher_name, version, secret_bits)

    def check_protocol_version(self):
        if self.protocol in WEAK_PROTOCOLS:
            return False, f"Weak TLS version negotiated: {self.protocol}"
        return True, f"TLS version: {self.protocol}"

    def check_cipher_strength(self):
        cipher_name = self.cipher[0]
        if any(weak in cipher_name.upper() for weak in WEAK_CIPHERS):
            return False, f"Weak cipher suite in use: {cipher_name}"
        return True, f"Cipher suite: {cipher_name}"

    def check_forward_secrecy(self):
        cipher_name = self.cipher[0]
        if any(kw in cipher_name.upper() for kw in FS_KEYWORDS):
            return True, "Cipher suite supports forward secrecy"
        return False, f"No forward secrecy: {cipher_name}"

    def run(self):
        self.connect_and_extract()

        proto_ok, proto_msg = self.check_protocol_version()
        cipher_ok, cipher_msg = self.check_cipher_strength()
        fs_ok, fs_msg = self.check_forward_secrecy()

        return {
            "protocol": proto_msg,
            "cipher": cipher_msg,
            "forward_secrecy": fs_msg,
            "protocol_ok": proto_ok,
            "cipher_ok": cipher_ok,
            "fs_ok": fs_ok
        }


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python tls_protocol_cipher_checker.py <hostname>")
        sys.exit(1)

    checker = TLSProtocolCipherChecker(sys.argv[1])
    result = checker.run()
    for key, value in result.items():
        if not key.endswith("_ok"):
            print(f"{key}: {value}")
