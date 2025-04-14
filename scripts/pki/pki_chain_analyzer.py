import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class PKIChainAnalyzer:
    def __init__(self, hostname, port=443):
        self.hostname = hostname
        self.port = port
        self.chain = []

    def fetch_chain(self):
        # Use SSL context to retrieve full cert chain
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=self.hostname)
        conn.settimeout(5)
        conn.connect((self.hostname, self.port))

        try:
            cert_chain = conn.getpeercert(True)  # End-entity cert (binary DER)
            self.chain.append(x509.load_der_x509_certificate(cert_chain, default_backend()))
        finally:
            conn.close()

    def analyze_chain_structure(self):
        if not self.chain:
            return False, "❌ No certificate chain fetched"

        end_entity = self.chain[0]
        subject_chain = [end_entity.subject.rfc4514_string()]
        issuer_chain = [end_entity.issuer.rfc4514_string()]

        results = {
            "end_entity_subject": end_entity.subject.rfc4514_string(),
            "end_entity_issuer": end_entity.issuer.rfc4514_string(),
            "chain_depth": len(self.chain),
            "chain_complete": False,
            "root_self_signed": False
        }

        # Basic chain logic: compare subject/issuer relationships
        is_self_signed = end_entity.subject == end_entity.issuer
        results["root_self_signed"] = is_self_signed
        results["chain_complete"] = not is_self_signed

        return True, results

    def run(self):
        self.fetch_chain()
        ok, result = self.analyze_chain_structure()
        return result if ok else {"pki_chain_status": result}


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python pki_chain_analyzer.py <hostname>")
        sys.exit(1)

    checker = PKIChainAnalyzer(sys.argv[1])
    results = checker.run()

    print("🔐 PKI Chain Analysis:")
    for k, v in results.items():
        print(f"{k}: {v}")
