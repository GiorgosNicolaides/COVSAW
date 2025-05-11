from covsaw.scripts.tls.tls_base import TLSChecker
from cryptography.hazmat.primitives.asymmetric import rsa, ec

class TLSCryptoStrengthChecker(TLSChecker):
    NAME = 'crypto-strength'

    def run_check(self):
        issues = []
        key = self.leaf.public_key()

        # RSA key strength
        if isinstance(key, rsa.RSAPublicKey):
            size = key.key_size
            if size < 2048:
                issues.append(('weak_rsa', f"RSA key size {size} bits"))

        # EC key strength
        if isinstance(key, ec.EllipticCurvePublicKey):
            curve = key.curve.name
            weak = {'secp192r1', 'sect163k1'}
            if curve in weak:
                issues.append(('weak_ec', f"Insecure curve {curve}"))

        # Signature algorithm strength
        sig = self.leaf.signature_hash_algorithm
        if sig and sig.name.lower() in {'md2', 'md5', 'sha1'}:
            issues.append(('weak_signature', f"Cert uses {sig.name}"))

        return issues

    def summary(self):
        key = self.leaf.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            return ('ok', f"RSA key size {key.key_size} bits; signature {self.leaf.signature_hash_algorithm.name}")
        if isinstance(key, ec.EllipticCurvePublicKey):
            return ('ok', f"EC curve {key.curve.name}; signature {self.leaf.signature_hash_algorithm.name}")
        return ('ok', 'Public key type is non-RSA/EC')
