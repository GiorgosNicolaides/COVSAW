import sys
from tls_certificate_checker import TLSCertificateChecker
from tls_revocation_checker import TLSRevocationChecker
from tls_crypto_strength_checker import TLSCryptoStrengthChecker
from tls_protocol_cipher_checker import TLSProtocolCipherChecker
from tls_extension_checker import TLSExtensionChecker


def analyze_tls(hostname):
    print(f"\n🔍 TLS Analysis for: {hostname}")

    results = {}

    # 1. Certificate basics
    try:
        cert_checker = TLSCertificateChecker(hostname)
        cert_info = cert_checker.run()
        results.update(cert_info)
    except Exception as e:
        results["certificate_error"] = f"Certificate check failed: {e}"

    # 2. OCSP / revocation
    try:
        revocation_checker = TLSRevocationChecker(hostname)
        ok, message = revocation_checker.check_ocsp_revocation()
        results["revocation_status"] = message
    except Exception as e:
        results["revocation_status"] = f"Revocation check failed: {e}"

    # 3. Key size / crypto strength
    try:
        crypto_checker = TLSCryptoStrengthChecker(hostname)
        crypto_result = crypto_checker.run()
        results.update(crypto_result)
    except Exception as e:
        results["crypto_strength"] = f"Crypto check failed: {e}"

    # 4. TLS version & cipher
    try:
        proto_checker = TLSProtocolCipherChecker(hostname)
        proto_result = proto_checker.run()
        results.update(proto_result)
    except Exception as e:
        results["protocol_cipher_check"] = f"Protocol/Cipher check failed: {e}"

    # 5. Extensions
    try:
        ext_checker = TLSExtensionChecker(hostname)
        ext_result = ext_checker.run()
        results.update(ext_result)
    except Exception as e:
        results["extension_check"] = f"Extension check failed: {e}"

    print("\n🔎 Report:")
    for key, value in results.items():
        if not key.endswith("_ok"):
            print(f"{key}: {value}")

    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tls_runner.py <hostname>")
        sys.exit(1)

    analyze_tls(sys.argv[1])
