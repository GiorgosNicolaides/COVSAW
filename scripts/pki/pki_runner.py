import sys
from .ct_sct_checker import CTSCTChecker
from .pki_chain_analyzer import PKIChainAnalyzer


def analyze_pki(hostname):
    print(f"\n🔍 PKI & Certificate Transparency Analysis for: {hostname}")
    results = {}

    # 1. Certificate Transparency (SCT)
    try:
        sct_checker = CTSCTChecker(hostname)
        sct_result = sct_checker.run()
        results.update(sct_result)
    except Exception as e:
        results["sct_status"] = f"❌ SCT check failed: {e}"

    # 2. PKI Chain structure
    try:
        chain_checker = PKIChainAnalyzer(hostname)
        chain_result = chain_checker.run()
        results.update(chain_result)
    except Exception as e:
        results["pki_chain_status"] = f"❌ PKI chain check failed: {e}"

    print("\n📋 Report:")
    for key, value in results.items():
        print(f"{key}: {value}")

    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pki_runner.py <hostname>")
        sys.exit(1)

    analyze_pki(sys.argv[1])
