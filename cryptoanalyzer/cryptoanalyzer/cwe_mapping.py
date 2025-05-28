# cryptoanalyzer/cwe_mapping.py

"""
Centralized mapping from rule identifiers to CWE identifiers.

Each key is the Rule.name (the unique identifier returned by a rule),
and the value is a list of CWE IDs that correspond to that rule.
"""

from typing import Dict, List

CWE_MAPPING: Dict[str, List[str]] = {
    # 1) Hard‐coded credentials
    "HardcodedCredentials": ["CWE-798"],

    # 2) Plaintext or weakly‐encoded secrets
    "PlaintextSecretStorage": ["CWE-256", "CWE-261"],

    # 3) Missing or improper crypto APIs
    "MissingEncryption": ["CWE-311"],
    "MissingIntegrityCheck": ["CWE-353", "CWE-354"],

    # 4) Certificate/TLS misconfiguration
    "ImproperCertificateValidation": ["CWE-295"],
    "MissingCertificateRevocationCheck": ["CWE-299"],

    # 5) Broken or weak algorithms / parameters
    "BrokenOrWeakAlgorithm": ["CWE-327", "CWE-328"],
    "HashWithoutSalt": ["CWE-759", "CWE-760"],
    "RSAWithoutOAEP": ["CWE-780"],

    # 6) Randomness issues
    "InsecureRandomness": ["CWE-330"],

    # 7) Predictable randomness / nonce reuse
    "NonceReuse": ["CWE-323"],
    "PredictableIV": ["CWE-329"],
    "WeakPRNG": ["CWE-338"],

    # 8) Cipher‐mode issues
    "InsecureCipherMode": ["CWE-310"],

    # 9) Padding oracle patterns
    "PaddingOracleSusceptible": ["CWE-346"],

    # 10) API misuse (e.g. HMAC defaults)
    "HmacWeakDefault": ["CWE-328"],

    # 11) Timing‐attack prone code
    "InsecureComparison": ["CWE-208"],

    # 12) Cleartext transmission/storage
    "CleartextTransmission": ["CWE-319"],
    "CleartextStorage": [
        "CWE-312", "CWE-313", "CWE-314", "CWE-315",
        "CWE-316", "CWE-317", "CWE-318"
    ],
}

def get_cwe_ids(rule_name: str) -> List[str]:
    """
    Return the list of CWE IDs for a given rule identifier.
    If the rule is not found in the mapping, returns an empty list.
    """
    return CWE_MAPPING.get(rule_name, [])
