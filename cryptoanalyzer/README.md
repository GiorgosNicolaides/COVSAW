
cryptoanalyzer/
└── rules/
    ├── __init__.py

    ├── credentials/                       # CWE-798
    │   ├── __init__.py
    │   └── hardcoded_credentials.py       # HardcodedCredentialsRule

    ├── plaintext_secrets/                 # CWE-256, CWE-261
    │   ├── __init__.py
    │   └── plaintext_storage.py           # PlaintextStorageRule

    ├── missing_crypto/                    # CWE-311, CWE-353, CWE-354
    │   ├── __init__.py
    │   ├── missing_encryption.py          # MissingEncryptionRule
    │   └── missing_integrity.py           # MissingIntegrityRule

    ├── certificate/                       # CWE-295, CWE-299
    │   ├── __init__.py
    │   ├── improper_validation.py         # ImproperCertificateValidationRule
    │   └── missing_revocation.py          # MissingCertificateRevocationCheckRule

    ├── algorithm_params/                  # CWE-327, CWE-328, CWE-759, CWE-760, CWE-780
    │   ├── __init__.py
    │   ├── broken_algorithm.py            # BrokenAlgorithmRule
    │   ├── hash_without_salt.py           # HashWithoutSaltRule
    │   └── rsa_without_oaep.py            # RsaNoOaepRule

    ├── randomness/                        # CWE-330
    │   ├── __init__.py
    │   └── insecure_randomness.py         # InsecureRandomRule

    ├── randomness_extra/                  # CWE-323, CWE-329, CWE-338
    │   ├── __init__.py
    │   ├── nonce_reuse.py                 # NonceReuseRule
    │   ├── predictable_iv.py              # PredictableIVRule
    │   └── weak_prng.py                   # WeakPrngRule

    ├── padding_oracle/                    # CWE-346
    │   ├── __init__.py
    │   └── padding_oracle.py              # PaddingOracleRule

    ├── api_misuse/                        # CWE-328 (HMAC)
    │   ├── __init__.py
    │   └── hmac_default_md5.py            # HmacDefaultMd5Rule

    └── cleartext/                         # CWE-319–CWE-318
        ├── __init__.py
        └── cleartext_issues.py            # CleartextTransmissionRule & CleartextStorageRule
