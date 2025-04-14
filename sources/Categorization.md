### Comprehensive Mapping of CWEs to Cryptographic Issues Categories

#### **1. Encryption and Transmission Issues**
| Subcategory | CWE Examples |
|-------------|--------------|
| **1.1 Weak or Inadequate Encryption** | CWE-256 (Plaintext Storage of Password), CWE-257 (Storing Passwords in a Recoverable Format), CWE-326 (Inadequate Encryption Strength), CWE-327 (Use of Broken or Risky Cryptographic Algorithm), CWE-328 (Use of Weak Hash), CWE-325 (Missing Cryptographic Step) |
| **1.2 Cleartext or Improper Transmission** | CWE-311 (Missing Encryption of Sensitive Data), CWE-319 (Cleartext Transmission of Sensitive Information), CWE-370 (Missing Check for Certificate Revocation After Initial Check), CWE-523 (Unprotected Transport of Credentials), CWE-549 (Missing Password Field Masking), CWE-5 (J2EE Misconfiguration: Data Transmission Without Encryption) |
| **Parent Category** | CWE-417 (Communication Channel Errors) |

#### **2. Key and Credential Management**
| Subcategory | CWE Examples |
|-------------|--------------|
| **2.1 Hardcoded or Default Keys/Credentials** | CWE-321 (Use of Hard-coded Cryptographic Key), CWE-798 (Use of Hard-coded Credentials), CWE-1392 (Use of Default Credentials), CWE-1394 (Use of Default Cryptographic Key), CWE-258 (Empty Password in Configuration File), CWE-260 (Password in Configuration File) |
| **2.2 Weak Key Management Practices** | CWE-324 (Use of Key Past its Expiration Date), CWE-322 (Key Exchange Without Entity Authentication), CWE-329 (Generation of Predictable IV with CBC Mode), CWE-1204 (Generation of Weak Initialization Vector (IV)), CWE-522 (Insufficiently Protected Credentials) |
| **2.3 Password Management Issues** | CWE-258 (Empty Password in Configuration File), CWE-261 (Weak Encoding for Password), CWE-555 (J2EE Misconfiguration: Plaintext Password in Configuration File), CWE-13 (ASP.NET Misconfiguration: Password in Configuration File), CWE-262 (Not Using Password Aging), CWE-263 (Password Aging with Long Expiration) |
| **Parent Category** | CWE-255 (Credentials Management Errors), CWE-320 (Key Management Errors) |

#### **3. Randomness and Entropy Issues**
| Subcategory | CWE Examples |
|-------------|--------------|
| **3.1 Insufficient Randomness or Predictability** | CWE-330 (Use of Insufficiently Random Values), CWE-331 (Insufficient Entropy), CWE-332 (Insufficient Entropy in PRNG), CWE-333 (Improper Handling of Insufficient Entropy in TRNG), CWE-338 (Use of Cryptographically Weak PRNG) |
| **3.2 Predictable or Reused Seeds** | CWE-335 (Incorrect Usage of Seeds in PRNG), CWE-336 (Same Seed in PRNG), CWE-337 (Predictable Seed in PRNG) |

#### **4. Certificate and Trust Chain Weaknesses**
| Subcategory | CWE Examples |
|-------------|--------------|
| **4.1 Improper Certificate Validation** | CWE-295 (Improper Certificate Validation), CWE-296 (Improper Following of a Certificate's Chain of Trust), CWE-297 (Improper Validation of Certificate with Host Mismatch), CWE-298 (Improper Validation of Certificate Expiration), CWE-299 (Improper Check for Certificate Revocation) |
| **4.2 Mismanagement of Trust Chain** | CWE-599 (Missing Validation of OpenSSL Certificate), CWE-370 (Missing Check for Certificate Revocation After Initial Check) |

#### **5. Sensitive Information Exposure**
| Subcategory | CWE Examples |
|-------------|--------------|
| **5.1 Storage in Insecure Locations** | CWE-312 (Cleartext Storage of Sensitive Information), CWE-313 (Cleartext Storage in a File or on Disk), CWE-314 (Cleartext Storage in the Registry), CWE-318 (Cleartext Storage of Sensitive Information in Executable), CWE-526 (Cleartext Storage of Sensitive Information in an Environment Variable) |
| **5.2 Exposure Through Applications** | CWE-315 (Cleartext Storage of Sensitive Information in a Cookie), CWE-316 (Cleartext Storage of Sensitive Information in Memory), CWE-317 (Cleartext Storage of Sensitive Information in GUI) |
| **5.3 Indirect Information Leakage** | CWE-1230 (Exposure of Sensitive Information Through Metadata), CWE-1258 (Exposure of Sensitive System Information Due to Uncleared Debug Information), CWE-1420 (Exposure of Sensitive Information During Transient Execution), CWE-1421 (Exposure of Sensitive Information in Shared Microarchitectural Structures during Transient Execution), CWE-1422 (Exposure of Sensitive Information caused by Incorrect Data Forwarding during Transient Execution), CWE-1423 (Exposure of Sensitive Information caused by Shared Microarchitectural Predictor State that Influences Transient Execution) |

#### **6. Authentication and Access Control**
| Subcategory | CWE Examples |
|-------------|--------------|
| **6.1 Weak Authentication Practices** | CWE-302 (Authentication Bypass by Assumed-Immutable Data), CWE-303 (Incorrect Implementation of Authentication Algorithm), CWE-304 (Missing Critical Step in Authentication), CWE-640 (Weak Password Recovery Mechanism for Forgotten Password), CWE-916 (Use of Password Hash with Insufficient Computational Effort), CWE-836 (Use of Password Hash Instead of Password for Authentication), CWE-1390 (Weak Authentication) |
| **6.2 Weak Credential Management** | CWE-555 (J2EE Misconfiguration: Plaintext Password in Configuration File), CWE-593 (Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created) |

#### **7. Data Integrity and Tampering Protections**
| Subcategory | CWE Examples |
|-------------|--------------|
| **7.1 Missing or Weak Integrity Checks** | CWE-353 (Missing Support for Integrity Check), CWE-354 (Improper Validation of Integrity Check Value), CWE-1239 (Improper Zeroization of Hardware Register) |
| **7.2 Encryption Without Integrity Checking** | CWE-759 (Use of a One-Way Hash Without a Salt), CWE-760 (Use of a One-Way Hash with a Predictable Salt), CWE-649 (Reliance on Obfuscation or Encryption of Security-Relevant Inputs Without Integrity Checking), CWE-323 (Reusing a Nonce, Key Pair in Encryption), CWE-347 (Improper Verification of Cryptographic Signature), CWE-349 (Acceptance of Extraneous Untrusted Data With Trusted Data) |

#### **8. Algorithm Selection and Negotiation Weaknesses**
| Subcategory | CWE Examples |
|-------------|--------------|
| **8.1 Algorithm Downgrade or Weak Selection** | CWE-757 (Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')), CWE-780 (Use of RSA Algorithm without OAEP), CWE-1240 (Use of a Cryptographic Primitive with a Risky Implementation) |
| **Parent Category** | CWE-310 (Cryptographic Issues) |

#### **9. Device and Hardware-Level Weaknesses**
| Subcategory | CWE Examples |
|-------------|--------------|
| **9.1 Improper Handling of Sensitive Data on Devices** | CWE-1266 (Improper Scrubbing of Sensitive Data from Decommissioned Device), CWE-1279 (Cryptographic Operations are run Before Supporting Units are Ready), CWE-1297 (Unprotected Confidential Information on Device is Accessible by OSAT Vendors), CWE-1302 (Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC)), CWE-1314 (Missing Write Protection for Parametric Data Values) |

#### **10. Cryptographic Implementation Issues**
| Subcategory | CWE Examples |
|-------------|--------------|
| **10.1 Errors in Cryptographic Processes** | CWE-1290 (Incorrect Decoding of Security Identifiers), CWE-1291 (Public Key Re-Use for Signing both Debug and Production Code), CWE-922 (Insecure Storage of Sensitive Information) |

