---
name: Cryptographic Analysis & Assessment
description: Cipher identification, SSL/TLS auditing, hash analysis, key strength assessment, and crypto implementation review
version: 1.0.0
author: Masriyan
tags: [cybersecurity, cryptography, ssl, tls, encryption, hashing, cipher]
---

# 🔐 Cryptographic Analysis & Assessment

## Overview

This skill enables Claude to assist with cryptographic security assessments including SSL/TLS configuration auditing, cipher suite analysis, hash algorithm identification, encryption implementation review, key management evaluation, and cryptographic weakness detection.

---

## Prerequisites

- Python 3.8+
- `cryptography`, `requests`

```bash
pip install cryptography requests pyOpenSSL
```

---

## Core Capabilities

### 1. SSL/TLS Configuration Auditing

**When the user asks to audit TLS:**

1. Connect to target server and enumerate supported TLS versions
2. List all accepted cipher suites with ratings
3. Check certificate validity (expiration, chain, revocation)
4. Identify weak protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
5. Detect weak cipher suites (RC4, DES, 3DES, NULL, EXPORT)
6. Check for perfect forward secrecy (PFS) support
7. Verify HSTS configuration
8. Check for certificate transparency
9. Rate overall TLS configuration (A-F grade)

### 2. Cipher Suite Analysis

**When the user asks about cipher suites:**

1. Parse and explain cipher suite names (e.g., TLS_AES_256_GCM_SHA384)
2. Rate each cipher suite by security strength
3. Identify weak key exchange algorithms
4. Check for AEAD cipher support
5. Recommend optimal cipher suite ordering
6. Compare against industry best practices (Mozilla, NIST)

### 3. Hash Analysis & Identification

**When the user asks about hashes:**

1. Identify hash algorithm from hash length/format (MD5, SHA-1, SHA-256, bcrypt, etc.)
2. Assess hash algorithm strength for the intended use case
3. Recommend alternative algorithms when weak ones are found
4. Analyze password hashing implementations (salting, iterations, key stretching)
5. Check for rainbow table vulnerability
6. Evaluate PBKDF2/bcrypt/scrypt/Argon2 parameters

### 4. Encryption Implementation Review

**When the user asks to review crypto implementation:**

1. Identify encryption algorithms used in code
2. Check for hardcoded keys and IVs
3. Verify proper key derivation from passwords
4. Check for ECB mode usage (insecure for most cases)
5. Verify IV/nonce uniqueness and randomness
6. Check for proper authenticated encryption (GCM, ChaCha20-Poly1305)
7. Identify custom/homebrew crypto (dangerous)
8. Review key storage and management

### 5. Key Strength Assessment

**When the user asks about key strength:**

1. Evaluate key lengths against current standards
2. Compare RSA, ECC, and post-quantum key sizes
3. Check for key reuse across services
4. Verify random number generator quality
5. Assess key rotation policies
6. Review key backup and recovery procedures

---

## Usage Instructions

### Example Prompts

```
> Audit the SSL/TLS configuration of example.com
> Identify the hash algorithm: $2b$12$LJ3m4ys3hQYBb8kS7D4N7e
> Review this Python encryption code for cryptographic weaknesses
> Recommend cipher suites for our Nginx configuration
> What's wrong with using AES-ECB mode for encrypting data at rest?
> Assess the key strength of our 2048-bit RSA certificates
```

---

## Script Reference

### `tls_auditor.py`

```bash
python scripts/tls_auditor.py --host example.com --port 443 --output report.json
python scripts/tls_auditor.py --host mail.example.com --port 993 --grade
```

---

## Integration Guide

- **← Web Security (09)**: Audit TLS for web applications
- **← Cloud Security (10)**: Assess cloud service encryption
- **→ Blue Team Defense (15)**: Recommend cryptographic hardening
- **→ Vulnerability Scanner (02)**: Flag weak crypto as vulnerabilities

---

## References

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [NIST SP 800-52 Rev. 2 — TLS Guidelines](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [SSL Labs Grading Criteria](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
