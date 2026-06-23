---
name: Cryptographic Analysis & Assessment
description: SSL/TLS auditing, cipher suite analysis, hash algorithm identification, encryption implementation review, and cryptographic weakness detection in code
version: 3.0.0
author: Masriyan
tags: [cybersecurity, cryptography, ssl, tls, encryption, hashing, cipher, pki, post-quantum]
---

# Cryptographic Analysis & Assessment

## Purpose

Enable Claude to assist with cryptographic security assessments including SSL/TLS configuration auditing, cipher suite analysis and recommendation, hash algorithm identification, encryption implementation code review, key management evaluation, and detection of cryptographic vulnerabilities. Claude directly analyzes provided configurations and code.

---

## Activation Triggers

This skill activates when the user asks about:
- Auditing SSL/TLS configuration of a server or service
- Evaluating cipher suites for security strength
- Identifying hash algorithms from hash values or code
- Reviewing code for cryptographic implementation flaws
- Assessing key lengths, key management, or rotation policies
- Detecting hardcoded keys, weak IVs, or ECB mode usage
- Generating TLS configuration recommendations (Mozilla profile)
- Certificate analysis (expiration, chain, transparency)
- Post-quantum cryptography guidance
- Password hashing implementation review (bcrypt, Argon2, PBKDF2)

---

## Prerequisites

```bash
pip install cryptography requests pyOpenSSL
```

**Recommended tools:**
- `sslyze` — Python TLS scanner
- `testssl.sh` — Comprehensive TLS testing
- `openssl` — Command-line TLS operations
- `Wireshark` — TLS traffic analysis
- `certbot` — Certificate management

---

## Core Capabilities

### 1. SSL/TLS Configuration Auditing

**When the user asks to audit TLS for a server or paste a TLS configuration:**

**Command-line audit approach:**
```bash
# Quick TLS check using openssl
openssl s_client -connect example.com:443 -tls1_2 2>/dev/null | grep -E "Protocol|Cipher"
openssl s_client -connect example.com:443 -tls1 2>/dev/null | grep -E "handshake|error"

# Check certificate details
openssl s_client -connect example.com:443 </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer

# Comprehensive scan with sslyze
sslyze --regular example.com --json_out result.json

# Or testssl.sh (most comprehensive)
./testssl.sh --severity HIGH --quiet example.com

# Use the skill's script
python scripts/tls_auditor.py --host example.com --port 443 --output report.json
python scripts/tls_auditor.py --host mail.example.com --port 993 --grade
```

**TLS Version Support Ratings:**
| Protocol | Status | Action |
|----------|--------|--------|
| SSLv2 | Critically broken | Block immediately |
| SSLv3 | Broken (POODLE) | Block immediately |
| TLS 1.0 | Deprecated (PCI-DSS violation) | Disable — BEAST, POODLE |
| TLS 1.1 | Deprecated | Disable |
| TLS 1.2 | Acceptable (with strong ciphers) | Keep with restrictions |
| TLS 1.3 | Current standard | Enable and prefer |

**TLS Vulnerability Checklist:**
```
[ ] Heartbleed (CVE-2014-0160): openssl s_client + heartbleed test
[ ] POODLE: SSLv3 enabled?
[ ] BEAST: TLS 1.0 + CBC cipher?
[ ] ROBOT: RSA key exchange supported?
[ ] DROWN: SSLv2 on any port of same server?
[ ] Logjam/FREAK: DHE < 2048-bit or EXPORT ciphers?
[ ] CRIME/BREACH: TLS compression enabled?
[ ] Sweet32: 3DES (64-bit block cipher) supported?
[ ] Weak certificate: RSA < 2048-bit, SHA-1 signed?
[ ] Certificate validity: Not expired, chain complete, not self-signed for prod?
[ ] HSTS: Strict-Transport-Security header present?
[ ] CT: Certificate in public transparency logs?
```

### 2. Cipher Suite Strength Evaluation

**When the user asks about cipher suite security:**

**TLS 1.3 Cipher Suites (All Secure — Use These):**
| Cipher Suite | Key Exchange | Auth | Encryption | MAC | Rating |
|-------------|-------------|------|------------|-----|--------|
| TLS_AES_256_GCM_SHA384 | ECDHE | RSA/ECDSA | AES-256-GCM | SHA-384 | A+ |
| TLS_CHACHA20_POLY1305_SHA256 | ECDHE | RSA/ECDSA | ChaCha20 | Poly1305 | A+ |
| TLS_AES_128_GCM_SHA256 | ECDHE | RSA/ECDSA | AES-128-GCM | SHA-256 | A |

**TLS 1.2 Cipher Suite Ratings:**
| Cipher Suite | Rating | Notes |
|-------------|--------|-------|
| ECDHE-ECDSA-AES256-GCM-SHA384 | A+ | Perfect — AEAD, PFS |
| ECDHE-RSA-AES256-GCM-SHA384 | A+ | Perfect — AEAD, PFS |
| ECDHE-RSA-AES128-GCM-SHA256 | A | Good — AEAD, PFS |
| DHE-RSA-AES256-GCM-SHA384 | A | Good — if DHE ≥ 2048-bit |
| AES256-GCM-SHA384 | B | No forward secrecy |
| ECDHE-RSA-AES256-SHA384 | B | CBC mode (timing attacks) |
| RC4-SHA | F | RC4 broken — never use |
| DES-CBC3-SHA | F | 3DES vulnerable (Sweet32) |
| NULL-SHA | F | No encryption |
| EXPORT-RC4-MD5 | F | FREAK vulnerable |

**Recommended nginx TLS Configuration (Mozilla Modern Profile):**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;  # TLS 1.3 ignores this; client order for TLS 1.2

# For TLS 1.2 compatibility
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

# DH parameters for DHE cipher suites
ssl_dhparam /etc/nginx/dhparam.pem;  # Generate: openssl dhparam -out dhparam.pem 4096

# Session management
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;  # Disabling improves forward secrecy

# HSTS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
```

**Generate DH parameters:**
```bash
# 4096-bit DH parameters (do this once, takes a few minutes)
openssl dhparam -out /etc/nginx/dhparam.pem 4096
```

### 3. Hash Algorithm Identification & Assessment

**When the user provides a hash value or asks to identify hash algorithms:**

**Hash Identification by Format:**
| Hash Format / Length | Algorithm | Security Status |
|----------------------|-----------|----------------|
| 32 hex chars | MD5 | Broken — collision attacks exist |
| 40 hex chars | SHA-1 | Deprecated — SHAttered collision |
| 56 hex chars | SHA-224 | Acceptable (limited use) |
| 64 hex chars | SHA-256 | Current standard |
| 96 hex chars | SHA-384 | Strong |
| 128 hex chars | SHA-512 | Strong |
| `$apr1$...` | MD5-APR (Apache) | Weak — only 1000 iterations |
| `$1$...` | MD5-crypt | Broken |
| `$5$...` | SHA-256-crypt | Acceptable |
| `$6$...` | SHA-512-crypt | Good |
| `$2b$12$...` | bcrypt (cost 12) | Good for passwords |
| `$argon2id$...` | Argon2id | Best for passwords |
| `sha256:...` | Django SHA-256 | Good |
| `pbkdf2_sha256$...` | PBKDF2-SHA256 | Good if iterations ≥ 260,000 |

**Password Hash Security Assessment:**

```
bcrypt:
  $2b$10$... → cost factor 10 → ~100ms/hash → ACCEPTABLE
  $2b$12$... → cost factor 12 → ~400ms/hash → GOOD
  $2b$14$... → cost factor 14 → ~1.6s/hash  → STRONG

Argon2id (OWASP recommended):
  Minimum: m=19456 (19MB), t=2 iterations, p=1 parallelism
  Strong:  m=65536 (64MB), t=3 iterations, p=4 parallelism

PBKDF2:
  SHA-1: 1,300,000 iterations minimum (NIST 2023)
  SHA-256: 600,000 iterations minimum (NIST 2023)
  SHA-512: 210,000 iterations minimum (NIST 2023)

Avoid:
  Plain MD5/SHA-1 → instantly cracked
  bcrypt cost < 10 → too fast for modern hardware
  No salt → rainbow table attack
  SHA-256 without KDF → GPU-crackable
```

### 4. Encryption Implementation Code Review

**When the user asks to review code for cryptographic flaws:**

Claude reads the code directly and flags these patterns:

**Python Crypto Anti-Patterns:**
```python
# INSECURE: Hardcoded encryption key
key = b"mysecretkey12345"  # ← NEVER hardcode keys
cipher = AES.new(key, AES.MODE_ECB)  # ← ECB mode is insecure

# INSECURE: ECB mode (produces identical ciphertext for identical blocks)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)  # ← Pattern detection attacks possible

# INSECURE: Static/reused IV
iv = b"\x00" * 16  # ← Static IV allows pattern detection
cipher = AES.new(key, AES.MODE_CBC, iv)  # ← Reusing IV with same key = CRITICAL

# INSECURE: Weak hash for passwords
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()  # ← GPU-crackable

# INSECURE: Trusting certificate errors
import ssl
ssl._create_default_https_context = ssl._create_unverified_context  # ← MitM possible
requests.get(url, verify=False)  # ← Never do this in production
```

**Secure Python Crypto Patterns:**
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os, secrets

# SECURE: Derive key from password using PBKDF2
def derive_key(password: bytes, salt: bytes = None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(32)  # 256-bit random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=600_000  # NIST 2023 minimum for PBKDF2-SHA256
    )
    key = kdf.derive(password)
    return key, salt

# SECURE: AES-GCM (authenticated encryption)
def encrypt(data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit random nonce (NEVER reuse!)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
    return nonce + ciphertext  # Prepend nonce for decryption

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = ciphertext[:12]
    return aesgcm.decrypt(nonce, ciphertext[12:], associated_data=None)

# SECURE: Argon2id for password hashing
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hashed = ph.hash(password)  # Automatic random salt
ph.verify(hashed, password)  # Verify with timing-safe comparison
```

**Code Review Checklist:**
```
Encryption:
[ ] No hardcoded keys (check for key = b"...", SECRET_KEY = "...", etc.)
[ ] No ECB mode (MODE_ECB, "AES/ECB/PKCS5Padding")
[ ] IV/Nonce is random and unique per encryption operation
[ ] Authenticated encryption used (AES-GCM, ChaCha20-Poly1305)
[ ] Key properly derived from password (PBKDF2, bcrypt, Argon2)
[ ] No custom/homebrew crypto algorithms

Certificate Handling:
[ ] Certificate validation is NOT disabled (verify=True)
[ ] Certificate pinning for mobile/critical apps
[ ] No ssl._create_unverified_context

Randomness:
[ ] Cryptographic operations use secrets module or os.urandom()
[ ] Not using random.random() or random.randint() for security
[ ] Tokens and OTPs have sufficient entropy (≥128 bits)
```

### 5. Key Management Assessment

**When the user asks about key management:**

**Key Length Recommendations (2025):**
| Algorithm | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| RSA | 2048-bit | 3072-bit | NIST recommends 3072+ post-2030 |
| ECC (ECDSA) | P-256 | P-384 | P-256 OK through 2030 |
| AES | 128-bit | 256-bit | 128-bit adequate; use 256 for high-value |
| ECDH (key exchange) | P-256 | P-384 | |
| DH (classic) | 2048-bit | 3072-bit | Avoid, prefer ECDH |
| SHA (hashing) | SHA-256 | SHA-256/384/512 | SHA-1 deprecated |

**Post-Quantum Cryptography Transition:**

NIST finalized PQC standards in 2024:
- **ML-KEM** (CRYSTALS-Kyber) — Key encapsulation mechanism (replaces RSA/ECDH for key exchange)
- **ML-DSA** (CRYSTALS-Dilithium) — Digital signature (replaces RSA/ECDSA)
- **SLH-DSA** (SPHINCS+) — Stateless hash-based signature (conservative fallback)

For systems expected to protect data beyond 2030, begin PQC migration planning.

**Key Rotation Schedule:**
| Key Type | Recommended Rotation |
|----------|---------------------|
| TLS certificates | Annual (or use 90-day Let's Encrypt) |
| Signing keys (JWT/API) | 90 days |
| Encryption keys (data at rest) | Annual |
| API keys / service tokens | 90 days or per-service |
| Employee SSH keys | Annual + on role change |
| Password hashes | On password change |

---

## Script Reference

### `tls_auditor.py`
```bash
python scripts/tls_auditor.py --host example.com --port 443 --output report.json
python scripts/tls_auditor.py --host mail.example.com --port 993 --grade
```

---

## Skill Integration

| Condition | Adjacent Skill |
|-----------|---------------|
| TLS audit for web application | ← Skill 09 (Web Security) |
| Cloud service encryption assessment | ← Skill 10 (Cloud Security) |
| Weak crypto findings → hardening recommendations | → Skill 15 (Blue Team Defense) |
| Crypto flaws → vulnerability report | → Skill 02 (Vulnerability Scanner) |

---

## References

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [NIST SP 800-52 Rev. 2 — TLS Guidelines](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [SSL Labs Grading Criteria](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)
- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Password Storage Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)


---

## v3.0 Enhancements (2026 Update)

**Post-quantum migration is now operational:**

- **Finalized PQC standards** — FIPS 203 (**ML-KEM**, key encapsulation), FIPS 204 (**ML-DSA**, signatures), and FIPS 205 (**SLH-DSA**, hash-based signatures) are published. Recommend these for new designs; FIPS 206 (FN-DSA/Falcon) is forthcoming.
- **Hybrid key exchange** — for TLS, recommend hybrid groups (e.g., X25519+ML-KEM-768 / `X25519MLKEM768`) so confidentiality survives both classical and quantum attacks during transition.
- **Harvest-now-decrypt-later** — prioritize PQC for long-lived secrets and data with multi-year confidentiality requirements; this is a present risk, not a future one.
- **Crypto-agility** — flag hardcoded algorithms/key sizes; recommend abstraction so primitives can be swapped. Inventory cryptography (a CBOM) as the first migration step.
- **Hard deprecations** — TLS 1.3 preferred / TLS 1.0-1.1 disallowed; SHA-1 and RSA/DH < 2048 flagged as failing; RSA-2048 acceptable now but on the PQC migration clock.

**Precision rule:** every finding states the primitive, key size/curve, protocol version, and the concrete upgrade (classical-now and PQC-target).
