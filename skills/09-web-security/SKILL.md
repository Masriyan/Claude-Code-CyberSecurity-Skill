---
name: Web Application Security Testing
description: OWASP Top 10 testing, XSS/SQLi detection, API security assessment, and authentication testing
version: 1.0.0
author: Masriyan
tags: [cybersecurity, web-security, owasp, xss, sqli, api, pentest]
---

# 🕸️ Web Application Security Testing

## Overview

This skill enables Claude to assist with web application security assessments including OWASP Top 10 testing, injection detection, API security evaluation, authentication/authorization testing, and web vulnerability reporting.

---

## Prerequisites

### Required

- Python 3.8+
- `requests`, `beautifulsoup4`, `urllib3`

### Optional

- **Burp Suite** — Web proxy and scanner
- **ZAP** — Open-source web scanner
- **sqlmap** — Automated SQL injection tool
- **Nikto** — Web server scanner
- **ffuf** — Web fuzzer

```bash
pip install requests beautifulsoup4 urllib3 lxml
```

---

## Core Capabilities

### 1. OWASP Top 10 Assessment

**When the user asks to test for OWASP Top 10:**

| #   | Vulnerability             | Testing Approach                                                                  |
| --- | ------------------------- | --------------------------------------------------------------------------------- |
| A01 | Broken Access Control     | Test IDOR, path traversal, forced browsing, missing function-level access control |
| A02 | Cryptographic Failures    | Audit TLS config, check for sensitive data in transit/at rest, weak algorithms    |
| A03 | Injection                 | Test SQL, NoSQL, OS command, LDAP, XPath injection vectors                        |
| A04 | Insecure Design           | Review architecture for missing security controls                                 |
| A05 | Security Misconfiguration | Check default configs, unnecessary features, error handling                       |
| A06 | Vulnerable Components     | Audit third-party libraries and frameworks                                        |
| A07 | Auth & ID Failures        | Test session management, credential storage, MFA, brute force                     |
| A08 | Software & Data Integrity | Check for unsigned updates, insecure deserialization, CI/CD security              |
| A09 | Logging & Monitoring      | Verify logging coverage, monitoring gaps, incident detection                      |
| A10 | SSRF                      | Test for server-side request forgery in URL parameters                            |

### 2. Injection Testing

**When the user asks to test for injections:**

1. Map all input points (forms, headers, cookies, URL parameters, JSON body)
2. Test each input with injection payloads appropriate to the context
3. Detect blind injection through timing or boolean differences
4. Test for second-order injection (stored payloads triggered later)
5. Test for NoSQL injection in MongoDB/Elasticsearch applications
6. Check for template injection (SSTI) in Jinja2, Twig, Freemarker
7. Test for command injection through shell metacharacters
8. Document PoC steps for confirmed findings

### 3. API Security Testing

**When the user asks to test API security:**

1. Parse OpenAPI/Swagger specifications
2. Test all endpoints for authentication requirements
3. Check for broken object-level authorization (BOLA)
4. Test rate limiting and throttling
5. Check for mass assignment vulnerabilities
6. Validate input/output schemas
7. Test for excessive data exposure
8. Check for security-relevant headers (CORS, CSP, etc.)
9. Test GraphQL-specific issues (introspection, batching attacks)

### 4. Authentication & Session Testing

**When the user asks to test authentication:**

1. Test password policies and brute-force protections
2. Analyze session token entropy and predictability
3. Test session fixation and session hijacking
4. Check for insecure "remember me" implementations
5. Test OAuth/OIDC flows for misconfigurations
6. Verify MFA implementation and bypass attempts
7. Test password reset flow security
8. Check for credential stuffing protections

### 5. XSS Detection & Exploitation

**When the user asks about XSS:**

1. Map all reflection points (reflected, stored, DOM-based)
2. Test basic payloads with various encoding bypasses
3. Identify WAF/filter rules and develop bypasses
4. Test for DOM-based XSS through JavaScript analysis
5. Craft context-specific payloads (HTML, attribute, JavaScript, URL)
6. Demonstrate impact (session theft, keylogging, phishing)
7. Generate remediation recommendations

---

## Usage Instructions

### Example Prompts

```
> Test this web application for OWASP Top 10 vulnerabilities
> Check this API for authentication bypass issues
> Generate XSS payloads that bypass this WAF
> Test these input fields for SQL injection
> Review the authentication flow of this application
> Assess the CORS configuration of this API
```

---

## Script Reference

### `owasp_scanner.py`

```bash
python scripts/owasp_scanner.py --url https://target.com --output report.json
python scripts/owasp_scanner.py --url https://target.com --tests a01,a03,a07
```

### `api_security_tester.py`

```bash
python scripts/api_security_tester.py --spec openapi.yaml --base-url https://api.target.com --output results.json
```

---

## Integration Guide

- **← Recon & OSINT (01)**: Receive discovered web applications for testing
- **← Vulnerability Scanner (02)**: Focus on web-specific vulnerabilities
- **→ Exploit Development (03)**: Develop PoCs for confirmed web vulns
- **→ CSOC Automation (11)**: Generate alerts for detected vulnerabilities

---

## References

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
