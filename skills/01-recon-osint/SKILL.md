---
name: Reconnaissance & OSINT Automation
description: Passive and active reconnaissance, subdomain enumeration, DNS analysis, technology fingerprinting, and OSINT data correlation for authorized security assessments
version: 2.0.0
author: Masriyan
tags: [cybersecurity, reconnaissance, osint, enumeration, dns, subdomain, fingerprinting]
---

# Reconnaissance & OSINT Automation

## Purpose

Enable Claude to conduct comprehensive reconnaissance and open-source intelligence gathering during authorized security assessments. Claude performs passive and active recon using its native analysis capabilities and orchestrates the included scripts for automation at scale.

> **Authorization Required**: Always confirm written authorization for the target scope before proceeding. Unauthorized reconnaissance is illegal in most jurisdictions.

---

## Activation Triggers

This skill activates when the user asks about:
- Subdomain enumeration or discovery
- DNS reconnaissance, zone transfers, or DNS record analysis
- OSINT gathering on a domain, organization, or person
- Technology fingerprinting or stack identification
- Port scanning, service detection, or banner grabbing
- Google dorking or advanced search query generation
- WHOIS, certificate transparency, or Shodan queries
- Attack surface mapping or perimeter discovery

---

## Prerequisites

```bash
pip install requests dnspython python-whois beautifulsoup4 shodan
```

**Optional enhanced capabilities:**
- `nmap` — Active port scanning
- `amass` — Advanced subdomain enumeration
- `theHarvester` — Email and domain harvesting
- Shodan API key — Internet-wide device search
- Censys API key — Certificate and host search

---

## Core Capabilities

### 1. Passive Reconnaissance (No Direct Target Contact)

**When the user asks for passive recon or OSINT:**

1. **WHOIS Analysis** — Query domain registration records for registrant, registrar, nameservers, and dates. Flag privacy-protected registrations and registrar patterns.
2. **Certificate Transparency Logs** — Search crt.sh for all certificates issued to the domain and subdomains. Extract SANs (Subject Alternative Names) to discover hidden subdomains.
3. **DNS Records (Passive)** — Enumerate A, AAAA, MX, NS, TXT, SOA, SRV, and CNAME records using public resolvers. Analyze SPF, DKIM, and DMARC for email security posture.
4. **Search Engine Dorking** — Generate targeted dork queries to discover exposed files, login portals, and configuration leaks:
   - `site:target.com filetype:pdf` — Exposed documents
   - `site:target.com inurl:admin` — Admin panels
   - `site:target.com ext:env OR ext:config` — Config files
   - `"@target.com" site:linkedin.com` — Employee enumeration
   - `"target.com" site:pastebin.com` — Credential leaks
5. **Shodan/Censys Queries** — Search for internet-exposed services, open ports, banners, and vulnerabilities associated with the target's IP ranges.
6. **Git/Code Repository Search** — Search GitHub/GitLab for leaked credentials, API keys, and internal information:
   - `org:targetorg api_key`
   - `filename:.env target.com`
   - `"target.com" password`

### 2. Subdomain Enumeration

**When the user asks to enumerate subdomains:**

1. **Certificate Transparency** — Extract all SANs from crt.sh/Censys certificates (most effective passive method)
2. **DNS Brute-Force** — Run subdomain_enum.py against the common wordlist in `resources/`
3. **Wildcard Detection** — Query random subdomains to detect wildcard DNS responses and filter false positives
4. **Resolution Validation** — Resolve all candidates to IP addresses; discard NXDOMAINs
5. **HTTP Probing** — Check which subdomains respond on ports 80/443; identify web applications
6. **Infrastructure Grouping** — Group discovered subdomains by IP/ASN to map cloud vs. on-prem assets

**Output format for subdomain findings:**
```
Target: example.com
Discovery Method: CT Logs + DNS Brute-Force
Discovered: 47 subdomains

LIVE SUBDOMAINS:
  admin.example.com       → 203.0.113.10  [HTTP 200] [nginx/1.18]
  dev.example.com         → 203.0.113.11  [HTTP 302 → /login]
  api.example.com         → 203.0.113.12  [HTTP 200] [cloudflare]
  internal.example.com    → 10.0.0.5      [No public response — internal?]

INFRASTRUCTURE CLUSTERS:
  203.0.113.10-15 → AS12345 (Company Hosting)
  Cloudflare CDN → 7 subdomains proxied
```

### 3. Active Port Scanning & Service Detection

**When the user asks to scan ports or detect services:**

1. Define scan scope (host, subnet, CIDR range) and confirm authorization
2. Select scan technique: SYN scan (requires root), connect scan (no root), or stealth options
3. Run top-1000 ports first, then targeted service ports
4. Perform service version detection (`-sV`) on all open ports
5. Run OS fingerprinting (`-O`) if authorized
6. Grab banners from discovered services
7. Flag services with known vulnerabilities based on version data

**Provide Nmap commands ready to run:**
```bash
# Quick discovery
nmap -sn 203.0.113.0/24

# Top 1000 TCP ports with service detection
nmap -sV -sC --top-ports 1000 -oA scan_results 203.0.113.10

# Full port scan with script engine
nmap -sV -sC -p- -T4 -oA full_scan 203.0.113.10
```

### 4. DNS Reconnaissance

**When the user asks for DNS analysis:**

1. Enumerate all record types: A, AAAA, MX, NS, TXT, SOA, SRV, CNAME, PTR
2. **Zone Transfer Attempt** (AXFR) — Try against all discovered nameservers:
   ```bash
   dig AXFR @ns1.example.com example.com
   ```
3. **Email Security Analysis:**
   - SPF: Check for `~all` (softfail) or `?all` (neutral) — both are weak
   - DMARC: Missing DMARC = zero enforcement; `p=none` = monitoring only
   - DKIM: Check selector existence and key strength
4. **Reverse DNS** — PTR lookups on all discovered IPs to find additional hostnames
5. **DNS History** — Check SecurityTrails or PassiveDNS for historical DNS records that may reveal old infrastructure

**Flag these misconfigurations:**
- Zone transfer allowed → Exposes full DNS zone
- No DMARC record → Email spoofing possible
- SPF `+all` → Any server can send as this domain
- DNSSEC not configured → DNS cache poisoning risk

### 5. Technology Fingerprinting

**When the user asks to fingerprint technology:**

1. Analyze HTTP response headers:
   - `Server:` → Web server and version
   - `X-Powered-By:` → Application framework
   - `Set-Cookie:` names → Session framework (PHPSESSID=PHP, JSESSIONID=Java)
   - `X-Generator:` / `X-WordPress-Cache:` → CMS
2. Examine HTML source for meta tags, script includes, CSS frameworks
3. Check `/robots.txt`, `/sitemap.xml`, `/.well-known/` for framework leaks
4. Test common CMS paths (`/wp-admin/`, `/administrator/`, `/wp-json/`)
5. Analyze JavaScript files for version strings
6. Detect WAF presence through header analysis and response behavior
7. Identify CDN (Cloudflare, Akamai, Fastly, CloudFront) via IP ranges and headers

**Technology stack report format:**
```
URL: https://example.com

WEB SERVER:    nginx/1.18.0 (Ubuntu)
APPLICATION:   WordPress 6.4.2
LANGUAGE:      PHP 8.1
DATABASE:      MySQL (inferred from wp-config patterns)
CDN/WAF:       Cloudflare
JS LIBRARIES:  jQuery 3.6.0, Bootstrap 5.3
TLS:           TLS 1.3, ECDHE-RSA-AES256-GCM-SHA384

NOTABLE HEADERS:
  ✗ Missing: X-Content-Type-Options
  ✗ Missing: X-Frame-Options
  ✗ Missing: Content-Security-Policy
  ✓ Present: Strict-Transport-Security
```

### 6. OSINT Correlation & Reporting

**When the user asks to correlate OSINT findings:**

1. Cross-reference IP ranges across WHOIS, ASN lookups, and cloud provider IP lists
2. Map employee data (LinkedIn/email patterns) to organizational structure
3. Correlate exposed credentials from paste sites against discovered email formats
4. Identify third-party services and SaaS platforms in use (via DNS records, JS imports)
5. Build infrastructure map showing relationships between assets

---

## Output Standards

Every recon engagement should produce a structured report:

```markdown
# Reconnaissance Report — [Target]
Date: [Date] | Scope: [Authorized Scope] | Analyst: [Name]

## Executive Summary
[2-3 sentence overview of key findings]

## Discovered Assets
- Subdomains: N found, N live
- IP Ranges: [CIDRs]
- Open Services: [Top findings]
- Technologies: [Stack summary]

## Key Findings
1. [High-impact finding with evidence]
2. [Medium-impact finding]
...

## Attack Surface Summary
[Map of entry points for follow-on testing]

## Recommended Next Steps
- Feed live web apps → Skill 09 (Web Security)
- Feed discovered services → Skill 02 (Vulnerability Scanner)
- Feed cloud assets → Skill 10 (Cloud Security)
```

---

## Script Reference

### `subdomain_enum.py`

```bash
# Passive CT log enumeration
python scripts/subdomain_enum.py --domain target.com --passive-only --output results.json

# Active brute-force with custom wordlist
python scripts/subdomain_enum.py --domain target.com --wordlist resources/common_subdomains.txt --threads 20 --output results.json
```

### `dns_recon.py`

```bash
# Full DNS reconnaissance
python scripts/dns_recon.py --domain target.com --output dns_report.json

# Check zone transfer vulnerability
python scripts/dns_recon.py --domain target.com --check-zone-transfer
```

### `tech_fingerprint.py`

```bash
# Single URL analysis
python scripts/tech_fingerprint.py --url https://target.com --output tech_report.json

# Batch URL fingerprinting
python scripts/tech_fingerprint.py --urls urls.txt --output tech_report.json
```

---

## Skill Integration

| Next Step | Condition | Target Skill |
|-----------|-----------|--------------|
| Vulnerability assessment | Live services discovered | → Skill 02 |
| Web application testing | Web apps found | → Skill 09 |
| Cloud asset auditing | Cloud-hosted assets found | → Skill 10 |
| Network traffic analysis | PCAP capture available | → Skill 08 |
| IOC correlation | Suspicious infrastructure found | → Skill 06 |

---

## References

- [OWASP Testing Guide — Information Gathering](https://owasp.org/www-project-web-security-testing-guide/)
- [MITRE ATT&CK — Reconnaissance (TA0043)](https://attack.mitre.org/tactics/TA0043/)
- [Certificate Transparency — crt.sh](https://crt.sh/)
- [Shodan Search Engine](https://www.shodan.io/)
- [DNSDumpster](https://dnsdumpster.com/)
- [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)
