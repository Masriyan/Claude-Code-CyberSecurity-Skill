---
name: Reconnaissance & OSINT Automation
description: Comprehensive reconnaissance and open-source intelligence gathering for security assessments
version: 1.0.0
author: Masriyan
tags: [cybersecurity, reconnaissance, osint, enumeration, dns, subdomain]
---

# 🔍 Reconnaissance & OSINT Automation

## Overview

This skill enables Claude to assist with comprehensive reconnaissance and open-source intelligence (OSINT) gathering during security assessments. It covers passive and active reconnaissance techniques, subdomain enumeration, port scanning, DNS analysis, technology fingerprinting, and OSINT data correlation.

> **⚠️ Important**: Always obtain proper authorization before performing reconnaissance against any target. Unauthorized scanning is illegal in most jurisdictions.

---

## Prerequisites

### Required

- Python 3.8+
- `requests`, `dnspython`, `python-whois`, `beautifulsoup4`, `shodan`

### Optional (Enhanced Capabilities)

- **Nmap** — Active port scanning and service detection
- **Amass** — Advanced subdomain enumeration
- **Subfinder** — Passive subdomain discovery
- **theHarvester** — Email and subdomain harvesting
- **Shodan API key** — Internet-wide device search
- **Censys API key** — Certificate and host search

```bash
pip install requests dnspython python-whois beautifulsoup4 shodan censys
```

---

## Core Capabilities

### 1. Subdomain Enumeration

- Passive subdomain discovery using certificate transparency logs
- DNS brute-force enumeration with customizable wordlists
- Recursive subdomain discovery
- Wildcard detection and filtering
- Result deduplication and validation

**When the user asks to enumerate subdomains:**

1. Start with passive methods (CT logs, DNS records, search engines)
2. Validate discovered subdomains via DNS resolution
3. Optionally perform active brute-force enumeration
4. Detect wildcard DNS and filter false positives
5. Resolve all valid subdomains to IP addresses
6. Group results by IP for infrastructure mapping
7. Output results in structured JSON format

### 2. Port Scanning & Service Detection

- TCP SYN/Connect scanning
- UDP scanning for critical services
- Service version detection
- OS fingerprinting
- Banner grabbing
- Rate-limited scanning to avoid detection

**When the user asks to scan ports:**

1. Determine scan scope (single host, subnet, list)
2. Select appropriate scan technique based on authorization level
3. Perform service version detection on open ports
4. Identify potential vulnerabilities based on service versions
5. Generate structured scan report

### 3. DNS Reconnaissance

- DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, SRV, CNAME)
- Zone transfer attempts (AXFR)
- DNS cache snooping
- Reverse DNS lookups
- SPF/DKIM/DMARC analysis for email security posture
- DNS history and passive DNS lookups

**When the user asks for DNS recon:**

1. Enumerate all DNS record types for the target domain
2. Attempt zone transfers on all nameservers
3. Analyze SPF, DKIM, and DMARC records
4. Perform reverse DNS on discovered IPs
5. Check for DNS misconfigurations
6. Document findings with security implications

### 4. Technology Fingerprinting

- Web technology identification (CMS, frameworks, libraries)
- HTTP header analysis
- SSL/TLS certificate analysis
- WAF detection
- CDN identification
- JavaScript library version detection

**When the user asks to fingerprint technologies:**

1. Analyze HTTP response headers
2. Parse HTML for framework indicators
3. Check for common CMS signatures
4. Analyze JavaScript includes and their versions
5. Detect WAF presence and type
6. Check SSL certificate details
7. Generate technology stack profile

### 5. OSINT Gathering

- Email address discovery and validation
- Social media profile correlation
- Domain WHOIS analysis
- Company infrastructure mapping
- Leaked credential checking (via public APIs)
- Metadata extraction from public documents
- Google dorking query generation

**When the user asks for OSINT:**

1. Gather WHOIS information for domains
2. Search certificate transparency logs
3. Discover email addresses associated with the domain
4. Generate and execute Google dork queries
5. Check for exposed services and data
6. Correlate findings across multiple sources
7. Present findings with confidence levels

---

## Usage Instructions

### Basic Reconnaissance Workflow

```
Step 1: Define target scope and authorization
Step 2: Passive reconnaissance (OSINT, DNS, CT logs)
Step 3: Subdomain enumeration
Step 4: Port scanning and service detection
Step 5: Technology fingerprinting
Step 6: Consolidate and report findings
```

### Example Prompts

```
> Enumerate all subdomains for example.com using passive methods
> Perform a full DNS reconnaissance of target.org
> Fingerprint the technology stack of https://target.com
> Generate Google dork queries for finding exposed files on example.com
> Scan the top 1000 ports on 192.168.1.0/24
```

---

## Integration Guide

### Chaining with Other Skills

- **→ Vulnerability Scanner (02)**: Feed discovered hosts and services into vulnerability scanning
- **→ Web Security (09)**: Pass discovered web applications for security testing
- **→ Network Security (08)**: Use scan results for network architecture mapping
- **→ Cloud Security (10)**: Identify cloud-hosted assets for cloud-specific auditing

### Output Formats

All scripts output structured JSON by default, compatible with:

- SIEM ingestion
- Custom reporting pipelines
- Other skill scripts

---

## Script Reference

### `subdomain_enum.py`

Passive and active subdomain enumeration with validation.

```bash
python scripts/subdomain_enum.py --domain target.com --output results.json
python scripts/subdomain_enum.py --domain target.com --wordlist wordlist.txt --threads 20
python scripts/subdomain_enum.py --domain target.com --passive-only
```

### `dns_recon.py`

Comprehensive DNS reconnaissance and analysis.

```bash
python scripts/dns_recon.py --domain target.com --output dns_report.json
python scripts/dns_recon.py --domain target.com --check-zone-transfer
```

### `tech_fingerprint.py`

Web technology fingerprinting and stack identification.

```bash
python scripts/tech_fingerprint.py --url https://target.com --output tech_report.json
python scripts/tech_fingerprint.py --urls urls.txt --output tech_report.json
```

---

## References

- [OWASP Testing Guide — Information Gathering](https://owasp.org/www-project-web-security-testing-guide/)
- [Shodan API Documentation](https://developer.shodan.io/)
- [Certificate Transparency](https://certificate.transparency.dev/)
- [MITRE ATT&CK — Reconnaissance](https://attack.mitre.org/tactics/TA0043/)
- [DNS RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)
