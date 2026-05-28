# Usage Guide

Comprehensive usage guide for the **Claude Code CyberSecurity Skill Collection v2.0**.

---

## Table of Contents

- [How Skills Work](#how-skills-work)
- [Using Individual Skills](#using-individual-skills)
- [Chaining Skills Together](#chaining-skills-together)
- [Standalone Script Reference](#standalone-script-reference)
- [Configuration](#configuration)
- [Best Practices](#best-practices)

---

## How Skills Work with Claude Code

### Skill Discovery

When Claude Code starts a session, it scans for `SKILL.md` files in:

1. `<project>/.claude/skills/` — project-scoped skills
2. `~/.claude/skills/` — globally available skills

Claude reads each file's YAML frontmatter to understand the skill's domain:

```yaml
---
name: Threat Hunting & IOC Analysis
description: IOC extraction, MITRE ATT&CK mapping, threat hunting
version: 2.0.0
tags: [cybersecurity, threat-hunting, ioc, mitre-attack]
---
```

### The Skill Lifecycle

```
STEP 1  Discovery   — Claude scans .claude/skills/ for SKILL.md files
STEP 2  Matching    — Claude maps your prompt to a skill by name/description/tags
STEP 3  Reading     — Claude reads the full SKILL.md body (methodology, templates, commands)
STEP 4  Execution   — Claude follows the instructions, runs scripts, generates artifacts
```

### Three Ways to Activate Skills

| Mode            | How It Works                                               | Example                                             |
| --------------- | ---------------------------------------------------------- | --------------------------------------------------- |
| **Implicit**    | Claude auto-detects domain from your prompt                | `"Analyze this PCAP"` → activates Network Security  |
| **Explicit**    | You name the skill directly                                | `"Use the threat-hunting skill to extract IOCs"`    |
| **Script-only** | Run Python scripts directly without Claude in the loop     | `python scripts/anomaly_detector.py --logs auth.log` |

### Real-World Example

```
You: "Analyze this suspicious email attachment and create detection rules."

Claude Code (behind the scenes):
  1  Matches  → skill 05-malware-analysis
  2  Reads    → SKILL.md: "calculate hashes, entropy, extract strings, analyze imports..."
  3  Runs     → static_analyzer.py --file attachment.exe
  4  Chains   → skill 05 YARA generator: yara_generator.py --file attachment.exe
  5  Chains   → skill 06-threat-hunting: mitre_mapper.py --technique T1566.001

Result: complete analysis report + YARA rule + MITRE ATT&CK mapping + SIEM queries
```

---

## Using Individual Skills

### 01 — Recon & OSINT

```
> Use the recon-osint skill to enumerate subdomains for target.com
> Perform passive OSINT gathering on "Acme Corp"
> Run DNS reconnaissance against 192.168.1.0/24
```

```bash
python skills/01-recon-osint/scripts/subdomain_enum.py --domain target.com --output results.json
python skills/01-recon-osint/scripts/dns_recon.py --domain target.com --output dns.json
python skills/01-recon-osint/scripts/tech_fingerprint.py --url https://target.com
```

---

### 02 — Vulnerability Scanner

```
> Scan this Python project for known CVEs in its dependencies
> Audit the nginx configuration for security misconfigurations
> Calculate CVSS scores for these findings
```

```bash
python skills/02-vulnerability-scanner/scripts/dependency_auditor.py --project-dir ./myapp --format json
python skills/02-vulnerability-scanner/scripts/config_auditor.py --file /etc/nginx/nginx.conf --type nginx
python skills/02-vulnerability-scanner/scripts/cvss_calculator.py --vector "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

---

### 03 — Exploit Development

**Authorization required before any assistance.** Claude will verify your authorization context first.

```
> Help me develop a proof-of-concept for CVE-2024-XXXX (authorized lab environment)
> Analyze this buffer overflow vulnerability
> Generate a reverse shell payload for authorized CTF challenge
```

```bash
python skills/03-exploit-development/scripts/payload_generator.py --list-types
python skills/03-exploit-development/scripts/payload_generator.py --type reverse_shell --os linux --arch x64 --lhost 10.0.0.1 --lport 4444
```

---

### 04 — Reverse Engineering

```
> Analyze this ELF binary and identify its main functionality
> Reverse engineer the protocol used by this IoT device
> Identify anti-analysis techniques in this sample
```

```bash
python skills/04-reverse-engineering/scripts/binary_analyzer.py --file suspicious.elf --output analysis.json
```

---

### 05 — Malware Analysis

```
> Perform static analysis on this suspicious executable
> Generate YARA rules based on these malware samples
> Identify malware family and MITRE ATT&CK techniques
```

```bash
python skills/05-malware-analysis/scripts/static_analyzer.py --file malware.exe --output report.json
python skills/05-malware-analysis/scripts/yara_generator.py --samples ./samples/ --output rules.yar
```

---

### 06 — Threat Hunting

```
> Extract IOCs from this threat intelligence report
> Map these TTPs to MITRE ATT&CK
> Generate hunt hypotheses for APT29 activity
```

```bash
python skills/06-threat-hunting/scripts/ioc_extractor.py --input threat_report.txt --output iocs.json
python skills/06-threat-hunting/scripts/mitre_mapper.py --ttps ttps.json --output attack_map.json
```

---

### 07 — Incident Response

```
> Create an incident response playbook for a ransomware attack
> Collect forensic evidence from this compromised host
> Build a forensic timeline from these log sources
```

```bash
# Collect volatile evidence locally (run as root for complete collection)
python skills/07-incident-response/scripts/evidence_collector.py --output ./evidence/ --type full
python skills/07-incident-response/scripts/evidence_collector.py --output ./evidence/ --type volatile
python skills/07-incident-response/scripts/timeline_builder.py --logs ./logs/ --output timeline.csv
```

---

### 08 — Network Security

```
> Analyze this PCAP file for suspicious network activity
> Create Suricata IDS rules to detect this attack pattern
> Review and harden this firewall ruleset
```

```bash
python skills/08-network-security/scripts/pcap_analyzer.py --file capture.pcap --output analysis.json
```

IDS rule generation is handled directly by Claude using the Suricata/Snort templates in SKILL.md — just ask: `"Create a Suricata rule to detect DNS tunneling over TXT records."`

---

### 09 — Web Security

```
> Test this web application for OWASP Top 10 vulnerabilities
> Test this REST API for authentication bypass and BOLA
> Check JWT token implementation for security issues
```

```bash
python skills/09-web-security/scripts/owasp_scanner.py --url https://target.com --output report.json
python skills/09-web-security/scripts/api_security_tester.py \
  --base-url https://api.example.com \
  --spec openapi.yaml \
  --token "Bearer eyJ..." \
  --output results.json
```

---

### 10 — Cloud Security

```
> Audit this AWS account for security misconfigurations
> Scan this Terraform configuration for security issues
> Review Kubernetes cluster security posture
```

```bash
python skills/10-cloud-security/scripts/cloud_auditor.py --provider aws --profile default --region us-east-1 --output report.json
python skills/10-cloud-security/scripts/cloud_auditor.py --provider gcp --project my-project-id
python skills/10-cloud-security/scripts/cloud_auditor.py --provider azure --subscription <subscription-id>
python skills/10-cloud-security/scripts/iac_scanner.py --path ./terraform/ --output findings.json
```

---

### 11 — CSOC Automation

```
> Triage this batch of SIEM alerts and suggest priorities
> Build an escalation workflow for critical incidents
> Generate a SOC shift handover report
```

```bash
python skills/11-csoc-automation/scripts/alert_triager.py --alerts alerts.json
python skills/11-csoc-automation/scripts/report_generator.py --shift night --date 2024-01-15 --analyst "John Smith" --output report.md
python skills/11-csoc-automation/scripts/report_generator.py --shift day --date 2024-01-15 --alerts alerts.json --demo
```

---

### 12 — Log Analysis & SIEM

```
> Parse these Windows Event Logs for suspicious authentication events
> Build a Splunk query to detect lateral movement
> Detect anomalies in this authentication log
```

```bash
python skills/12-log-analysis/scripts/log_parser.py --input /var/log/auth.log --format json --output parsed.json
python skills/12-log-analysis/scripts/anomaly_detector.py --logs parsed.json --output anomalies.json
python skills/12-log-analysis/scripts/anomaly_detector.py --demo   # Run with sample data
```

---

### 13 — Cryptographic Analysis

```
> Audit the SSL/TLS configuration of this server
> Identify weak cryptographic implementations in this codebase
> Assess the strength of this password hashing scheme
```

```bash
python skills/13-crypto-analysis/scripts/tls_auditor.py --host target.com --port 443 --output report.json
```

---

### 14 — Red Team Operations

**Authorization required before any assistance.** Claude will verify your engagement authorization first.

```
> Help me plan a red team engagement methodology
> Generate an engagement scope document
> Review this phishing pretext for an authorized simulation
```

```bash
python skills/14-red-team-ops/scripts/engagement_planner.py --scope scope.json --output plan.md
```

C2 infrastructure setup is documented in SKILL.md but requires explicit authorized engagement context — Claude will verify before assisting.

---

### 15 — Blue Team Defense

```
> Generate a system hardening checklist for Ubuntu 22.04
> Create detection rules for common persistence mechanisms
> Build a security baseline for our Windows Server fleet
```

```bash
python skills/15-blue-team-defense/scripts/hardening_checker.py --os ubuntu --version 22.04 --output report.json
python skills/15-blue-team-defense/scripts/hardening_checker.py --os windows --cis-level 1
```

Sigma/Suricata/YARA rule generation is handled directly by Claude using the detection templates in SKILL.md — just ask: `"Create a Sigma rule to detect scheduled task creation."`

---

## Chaining Skills Together

### Full Penetration Test Workflow

```
1  recon-osint          →  enumerate target, identify attack surface
2  vulnerability-scanner →  discover CVEs and misconfigurations
3  web-security          →  test application layer (OWASP Top 10, API)
4  exploit-development   →  build authorized proof-of-concept
5  blue-team-defense     →  generate remediation guidance
```

### Incident Response Workflow

```
1  csoc-automation   →  triage SIEM alerts, determine severity
2  log-analysis      →  correlate events, detect anomalies
3  threat-hunting    →  extract IOCs, map to MITRE ATT&CK
4  network-security  →  analyze packet captures for C2/exfiltration
5  incident-response →  collect evidence, build timeline, run playbook
6  malware-analysis  →  analyze any discovered samples
```

### Threat Intelligence Workflow

```
1  threat-hunting  →  extract IOCs from intelligence reports
2  malware-analysis →  analyze related samples
3  reverse-engineering →  understand binary behavior
4  blue-team-defense →  build detection rules from findings
```

---

## Standalone Script Reference

All scripts that exist and are validated to run:

| Script | Skill | Purpose |
|--------|-------|---------|
| `subdomain_enum.py` | 01 | Subdomain enumeration |
| `dns_recon.py` | 01 | DNS reconnaissance |
| `tech_fingerprint.py` | 01 | Technology fingerprinting |
| `dependency_auditor.py` | 02 | CVE/dependency auditing |
| `config_auditor.py` | 02 | Config file security audit |
| `cvss_calculator.py` | 02 | CVSS v3.1 score calculation |
| `payload_generator.py` | 03 | Payload generation (authorized) |
| `binary_analyzer.py` | 04 | Binary static analysis |
| `static_analyzer.py` | 05 | Malware static analysis |
| `yara_generator.py` | 05 | YARA rule generation |
| `ioc_extractor.py` | 06 | IOC extraction from reports |
| `mitre_mapper.py` | 06 | MITRE ATT&CK mapping |
| `evidence_collector.py` | 07 | Forensic evidence collection |
| `timeline_builder.py` | 07 | Forensic timeline construction |
| `pcap_analyzer.py` | 08 | PCAP analysis |
| `owasp_scanner.py` | 09 | OWASP Top 10 web testing |
| `api_security_tester.py` | 09 | REST API security testing |
| `cloud_auditor.py` | 10 | AWS/Azure/GCP misconfiguration audit |
| `iac_scanner.py` | 10 | Terraform/IaC security scanning |
| `alert_triager.py` | 11 | SOC alert triage |
| `report_generator.py` | 11 | SOC shift handover reports |
| `log_parser.py` | 12 | Log file parsing |
| `anomaly_detector.py` | 12 | Statistical log anomaly detection |
| `tls_auditor.py` | 13 | TLS/SSL certificate auditing |
| `engagement_planner.py` | 14 | Red team engagement planning |
| `hardening_checker.py` | 15 | System hardening verification |

---

## Configuration

### Environment Variables

```bash
export CYBERSKILL_OUTPUT_DIR="./output"    # Default output directory
export CYBERSKILL_LOG_LEVEL="INFO"         # DEBUG, INFO, WARNING, ERROR
export CYBERSKILL_API_TIMEOUT="30"         # HTTP request timeout (seconds)
```

### Script Configuration File

Many scripts accept `--config` with a YAML file:

```yaml
# config.yaml
output_directory: ./results
log_level: INFO
timeout: 30
```

```bash
python scripts/tool.py --config config.yaml
```

---

## Best Practices

### Authorization

1. Always obtain **written authorization** before testing any system
2. Use **isolated lab environments** for malware analysis and exploit testing
3. **Document your scope** and rules of engagement before starting
4. Handle sensitive findings through **secure channels** only

### Effectiveness

1. **Start with reconnaissance** — understanding the target drives better results
2. **Chain skills logically** — follow established methodologies
3. **Cross-reference findings** across multiple tools
4. **Document everything** using the included report templates

### Technical

1. **Use virtual environments** to prevent dependency conflicts
2. **Review scripts before running** — understand what each one does
3. Keep skills updated with `git pull` + `cp -r skills/* ~/.claude/skills/`
4. Run scripts with `--help` to see all available options

---

[Back to Main Repository](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill)
