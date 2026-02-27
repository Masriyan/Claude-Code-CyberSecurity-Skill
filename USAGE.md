# 📖 Usage Guide

> Comprehensive usage guide for the **Claude Code CyberSecurity Skill Collection**.

---

## Table of Contents

- [How Skills Work](#how-skills-work)
- [Using Individual Skills](#using-individual-skills)
- [Chaining Skills Together](#chaining-skills-together)
- [Workflow Examples](#workflow-examples)
- [Standalone Script Usage](#standalone-script-usage)
- [Configuration](#configuration)
- [Best Practices](#best-practices)

---

## How Skills Work with Claude Code

### The Skill Discovery Process

When Claude Code starts a conversation, it **scans for `SKILL.md` files** in these directories:

1. **Project-level**: `<your-project>/.claude/skills/` — skills scoped to one project
2. **User-level (global)**: `~/.claude/skills/` — skills available across all projects

Claude reads each `SKILL.md` file's **YAML frontmatter** to understand what the skill does:

```yaml
---
name: Threat Hunting & IOC Analysis # Human-readable name
description: IOC extraction, MITRE ATT&CK mapping # What Claude looks for when matching
version: 1.0.0
tags: [cybersecurity, threat-hunting, ioc] # Additional matching keywords
---
```

### The Skill Lifecycle

```
╔══════════════════════════════════════════════════════════════╗
║  STEP 1: DISCOVERY                                          ║
║  Claude Code scans .claude/skills/ for SKILL.md files       ║
║  and reads the YAML frontmatter of each one                 ║
╠══════════════════════════════════════════════════════════════╣
║  STEP 2: MATCHING                                           ║
║  When you type a prompt, Claude determines which skill(s)   ║
║  are relevant based on name, description, and tags          ║
╠══════════════════════════════════════════════════════════════╣
║  STEP 3: READING                                            ║
║  Claude reads the full SKILL.md body — the methodology,     ║
║  step-by-step procedures, and script references             ║
╠══════════════════════════════════════════════════════════════╣
║  STEP 4: EXECUTION                                          ║
║  Claude follows the instructions: answering questions,      ║
║  running scripts, generating code, or analyzing files       ║
╚══════════════════════════════════════════════════════════════╝
```

### Three Ways to Activate Skills

| Mode            | How It Works                                                            | Example                                                                    |
| --------------- | ----------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| **Implicit**    | Claude auto-detects the domain from your prompt                         | `"Analyze this PCAP for suspicious activity"` → activates Network Security |
| **Explicit**    | You name the skill directly                                             | `"Use the threat-hunting skill to extract IOCs from this report"`          |
| **Script-only** | You run the Python scripts directly in your terminal (no Claude needed) | `python scripts/ioc_extractor.py --input report.txt`                       |

### What Happens Inside Claude Code — Real Example

```
┌─────────────────────────────────────────────────────────────────┐
│ YOU: "I received a suspicious email with an attachment.         │
│       Analyze the attachment and create detection rules."       │
│                                                                 │
│ CLAUDE CODE (behind the scenes):                                │
│                                                                 │
│   ① Matches → skill 05-malware-analysis                        │
│   ② Reads SKILL.md: "When the user asks to analyze a sample,   │
│      calculate hashes, identify file type, calculate entropy,   │
│      extract strings, analyze imports, detect packing..."       │
│   ③ Runs: scripts/static_analyzer.py --file attachment.exe     │
│      → Returns hashes, entropy, suspicious strings, IOCs       │
│                                                                 │
│   ④ Chains → skill 05 YARA generation                          │
│   ⑤ Runs: scripts/yara_generator.py --file attachment.exe      │
│      → Returns YARA detection rule                             │
│                                                                 │
│   ⑥ Chains → skill 06-threat-hunting                           │
│   ⑦ Runs: scripts/mitre_mapper.py --technique T1566.001        │
│      → Maps to MITRE ATT&CK with Splunk detection queries     │
│                                                                 │
│ RESULT: You get a complete analysis report, YARA rule,          │
│         and SIEM detection queries — all from one prompt.       │
└─────────────────────────────────────────────────────────────────┘
```

### Tips for Effective Skill Usage

1. **Be specific** — "Analyze this binary for malware IOCs" activates skills more precisely than "look at this file"
2. **Chain requests** — After one skill runs, ask a follow-up that triggers another skill
3. **Use skill names** — When you want a specific methodology, reference it: `"Use the red-team-ops skill..."`
4. **Run scripts directly** — Every script works standalone; you don't always need Claude in the loop
5. **Customize skills** — Edit `SKILL.md` to adjust procedures for your organization's workflow

---

## Using Individual Skills

### 01 — Recon & OSINT

```
> Use the recon-osint skill to enumerate subdomains for target.com
> Perform a comprehensive OSINT gathering on organization "Acme Corp"
> Run DNS reconnaissance against 192.168.1.0/24
```

**Standalone script:**

```bash
python skills/01-recon-osint/scripts/subdomain_enum.py --domain target.com --output results.json
```

---

### 02 — Vulnerability Scanner

```
> Scan this Python project for known CVEs in its dependencies
> Audit the nginx configuration at /etc/nginx/nginx.conf for security misconfigurations
> Generate a CVSS score report for these findings
```

**Standalone script:**

```bash
python skills/02-vulnerability-scanner/scripts/dependency_auditor.py --project-dir ./myapp --format json
```

---

### 03 — Exploit Development

```
> Help me develop a proof-of-concept for CVE-2024-XXXX
> Analyze this buffer overflow vulnerability and suggest exploitation techniques
> Generate a reverse shell payload for Linux x64
```

**Standalone script:**

```bash
python skills/03-exploit-development/scripts/payload_generator.py --type reverse_shell --os linux --arch x64
```

---

### 04 — Reverse Engineering

```
> Analyze this ELF binary and identify its main functionality
> Decompile this firmware image and map out its control flow
> Reverse engineer the protocol used by this IoT device
```

**Standalone script:**

```bash
python skills/04-reverse-engineering/scripts/binary_analyzer.py --file suspicious.elf --output analysis.json
```

---

### 05 — Malware Analysis

```
> Perform static analysis on this suspicious executable
> Generate YARA rules based on these malware samples
> Set up a sandbox environment for dynamic analysis
```

**Standalone script:**

```bash
python skills/05-malware-analysis/scripts/static_analyzer.py --file malware.exe --output report.json
python skills/05-malware-analysis/scripts/yara_generator.py --samples ./samples/ --output rules.yar
```

---

### 06 — Threat Hunting

```
> Extract IOCs from this threat intelligence report
> Map these TTPs to the MITRE ATT&CK framework
> Generate hunt hypotheses for APT29 activity in our environment
```

**Standalone script:**

```bash
python skills/06-threat-hunting/scripts/ioc_extractor.py --input threat_report.txt --output iocs.json
python skills/06-threat-hunting/scripts/mitre_mapper.py --ttps ttps.json --output attack_map.json
```

---

### 07 — Incident Response

```
> Create an incident response playbook for a ransomware attack
> Help me collect and preserve digital evidence from this compromised host
> Build a forensic timeline from these log sources
```

**Standalone script:**

```bash
python skills/07-incident-response/scripts/evidence_collector.py --host 192.168.1.100 --output evidence/
python skills/07-incident-response/scripts/timeline_builder.py --logs ./logs/ --output timeline.csv
```

---

### 08 — Network Security

```
> Analyze this PCAP file for suspicious network activity
> Create Suricata IDS rules to detect this attack pattern
> Review and harden this firewall ruleset
```

**Standalone script:**

```bash
python skills/08-network-security/scripts/pcap_analyzer.py --file capture.pcap --output analysis.json
python skills/08-network-security/scripts/ids_rule_generator.py --attack-pattern pattern.json --output rules.rules
```

---

### 09 — Web Security

```
> Test this web application for OWASP Top 10 vulnerabilities
> Analyze this API endpoint for authentication bypass vulnerabilities
> Check for XSS and SQL injection in these input fields
```

**Standalone script:**

```bash
python skills/09-web-security/scripts/owasp_scanner.py --url https://target.com --output report.json
python skills/09-web-security/scripts/api_security_tester.py --spec openapi.yaml --output results.json
```

---

### 10 — Cloud Security

```
> Audit this AWS account for security misconfigurations
> Scan this Terraform configuration for security issues
> Review Kubernetes cluster security posture
```

**Standalone script:**

```bash
python skills/10-cloud-security/scripts/cloud_auditor.py --provider aws --profile default --output report.json
python skills/10-cloud-security/scripts/iac_scanner.py --path ./terraform/ --output findings.json
```

---

### 11 — CSOC Automation

```
> Create an automated alert triage playbook for our SOC
> Build an escalation workflow for critical security incidents
> Generate a SOC shift handover report
```

**Standalone script:**

```bash
python skills/11-csoc-automation/scripts/alert_triager.py --alerts alerts.json --playbook playbook.yaml
python skills/11-csoc-automation/scripts/report_generator.py --shift night --date 2024-01-15 --output report.pdf
```

---

### 12 — Log Analysis & SIEM

```
> Parse these Windows Event Logs for suspicious authentication events
> Build a Splunk query to detect lateral movement
> Create correlation rules for detecting brute force attacks
```

**Standalone script:**

```bash
python skills/12-log-analysis/scripts/log_parser.py --input /var/log/auth.log --format json --output parsed.json
python skills/12-log-analysis/scripts/anomaly_detector.py --logs parsed.json --baseline baseline.json --output anomalies.json
```

---

### 13 — Cryptographic Analysis

```
> Audit the SSL/TLS configuration of this server
> Identify weak cryptographic implementations in this codebase
> Analyze the strength of this encryption scheme
```

**Standalone script:**

```bash
python skills/13-crypto-analysis/scripts/tls_auditor.py --host target.com --port 443 --output report.json
python skills/13-crypto-analysis/scripts/crypto_scanner.py --path ./src/ --output findings.json
```

---

### 14 — Red Team Operations

```
> Help me plan a red team engagement methodology
> Set up a C2 infrastructure for authorized testing
> Document persistence techniques for this Windows environment
```

**Standalone script:**

```bash
python skills/14-red-team-ops/scripts/engagement_planner.py --scope scope.json --output plan.md
python skills/14-red-team-ops/scripts/c2_setup.py --framework sliver --output config.yaml
```

---

### 15 — Blue Team Defense

```
> Generate a system hardening checklist for Ubuntu 22.04
> Create detection rules for common persistence mechanisms
> Build a security baseline for our Windows Server fleet
```

**Standalone script:**

```bash
python skills/15-blue-team-defense/scripts/hardening_checker.py --os ubuntu --version 22.04 --output report.json
python skills/15-blue-team-defense/scripts/detection_rule_generator.py --technique T1053 --format sigma --output rules/
```

---

## Chaining Skills Together

Skills can be combined for comprehensive security operations:

### Full Penetration Test Workflow

```
1. Use recon-osint to enumerate the target →
2. Use vulnerability-scanner to identify weaknesses →
3. Use exploit-development to create PoCs →
4. Use web-security for application-layer testing →
5. Use blue-team-defense to generate remediation guidance
```

### Incident Response Workflow

```
1. Use csoc-automation to triage the alert →
2. Use log-analysis to correlate events →
3. Use threat-hunting to identify IOCs →
4. Use network-security to analyze traffic →
5. Use incident-response to build timeline and collect evidence →
6. Use malware-analysis if malware is discovered
```

### Threat Intelligence Workflow

```
1. Use threat-hunting to extract IOCs from reports →
2. Use malware-analysis to analyze samples →
3. Use reverse-engineering to understand binary behavior →
4. Use blue-team-defense to create detection rules
```

---

## Configuration

### Environment Variables

Some scripts support configuration via environment variables:

```bash
export CYBERSKILL_OUTPUT_DIR="./output"       # Default output directory
export CYBERSKILL_LOG_LEVEL="INFO"            # Logging level (DEBUG, INFO, WARNING, ERROR)
export CYBERSKILL_API_TIMEOUT="30"            # API timeout in seconds
export CYBERSKILL_MAX_THREADS="10"            # Maximum concurrent threads
```

### Script Configuration Files

Many scripts accept YAML/JSON configuration files:

```yaml
# config.yaml
output_directory: ./results
log_level: INFO
report_format: json
threads: 5
timeout: 30
```

```bash
python scripts/tool.py --config config.yaml
```

---

## Best Practices

### 🔒 Security

1. **Always obtain authorization** before testing any system
2. **Use isolated environments** for malware analysis and exploit testing
3. **Handle sensitive data** (API keys, credentials) securely — never commit them
4. **Document your scope** and rules of engagement

### 🎯 Effectiveness

1. **Start with reconnaissance** — understanding the target is crucial
2. **Chain skills logically** — follow established methodologies
3. **Validate findings** — cross-reference results across multiple tools
4. **Document everything** — use the included report templates

### 🔧 Technical

1. **Keep skills updated** — `git pull` regularly for latest improvements
2. **Use virtual environments** — prevent dependency conflicts
3. **Review scripts before running** — understand what each script does
4. **Check output formats** — ensure compatibility with your existing tools

---

<p align="center">
  <a href="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill">← Back to Main Repository</a>
</p>
