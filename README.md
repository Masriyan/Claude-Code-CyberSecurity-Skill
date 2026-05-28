<p align="center">
  <img src="https://img.shields.io/badge/Claude%20Code-CyberSecurity%20Skills-red?style=for-the-badge" alt="Claude Code CyberSecurity Skills"/>
  <br/>
  <img src="https://img.shields.io/badge/Skills-15-blue?style=flat-square" alt="Skills"/>
  <img src="https://img.shields.io/badge/Version-2.0.0-orange?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python" alt="Python"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square" alt="Platform"/>
</p>

# Claude Code CyberSecurity Skill Collection

> **15 production-quality Claude Code Skills for cybersecurity professionals** — covering offensive security, defensive operations, reverse engineering, threat hunting, CSOC automation, and more. Version 2.0 — rebuilt from the ground up for Claude Code.

Transform Claude Code into your ultimate cybersecurity co-pilot. Each skill provides Claude with structured methodology, decision frameworks, ready-to-run commands, and output templates that enable precise, expert-level assistance for real-world security operations.

---

## What Are Claude Code Skills?

Claude Code Skills are **structured SKILL.md files** that you install into your `~/.claude/skills/` directory (global) or `.claude/skills/` (project-specific). When Claude reads these files, it gains deep, domain-specific expertise that goes far beyond generic knowledge.

### How Skills Work

Skills are **instruction documents Claude reads at conversation start**. Each SKILL.md contains:

1. **YAML frontmatter** — `name`, `description`, `tags` for skill identification
2. **Activation triggers** — Explicit list of prompts that should invoke this skill
3. **Methodology** — Step-by-step procedures Claude follows natively
4. **Output templates** — Exact formats for reports, rules, and artifacts Claude produces
5. **Script references** — When and how to use the included Python automation scripts
6. **Authorization gates** — Built-in prompts for offensive skills to confirm legal scope

### Claude Code-Native Design

These skills are built around what **Claude does natively** in Claude Code:

- **Read** configuration files, code, and logs directly — no copy-paste needed
- **Bash** tool to run scripts, network commands, and system queries
- **Analysis** of disassembly, PCAP data, log events, and code with full context
- **Generation** of detection rules, hardening scripts, reports, and payloads
- **WebSearch** for CVE lookups, threat intelligence, and vulnerability research

---

## Skill Collection

| # | Skill | Domain | Key Capabilities |
|:-:| ----- | ------ | ---------------- |
| 01 | [Recon & OSINT](skills/01-recon-osint/) | Reconnaissance | Subdomain enum, DNS analysis, technology fingerprinting, Google dorking, WHOIS |
| 02 | [Vulnerability Scanner](skills/02-vulnerability-scanner/) | Assessment | Dependency auditing, config review, CVSS scoring, structured vulnerability reports |
| 03 | [Exploit Development](skills/03-exploit-development/) | Offensive | PoC templates, payload generation, buffer overflow, web exploit payloads |
| 04 | [Reverse Engineering](skills/04-reverse-engineering/) | Analysis | Binary triage, assembly interpretation, firmware RE, protocol reversing, CTF |
| 05 | [Malware Analysis](skills/05-malware-analysis/) | Threat Analysis | Static analysis, YARA generation, sandbox setup, behavioral analysis, IOC extraction |
| 06 | [Threat Hunting](skills/06-threat-hunting/) | Hunting | IOC extraction, ATT&CK mapping, hunt hypotheses, Sigma + SIEM query library |
| 07 | [Incident Response](skills/07-incident-response/) | IR & Forensics | PICERL playbooks, evidence collection, timeline analysis, memory forensics, IR reports |
| 08 | [Network Security](skills/08-network-security/) | Network | PCAP analysis, Suricata/Snort rules, firewall auditing, beaconing detection |
| 09 | [Web Security](skills/09-web-security/) | Web | OWASP Top 10, injection testing, API security, JWT analysis, security headers |
| 10 | [Cloud Security](skills/10-cloud-security/) | Cloud | AWS/Azure/GCP audit, Dockerfile review, K8s hardening, IaC scanning |
| 11 | [CSOC Automation](skills/11-csoc-automation/) | SOC Operations | Alert triage, playbook YAML, escalation workflows, shift reports, KPI tracking |
| 12 | [Log Analysis & SIEM](skills/12-log-analysis/) | Log Analysis | SIEM query library (Splunk/KQL/EQL), Sigma rules, anomaly detection, correlation |
| 13 | [Cryptographic Analysis](skills/13-crypto-analysis/) | Cryptography | TLS auditing, cipher analysis, hash identification, crypto code review, PQC guidance |
| 14 | [Red Team Operations](skills/14-red-team-ops/) | Red Team | Engagement planning, C2 design, AD attacks, OPSEC, social engineering, reporting |
| 15 | [Blue Team Defense](skills/15-blue-team-defense/) | Blue Team | Linux/Windows hardening, detection engineering, baselines, patch management |

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill.git
cd Claude-Code-CyberSecurity-Skill
```

### 2. Install Skills into Claude Code

Claude Code loads skills from two locations:

| Location | Scope | Path |
|----------|-------|------|
| **Global** | All projects | `~/.claude/skills/` |
| **Project** | This project only | `./.claude/skills/` |

```bash
# Install globally (recommended — available everywhere)
mkdir -p ~/.claude/skills
cp -r skills/* ~/.claude/skills/

# Or symlink for development (changes auto-sync)
ln -sf "$(pwd)/skills/"* ~/.claude/skills/

# Or install to a specific project
mkdir -p /path/to/project/.claude/skills
cp -r skills/* /path/to/project/.claude/skills/
```

### 3. Use Claude Code

Open Claude Code and talk naturally. Claude activates the relevant skill based on what you ask:

```bash
claude
```

**Example interactions:**

```
# Recon (Skill 01 activates)
> Enumerate all subdomains for example.com and fingerprint the web stack

# Vulnerability Assessment (Skill 02 activates)
> Audit the Python dependencies in my project for known CVEs

# Malware Analysis (Skill 05 activates)
> Generate YARA rules from this suspicious PE file and extract all IOCs

# Threat Hunting (Skill 06 activates)
> Map these TTPs to MITRE ATT&CK and write Splunk SPL queries to hunt for them

# Blue Team (Skill 15 activates)
> Give me hardening commands to secure this Ubuntu 24.04 server following CIS Level 1

# Incident Response (Skill 07 activates)  
> Create a ransomware incident response playbook for our SOC team
```

You can also **explicitly name a skill**:
```
> Use the reverse-engineering skill to interpret this ARM assembly
> Use the log-analysis skill to build a Sentinel KQL query for DCSync detection
> Use the blue-team-defense skill to audit this Dockerfile
```

---

## What's New in v2.0

**Major overhaul — everything rebuilt for Claude Code:**

- **Activation Triggers** — Every skill now lists explicit phrases that should invoke it
- **Claude-native methodology** — Skills describe what Claude does directly, not just script usage
- **Output templates** — Exact formats for reports, rules, and artifacts (no more vague instructions)
- **Built-in authorization gates** — Offensive skills (03, 14) require authorization confirmation before proceeding
- **Skill 15 completely rebuilt** — Blue Team Defense expanded from 1 page to a full hardening reference
- **SIEM query library** — Skills 06, 11, 12 now include ready-to-run Splunk/Sentinel/Elastic queries
- **Detection rule templates** — Complete Sigma, Suricata, and YARA templates throughout
- **Post-quantum cryptography** — Skill 13 updated with NIST PQC 2024 standards
- **Kubernetes security** — Complete K8s hardening in Skill 10
- **`.gitignore`** — Added to exclude `__pycache__` and generated artifacts

---

## Project Structure

```
Claude-Code-CyberSecurity-Skill/
├── README.md
├── INSTALL.md
├── USAGE.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── SECURITY.md
├── LICENSE
├── .gitignore
│
└── skills/
    ├── 01-recon-osint/          SKILL.md + scripts/ + examples/ + resources/
    ├── 02-vulnerability-scanner/ SKILL.md + scripts/ + examples/
    ├── 03-exploit-development/   SKILL.md + scripts/ + examples/
    ├── 04-reverse-engineering/   SKILL.md + scripts/ + examples/
    ├── 05-malware-analysis/      SKILL.md + scripts/ + examples/
    ├── 06-threat-hunting/        SKILL.md + scripts/ + examples/
    ├── 07-incident-response/     SKILL.md + scripts/ + examples/
    ├── 08-network-security/      SKILL.md + scripts/ + examples/
    ├── 09-web-security/          SKILL.md + scripts/ + examples/
    ├── 10-cloud-security/        SKILL.md + scripts/ + examples/
    ├── 11-csoc-automation/       SKILL.md + scripts/ + examples/
    ├── 12-log-analysis/          SKILL.md + scripts/ + examples/
    ├── 13-crypto-analysis/       SKILL.md + scripts/ + examples/
    ├── 14-red-team-ops/          SKILL.md + scripts/ + examples/
    └── 15-blue-team-defense/     SKILL.md + scripts/ + examples/
```

---

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Claude Code | Latest | AI coding assistant — [install guide](https://docs.anthropic.com/en/docs/claude-code) |
| Python | 3.10+ | Automation scripts |
| Git | 2.x+ | Repository management |

### Optional Tools (Enhanced by Specific Skills)

- **nmap** — Port scanning and service detection (Skills 01, 08)
- **Burp Suite** — Web security testing (Skill 09)
- **Ghidra / IDA Free** — Reverse engineering (Skill 04)
- **Wireshark / tshark** — Network traffic analysis (Skill 08)
- **Volatility 3** — Memory forensics (Skill 07)
- **YARA** — Malware pattern matching (Skills 05, 06)
- **Trivy** — Container and IaC scanning (Skill 10)
- **Checkov / tfsec** — Terraform security (Skill 10)
- **Sigma CLI** — Rule conversion between SIEM platforms (Skills 06, 12, 15)

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Adding new skills
- Improving existing skill methodology
- Submitting detection rules or hardening checklists
- Bug reports

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

> **This skill collection is intended for authorized security testing, research, CTF competitions, and educational purposes only.** Users are solely responsible for compliance with all applicable laws. Offensive skills (Exploit Development, Red Team Operations) require explicit authorization confirmation before Claude will assist. The authors assume no liability for misuse.

---

<p align="center">
  <b>Built for the CyberSecurity Community</b><br/>
  <a href="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill">GitHub</a> •
  <a href="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/issues">Issues</a> •
  <a href="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/discussions">Discussions</a>
</p>
