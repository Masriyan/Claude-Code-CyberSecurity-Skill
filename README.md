<p align="center">
  <img src="https://img.shields.io/badge/Claude%20Code-CyberSecurity%20Skills-red?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTEyIDJDNi40OCAyIDIgNi40OCAyIDEyczQuNDggMTAgMTAgMTAgMTAtNC40OCAxMC0xMFMxNy41MiAyIDEyIDJ6bTAgMThjLTQuNDEgMC04LTMuNTktOC04czMuNTktOCA4LTggOCAzLjU5IDggOC0zLjU5IDgtOCA4eiIgZmlsbD0id2hpdGUiLz48L3N2Zz4=" alt="Claude Code CyberSecurity Skills"/>
  <br/>
  <img src="https://img.shields.io/badge/Skills-15-blue?style=flat-square" alt="Skills"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/Version-1.0.0-orange?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python" alt="Python"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square" alt="Platform"/>
</p>

# 🛡️ Claude Code CyberSecurity Skill Collection

> **A comprehensive collection of 15 Claude Code Skills for cybersecurity professionals** — covering offensive security, defensive operations, reverse engineering, threat hunting, CSOC automation, and more.

Transform Claude Code into your ultimate cybersecurity co-pilot. Each skill provides structured instructions, automation scripts, templates, and examples that enable Claude to assist with real-world security operations.

---

## 🎯 What Are Claude Code Skills?

Claude Code Skills are **structured instruction sets** that live inside your project and extend Claude's capabilities for specific domains. They are the core mechanism through which Claude Code gains domain expertise.

### How Claude Code Discovers and Uses Skills

When you place skill folders in your project's `.claude/skills/` directory (or `~/.claude/skills/` globally), Claude Code **automatically discovers them** at the start of each conversation. Here is exactly what happens:

```
┌─────────────────────────────────────────────────────────────┐
│  1. DISCOVERY — Claude Code scans for SKILL.md files       │
│     in .claude/skills/ (project) or ~/.claude/skills/      │
│                                                             │
│  2. READING — Claude reads the YAML frontmatter (name,     │
│     description, tags) to understand what each skill does   │
│                                                             │
│  3. ACTIVATION — When your prompt matches a skill's domain,│
│     Claude reads the full SKILL.md for detailed methodology │
│                                                             │
│  4. EXECUTION — Claude follows the instructions in SKILL.md│
│     and can run the scripts/ included with the skill       │
└─────────────────────────────────────────────────────────────┘
```

### Anatomy of a Skill

Each skill folder follows this structure:

```
skills/06-threat-hunting/
├── SKILL.md              ← Core instruction file (REQUIRED)
│   ├── YAML Frontmatter  ← name, description, version, tags
│   └── Markdown Body     ← Detailed methodology, procedures, prompts
├── scripts/              ← Automation scripts Claude can execute
│   ├── ioc_extractor.py
│   └── mitre_mapper.py
├── examples/             ← Usage examples for reference
│   └── example_usage.md
└── resources/            ← Templates, wordlists, data files
```

### The `SKILL.md` File — The Brain of Each Skill

The `SKILL.md` file is the **most important file** in every skill. It tells Claude Code:

1. **What the skill does** — via the YAML frontmatter at the top:

   ```yaml
   ---
   name: Threat Hunting & IOC Analysis
   description: IOC extraction, threat intelligence correlation, MITRE ATT&CK mapping
   version: 1.0.0
   author: Masriyan
   tags: [cybersecurity, threat-hunting, ioc, mitre-attack]
   ---
   ```

2. **How to perform tasks** — via structured methodology sections like:
   - "When the user asks to extract IOCs, follow these steps: 1, 2, 3..."
   - "When the user asks to map to ATT&CK, do this..."

3. **What tools and scripts are available** — via script references:
   - `python scripts/ioc_extractor.py --input report.txt --output iocs.json`

4. **How skills connect** — via integration guides that show skill chaining

### How You Interact with Claude Code + Skills

Once skills are installed, you simply **talk to Claude Code naturally**. Claude automatically activates the relevant skill based on your prompt:

```
┌──────────────────────────────────────────────────────────────┐
│ YOU:  "Extract all IOCs from this threat report and map     │
│        them to MITRE ATT&CK techniques"                     │
│                                                              │
│ CLAUDE CODE:                                                 │
│   1. Detects this matches skill 06-threat-hunting            │
│   2. Reads SKILL.md for IOC extraction methodology           │
│   3. Runs scripts/ioc_extractor.py on your report            │
│   4. Runs scripts/mitre_mapper.py on the extracted IOCs      │
│   5. Returns structured results with ATT&CK mappings         │
└──────────────────────────────────────────────────────────────┘
```

You can also be **explicit** about which skill to use:

```
> Use the malware-analysis skill to generate YARA rules from these samples
> Use the blue-team-defense skill to harden this Ubuntu server
> Use the csoc-automation skill to triage these 50 SIEM alerts
```

### Key Benefits Over Regular Prompting

| Without Skills                        | With Skills Installed                                |
| ------------------------------------- | ---------------------------------------------------- |
| Claude has general knowledge          | Claude follows **specific, validated methodologies** |
| You must explain procedures each time | Procedures are **pre-loaded and consistent**         |
| No automation scripts available       | **Ready-to-run Python scripts** included             |
| Generic advice                        | **Actionable, step-by-step** instructions            |
| No tool chaining                      | Skills **reference each other** for workflows        |

---

## 📋 Skill Collection Overview

|  #  | Skill                                                     | Domain             | Description                                                                                 |
| :-: | --------------------------------------------------------- | ------------------ | ------------------------------------------------------------------------------------------- |
| 01  | [Recon & OSINT](skills/01-recon-osint/)                   | 🔍 Reconnaissance  | Subdomain enumeration, port scanning, OSINT gathering, DNS recon, technology fingerprinting |
| 02  | [Vulnerability Scanner](skills/02-vulnerability-scanner/) | 🔎 Assessment      | CVE scanning, dependency auditing, configuration analysis, CVSS scoring                     |
| 03  | [Exploit Development](skills/03-exploit-development/)     | 💥 Offensive       | PoC generation, payload crafting, shellcode development, buffer overflow analysis           |
| 04  | [Reverse Engineering](skills/04-reverse-engineering/)     | 🔬 Analysis        | Binary analysis, disassembly, decompilation, firmware RE, protocol reverse engineering      |
| 05  | [Malware Analysis](skills/05-malware-analysis/)           | 🦠 Threat Analysis | Static/dynamic analysis, YARA rule generation, sandbox configuration, behavior profiling    |
| 06  | [Threat Hunting](skills/06-threat-hunting/)               | 🎯 Hunting         | IOC extraction, threat intelligence, MITRE ATT&CK mapping, hunt hypothesis generation       |
| 07  | [Incident Response](skills/07-incident-response/)         | 🚨 IR & Forensics  | IR playbook execution, evidence collection, timeline analysis, memory forensics             |
| 08  | [Network Security](skills/08-network-security/)           | 🌐 Network         | Traffic analysis, PCAP parsing, IDS/IPS rule creation, firewall configuration               |
| 09  | [Web Security](skills/09-web-security/)                   | 🕸️ Web             | OWASP Top 10 testing, XSS/SQLi detection, API security assessment, authentication testing   |
| 10  | [Cloud Security](skills/10-cloud-security/)               | ☁️ Cloud           | AWS/Azure/GCP auditing, container hardening, IaC scanning, Kubernetes security              |
| 11  | [CSOC Automation](skills/11-csoc-automation/)             | 🏢 SOC Operations  | Alert triage automation, playbook creation, escalation workflows, shift reporting           |
| 12  | [Log Analysis & SIEM](skills/12-log-analysis/)            | 📊 Log Analysis    | Log parsing, anomaly detection, SIEM query building, correlation rule development           |
| 13  | [Cryptographic Analysis](skills/13-crypto-analysis/)      | 🔐 Cryptography    | Cipher identification, SSL/TLS auditing, hash analysis, key strength assessment             |
| 14  | [Red Team Operations](skills/14-red-team-ops/)            | 🔴 Red Team        | C2 framework setup, lateral movement, persistence mechanisms, social engineering            |
| 15  | [Blue Team Defense](skills/15-blue-team-defense/)         | 🔵 Blue Team       | System hardening, detection engineering, baseline monitoring, patch management              |

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill.git
cd Claude-Code-CyberSecurity-Skill
```

### 2. Install Skills into Claude Code

Claude Code looks for skills in **two locations** (in order of priority):

| Location          | Scope                | Path                             |
| ----------------- | -------------------- | -------------------------------- |
| **Project-level** | Current project only | `<your-project>/.claude/skills/` |
| **Global**        | All projects         | `~/.claude/skills/`              |

```bash
# Option A: Install globally (available everywhere)
mkdir -p ~/.claude/skills
cp -r skills/* ~/.claude/skills/

# Option B: Install into a specific project
mkdir -p /path/to/your/project/.claude/skills
cp -r skills/* /path/to/your/project/.claude/skills/

# Option C: Symlink for development (changes auto-apply)
ln -s "$(pwd)/skills/"* ~/.claude/skills/
```

### 3. Start Using with Claude Code

Open Claude Code in your terminal and start asking cybersecurity questions. Claude will **automatically detect and activate** the relevant skill:

```bash
# Start Claude Code
claude
```

**Example conversation in Claude Code:**

```
You: Scan my project dependencies for known CVEs

# Claude Code activates skill 02-vulnerability-scanner
# Reads SKILL.md methodology for dependency auditing
# Runs scripts/dependency_auditor.py on your project
# Returns a structured vulnerability report with CVSS scores

You: Now create YARA rules from this suspicious binary on my desktop

# Claude Code activates skill 05-malware-analysis
# Runs scripts/static_analyzer.py for initial analysis
# Runs scripts/yara_generator.py to create detection rules
# Outputs .yar file with proper metadata

You: Map the findings to MITRE ATT&CK and create a Splunk detection query

# Claude Code activates skill 06-threat-hunting
# Runs scripts/mitre_mapper.py with ATT&CK technique IDs
# Generates Splunk SPL queries for each mapped technique
```

You can also **explicitly reference a skill** by name:

```
> Use the threat-hunting skill to analyze these IOCs from our SIEM alerts
> Use the reverse-engineering skill to analyze this suspicious binary
> Use the csoc-automation skill to create a phishing incident playbook
```

> 📖 See [INSTALL.md](INSTALL.md) for detailed installation instructions and [USAGE.md](USAGE.md) for comprehensive usage examples.

---

## 📁 Project Structure

```
Claude-Code-CyberSecurity-Skill/
├── README.md                          # This file
├── INSTALL.md                         # Installation guide
├── USAGE.md                           # Usage guide
├── CONTRIBUTING.md                    # Contribution guidelines
├── CODE_OF_CONDUCT.md                 # Community code of conduct
├── SECURITY.md                        # Security policy
├── CHANGELOG.md                       # Version history
├── LICENSE                            # MIT License
├── .gitignore                         # Git ignore rules
│
└── skills/                            # All skills
    ├── 01-recon-osint/                # Recon & OSINT
    │   ├── SKILL.md
    │   ├── scripts/
    │   ├── examples/
    │   └── resources/
    ├── 02-vulnerability-scanner/      # Vulnerability Scanner
    ├── 03-exploit-development/        # Exploit Development
    ├── 04-reverse-engineering/        # Reverse Engineering
    ├── 05-malware-analysis/           # Malware Analysis
    ├── 06-threat-hunting/             # Threat Hunting
    ├── 07-incident-response/          # Incident Response
    ├── 08-network-security/           # Network Security
    ├── 09-web-security/               # Web Security
    ├── 10-cloud-security/             # Cloud Security
    ├── 11-csoc-automation/            # CSOC Automation
    ├── 12-log-analysis/               # Log Analysis & SIEM
    ├── 13-crypto-analysis/            # Crypto Analysis
    ├── 14-red-team-ops/               # Red Team Operations
    └── 15-blue-team-defense/          # Blue Team Defense
```

---

## 🔧 Prerequisites

| Requirement | Version | Purpose                   |
| ----------- | ------- | ------------------------- |
| Python      | 3.8+    | Automation scripts        |
| Claude Code | Latest  | AI coding assistant       |
| Git         | 2.x+    | Repository management     |
| pip         | Latest  | Python package management |

### Optional Tools (Enhanced by Skills)

- **Nmap** — Network scanning (Skill 01, 08)
- **Burp Suite** — Web security testing (Skill 09)
- **Ghidra / IDA** — Reverse engineering (Skill 04)
- **Wireshark / tshark** — Network analysis (Skill 08)
- **Docker** — Sandboxing and container security (Skill 05, 10)
- **Volatility** — Memory forensics (Skill 07)
- **YARA** — Malware detection (Skill 05, 06)

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Adding new skills
- Improving existing skills
- Reporting issues
- Submitting pull requests

---

## 📜 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

> **This tool collection is intended for authorized security testing, research, and educational purposes only.** Users are solely responsible for ensuring compliance with all applicable laws and regulations. The authors assume no liability for misuse. Always obtain proper authorization before conducting security assessments.

---

## 🌟 Star History

If you find this project useful, please consider giving it a ⭐ on [GitHub](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill)!

---

<p align="center">
  <b>Made with ❤️ for the CyberSecurity Community</b>
  <br/>
  <a href="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill">GitHub</a> •
  <a href="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/issues">Issues</a> •
  <a href="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/discussions">Discussions</a>
</p>
