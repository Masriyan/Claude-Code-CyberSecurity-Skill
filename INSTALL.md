# Installation Guide

Complete installation instructions for the **Claude Code CyberSecurity Skill Collection v2.0**.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Clone the Repository](#step-1-clone-the-repository)
- [Step 2: Install Python Dependencies](#step-2-install-python-dependencies)
- [Step 3: Install Skills into Claude Code](#step-3-install-skills-into-claude-code)
- [Step 4: Verify Installation](#step-4-verify-installation)
- [Platform-Specific Notes](#platform-specific-notes)
- [Optional Tool Installation](#optional-tool-installation)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Tool            | Minimum Version | Check Command        |
| --------------- | --------------- | -------------------- |
| **Git**         | 2.x             | `git --version`      |
| **Python**      | 3.10+           | `python3 --version`  |
| **pip**         | 22+             | `pip3 --version`     |
| **Claude Code** | Latest          | `claude --version`   |

---

## Step 1: Clone the Repository

```bash
git clone https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill.git
cd Claude-Code-CyberSecurity-Skill
```

---

## Step 2: Install Python Dependencies

The scripts use mostly standard-library modules. Only a few skills require third-party packages.

```bash
# Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate       # Linux/macOS
# venv\Scripts\activate        # Windows

# Install optional dependencies for enhanced script functionality
pip install requests           # Skills 01, 09 (HTTP requests)
pip install pyyaml             # Skills 02, 09, 11 (YAML OpenAPI specs)
pip install boto3              # Skill 10 (AWS SDK — alternative to AWS CLI)
pip install yara-python        # Skill 05 (YARA rule compilation)
pip install scapy              # Skill 08 (PCAP analysis)
```

Scripts degrade gracefully when optional dependencies are absent — they print a warning and skip the feature that requires the missing package.

---

## Step 3: Install Skills into Claude Code

### Understanding Skill Locations

Claude Code looks for skills in two directories:

| Priority | Location                     | Scope                     | Best For                            |
| -------- | ---------------------------- | ------------------------- | ----------------------------------- |
| 1st      | `<project>/.claude/skills/`  | Current project only      | Project-specific security workflows |
| 2nd      | `~/.claude/skills/`          | All Claude Code sessions  | General-purpose security skills     |

When a session starts, Claude reads each `SKILL.md` file's YAML frontmatter (name, description, tags) and activates the relevant skill when your prompt matches its domain.

### Option A: Install All Skills Globally (Recommended)

```bash
mkdir -p ~/.claude/skills
cp -r skills/* ~/.claude/skills/

# Verify — should list 15 directories
ls ~/.claude/skills/
```

### Option B: Install Individual Skills

```bash
# Example: Install only Threat Hunting and CSOC Automation
cp -r skills/06-threat-hunting/   ~/.claude/skills/
cp -r skills/11-csoc-automation/  ~/.claude/skills/
```

### Option C: Project-Scoped Installation

```bash
cd /path/to/your/project
mkdir -p .claude/skills
cp -r /path/to/Claude-Code-CyberSecurity-Skill/skills/* .claude/skills/
```

### Option D: Symlink (for Contributors)

```bash
# Changes to the repo immediately reflect in Claude Code
ln -s "$(pwd)/skills/"* ~/.claude/skills/
```

---

## Step 4: Verify Installation

### Check Files Are in Place

```bash
# Count SKILL.md files — should output 15
find ~/.claude/skills/ -name "SKILL.md" | wc -l

# Verify YAML frontmatter on a sample skill
head -5 ~/.claude/skills/06-threat-hunting/SKILL.md
# Expected: "---" on line 1, then name/description/version/tags
```

### Test Scripts Directly

```bash
# CVSS calculator (no external dependencies)
python3 ~/.claude/skills/02-vulnerability-scanner/scripts/cvss_calculator.py \
  --vector "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# Expected: Score 9.8 / Critical

# Anomaly detector demo
python3 ~/.claude/skills/12-log-analysis/scripts/anomaly_detector.py --demo
# Expected: 11 anomalies detected in sample data

# SOC report demo
python3 ~/.claude/skills/11-csoc-automation/scripts/report_generator.py \
  --shift day --date 2024-01-15 --demo
# Expected: Markdown shift handover report
```

### Test with Claude Code

```bash
claude
```

```
# Ask Claude what skills are loaded:
> What cybersecurity skills do you have available?

# Test a specific skill:
> Use the threat-hunting skill to map T1059.001 to MITRE ATT&CK

# Test script execution:
> Run the TLS auditor on google.com
```

If Claude does not recognize the skills:
1. Confirm files exist in `~/.claude/skills/` (or `.claude/skills/` for project scope)
2. Confirm each directory contains a `SKILL.md` with valid YAML frontmatter
3. Restart Claude Code to trigger a fresh skill scan

---

## Platform-Specific Notes

### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv

# Optional security tools
sudo apt install -y nmap wireshark tshark ncat netcat-openbsd
```

### Linux (RHEL/CentOS/Fedora)

```bash
sudo dnf install -y git python3 python3-pip

# Optional security tools
sudo dnf install -y nmap wireshark-cli
```

### macOS

```bash
brew install git python3

# Optional security tools
brew install nmap wireshark
```

### Windows

```powershell
winget install Git.Git
winget install Python.Python.3.12

# Note: Some scripts use Linux-specific commands (ss, lsof, etc.)
# For full compatibility, use WSL2 on Windows
```

---

## Optional Tool Installation

These tools extend specific skills but are not required:

### Reverse Engineering (Skill 04)

```bash
# radare2
git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh

# Ghidra — download from https://ghidra-sre.org/
```

### Malware Analysis (Skill 05)

```bash
sudo apt install -y yara
pip install yara-python

# Docker for isolated sandbox
sudo apt install -y docker.io && sudo systemctl enable docker
```

### Network Security (Skill 08)

```bash
sudo apt install -y wireshark tshark suricata
pip install scapy
```

### Incident Response (Skill 07)

```bash
# Volatility 3 for memory forensics
pip install volatility3
```

### Cloud Security (Skill 10)

```bash
# AWS CLI
pip install awscli    # then: aws configure

# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash    # then: az login

# Google Cloud SDK — https://cloud.google.com/sdk/docs/install
# then: gcloud auth login
```

---

## Troubleshooting

### Skills Not Detected

1. Verify `~/.claude/skills/<skill-dir>/SKILL.md` exists
2. Check that YAML frontmatter opens with `---` on line 1
3. Restart Claude Code

### Python Script Errors

```bash
# Ensure virtual environment is active
source venv/bin/activate

# Install a specific missing package
pip install <package-name>

# Test a script in isolation
python3 skills/<skill>/scripts/<script>.py --help
```

### Permission Issues

```bash
chmod -R 755 ~/.claude/skills/
find ~/.claude/skills/ -name "*.py" -exec chmod +x {} \;
```

---

## Updating

```bash
cd Claude-Code-CyberSecurity-Skill
git pull origin main
cp -r skills/* ~/.claude/skills/
```

## Uninstalling

```bash
rm -rf ~/.claude/skills/[0-1][0-9]-*/
rm -rf Claude-Code-CyberSecurity-Skill/
```

---

[Back to Main Repository](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill)
