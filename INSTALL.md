# 📦 Installation Guide

> Complete installation instructions for the **Claude Code CyberSecurity Skill Collection**.

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

Before installing, ensure you have the following:

| Tool            | Minimum Version | Check Command       |
| --------------- | --------------- | ------------------- |
| **Git**         | 2.x             | `git --version`     |
| **Python**      | 3.8+            | `python3 --version` |
| **pip**         | Latest          | `pip3 --version`    |
| **Claude Code** | Latest          | `claude --version`  |

---

## Step 1: Clone the Repository

```bash
# Clone via HTTPS
git clone https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill.git

# Navigate into the directory
cd Claude-Code-CyberSecurity-Skill
```

**Alternative — Clone via SSH:**

```bash
git clone git@github.com:Masriyan/Claude-Code-CyberSecurity-Skill.git
cd Claude-Code-CyberSecurity-Skill
```

---

## Step 2: Install Python Dependencies

Some skills include Python scripts that require additional packages. Install all dependencies:

```bash
# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install all required packages
pip install -r requirements.txt
```

> **Note:** If `requirements.txt` doesn't exist yet, individual skills list their dependencies in their respective `SKILL.md` files.

---

## Step 3: Install Skills into Claude Code

### Understanding Skill Locations

Claude Code looks for skills in **two directories** (checked in this order):

| Priority | Location                    | Scope                    | Best For                            |
| -------- | --------------------------- | ------------------------ | ----------------------------------- |
| 1st      | `<project>/.claude/skills/` | Current project only     | Project-specific security workflows |
| 2nd      | `~/.claude/skills/`         | All Claude Code sessions | General-purpose security skills     |

> **How it works**: When you start a Claude Code session, it scans these directories for folders containing `SKILL.md` files. Claude reads the **YAML frontmatter** (name, description, tags) to understand what each skill does, and activates the relevant skill when your prompt matches its domain.

### Option A: Install All Skills Globally (Recommended)

```bash
# Create the Claude Code skills directory
mkdir -p ~/.claude/skills

# Copy all 15 skills
cp -r skills/* ~/.claude/skills/

# Verify: you should see 15 skill directories
ls ~/.claude/skills/
```

### Option B: Install Individual Skills

```bash
# Example: Install only Threat Hunting + CSOC Automation
cp -r skills/06-threat-hunting/ ~/.claude/skills/
cp -r skills/11-csoc-automation/ ~/.claude/skills/
```

### Option C: Install for a Specific Project Only

```bash
# Skills will only be available when Claude Code is opened in this project
cd /path/to/your/project
mkdir -p .claude/skills
cp -r /path/to/Claude-Code-CyberSecurity-Skill/skills/* .claude/skills/
```

### Option D: Symlink (Development / Contributing)

For contributors who want to test changes in real-time:

```bash
# Changes to the repo automatically apply to Claude Code
ln -s "$(pwd)/skills/"* ~/.claude/skills/
```

---

## Step 4: Verify Installation

### Check Skill Files Are in Place

```bash
# List installed skills — you should see 15 directories
ls -la ~/.claude/skills/

# Verify each skill has a SKILL.md file
find ~/.claude/skills/ -name "SKILL.md" | wc -l
# Should output: 15

# Verify YAML frontmatter is valid
head -3 ~/.claude/skills/06-threat-hunting/SKILL.md
# Should show "---" on line 1
```

### Test with Claude Code

Open Claude Code in your terminal and try these prompts:

```bash
# Start Claude Code
claude
```

```
# Ask Claude what skills are available:
You: What cybersecurity skills do you have available?
# Claude should list the installed skills and their capabilities

# Test a specific skill:
You: Use the recon-osint skill to help me enumerate subdomains for example.com
# Claude should follow the SKILL.md methodology and offer to run
# scripts/subdomain_enum.py

# Test script execution:
You: Run the TLS auditor on google.com
# Claude should execute scripts/tls_auditor.py --host google.com
```

**If Claude does NOT recognize the skills:**

1. Verify the files are in `~/.claude/skills/` (or your project's `.claude/skills/`)
2. Ensure each skill directory contains a `SKILL.md` file with valid YAML frontmatter
3. Restart Claude Code to trigger a fresh skill scan

---

## Platform-Specific Notes

### 🐧 Linux (Ubuntu/Debian)

```bash
# Install prerequisites
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv

# Optional: Install security tools
sudo apt install -y nmap wireshark tshark ncat netcat-openbsd
```

### 🐧 Linux (RHEL/CentOS/Fedora)

```bash
# Install prerequisites
sudo dnf install -y git python3 python3-pip

# Optional: Install security tools
sudo dnf install -y nmap wireshark-cli
```

### 🍎 macOS

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install prerequisites
brew install git python3

# Optional: Install security tools
brew install nmap wireshark
```

### 🪟 Windows

```powershell
# Using winget
winget install Git.Git
winget install Python.Python.3.12

# Or use Chocolatey
choco install git python3 -y

# Note: Some scripts may require WSL2 for full compatibility
```

---

## Optional Tool Installation

These tools enhance specific skills but are not required:

### Reverse Engineering (Skill 04)

```bash
# Ghidra (Free, NSA)
wget https://github.com/NationalSecurityAgency/ghidra/releases/latest -O ghidra.zip
unzip ghidra.zip

# radare2
git clone https://github.com/radareorg/radare2
cd radare2 && sys/install.sh
```

### Malware Analysis (Skill 05)

```bash
# YARA
sudo apt install -y yara
pip install yara-python

# Docker for sandboxing
sudo apt install -y docker.io
sudo systemctl enable docker
```

### Network Security (Skill 08)

```bash
# Wireshark / tshark
sudo apt install -y wireshark tshark

# Suricata IDS
sudo apt install -y suricata
```

### Memory Forensics (Skill 07)

```bash
# Volatility 3
pip install volatility3
```

### Cloud Security (Skill 10)

```bash
# AWS CLI
pip install awscli

# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Google Cloud SDK
curl https://sdk.cloud.google.com | bash
```

---

## Troubleshooting

### Skills Not Detected

1. Verify the skill files are in `~/.claude/skills/`
2. Ensure each skill directory contains a `SKILL.md` file
3. Restart Claude Code

### Python Script Errors

```bash
# Ensure you're using the virtual environment
source venv/bin/activate

# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

### Permission Issues

```bash
# Fix permissions on skill files
chmod -R 755 ~/.claude/skills/

# Fix script permissions
find ~/.claude/skills/ -name "*.py" -exec chmod +x {} \;
find ~/.claude/skills/ -name "*.sh" -exec chmod +x {} \;
```

### Windows Path Issues

If you're on Windows, ensure paths use forward slashes or escaped backslashes in configuration files.

---

## Updating

To update to the latest version:

```bash
cd Claude-Code-CyberSecurity-Skill
git pull origin main

# Reinstall skills
cp -r skills/* ~/.claude/skills/
```

---

## Uninstalling

```bash
# Remove all skills
rm -rf ~/.claude/skills/01-recon-osint/
rm -rf ~/.claude/skills/02-vulnerability-scanner/
# ... (repeat for each skill)

# Or remove all at once
rm -rf ~/.claude/skills/[0-1][0-9]-*/

# Remove the repository
cd ..
rm -rf Claude-Code-CyberSecurity-Skill
```

---

<p align="center">
  <a href="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill">← Back to Main Repository</a>
</p>
