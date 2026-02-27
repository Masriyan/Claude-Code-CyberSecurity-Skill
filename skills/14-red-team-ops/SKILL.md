---
name: Red Team Operations & C2 Framework
description: Red team engagement planning, C2 infrastructure setup, lateral movement, persistence, and social engineering
version: 1.0.0
author: Masriyan
tags: [cybersecurity, red-team, c2, lateral-movement, persistence, pentest]
---

# 🔴 Red Team Operations & C2 Framework

## Overview

This skill enables Claude to assist authorized red team operators with engagement planning, C2 infrastructure design, attack methodology, lateral movement strategy, persistence mechanisms, and comprehensive reporting.

> **⚠️ CRITICAL**: This skill is for AUTHORIZED red team operations ONLY. All activities must be within a defined scope with written authorization. Unauthorized use is illegal.

---

## Prerequisites

- Python 3.8+
- `pyyaml`, `requests`

### Optional Tools

- **Cobalt Strike / Sliver / Havoc** — C2 frameworks
- **Metasploit** — Exploitation framework
- **BloodHound** — AD attack path analysis
- **Impacket** — Network protocol tools
- **CrackMapExec** — AD enumeration/exploitation
- **Responder** — LLMNR/NBT-NS poisoning

```bash
pip install pyyaml requests impacket
```

---

## Core Capabilities

### 1. Red Team Engagement Planning

**When the user asks to plan an engagement:**

1. Define objectives, scope, and rules of engagement
2. Create attack scenario narratives (APT simulation)
3. Map target infrastructure and attack surface
4. Plan the kill chain phases
5. Define success criteria and reporting requirements
6. Create deconfliction procedures
7. Plan communication channels with blue team POCs
8. Document emergency abort procedures

### 2. C2 Infrastructure Design

**When the user asks about C2:**

1. Design multi-tier C2 architecture (redirectors → team servers)
2. Configure HTTPS/DNS/DoH/WebSocket C2 channels
3. Set up domain fronting or cloud redirectors
4. Implement malleable C2 profiles for evasion
5. Plan backup C2 channels
6. Set up logging and operational security measures
7. Implement automated infrastructure teardown

### 3. Lateral Movement Strategy

**When the user asks about lateral movement:**

1. Enumerate Active Directory attack paths (BloodHound)
2. Identify privilege escalation opportunities
3. Plan WMI/PSExec/WinRM/DCOM movement techniques
4. Kerberoasting and AS-REP roasting strategies
5. Pass-the-Hash / Pass-the-Ticket techniques
6. Token impersonation and delegation abuse
7. GPO abuse for mass deployment
8. Document each movement step for reporting

### 4. Persistence Mechanisms

**When the user asks about persistence:**

1. Registry run keys and startup folder persistence
2. Scheduled tasks and services
3. DLL hijacking and COM objects
4. WMI event subscriptions
5. Golden/Silver ticket creation
6. DACL/SACL manipulation
7. Web shells for web server persistence
8. Firmware/UEFI-level persistence (advanced)

### 5. Social Engineering

**When the user asks about social engineering:**

1. Phishing campaign planning and templates
2. Pretexting scenarios
3. Callback phishing (vishing) scripts
4. USB drop attack planning
5. Physical security assessment methodology
6. Badge cloning and tailgating strategies

---

## Usage Instructions

### Example Prompts

```
> Plan a red team engagement for testing our AD security
> Design a resilient C2 infrastructure for an authorized test
> What lateral movement techniques should I try after initial compromise?
> Create persistence mechanisms for continued access during the engagement
> Generate a phishing pretext for our authorized social engineering test
```

---

## Script Reference

### `engagement_planner.py`

```bash
python scripts/engagement_planner.py --scope scope.json --output plan.md
```

---

## Integration Guide

- **← Exploit Development (03)**: Use exploits within red team operations
- **← Recon & OSINT (01)**: Initial reconnaissance for target profiling
- **→ Blue Team Defense (15)**: Provide findings for defensive improvements
- **→ CSOC Automation (11)**: Test SOC detection capabilities

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Red Team Field Manual](https://doc.lagout.org/rtfm-red-team-field-manual.pdf)
- [Sliver C2 Documentation](https://github.com/BishopFox/sliver)
- [Cobalt Strike User Guide](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/)
- [The Hacker Playbook 3](https://www.thehackerplaybook.com/)
