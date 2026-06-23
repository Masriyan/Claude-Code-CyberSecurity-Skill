---
name: Incident Response & Digital Forensics
description: IR playbook execution, evidence collection, forensic timeline analysis, memory forensics, and post-incident reporting following NIST SP 800-61 and SANS PICERL methodology
version: 3.0.0
author: Masriyan
tags: [cybersecurity, incident-response, forensics, dfir, evidence, timeline, picerl, nist]
---

# Incident Response & Digital Forensics

## Purpose

Enable Claude to assist with structured incident response operations following NIST SP 800-61 and the SANS PICERL framework. Claude generates IR playbooks, guides evidence collection with chain of custody, constructs forensic timelines, interprets memory forensics output, and produces post-incident reports.

---

## Activation Triggers

This skill activates when the user asks about:
- Creating an incident response playbook (ransomware, phishing, breach, etc.)
- Evidence collection and chain of custody procedures
- Forensic timeline construction from logs or artifacts
- Memory forensics using Volatility
- Post-incident report generation
- DFIR (Digital Forensics and Incident Response) procedures
- Containment and eradication strategies
- Root cause analysis for security incidents
- IR metrics, SLA tracking, or reporting for management

---

## Prerequisites

```bash
pip install pyyaml jinja2 pandas python-dateutil
```

**Recommended DFIR tools:**
- `Volatility 3` — Memory forensics framework
- `Autopsy / Sleuth Kit` — Disk forensics
- `plaso / log2timeline` — Supertimeline generation
- `KAPE` — Evidence collection (Windows)
- `Velociraptor` — Enterprise-scale endpoint forensics
- `FTK Imager` — Forensic imaging (Windows)
- `dd / dcfldd / dc3dd` — Disk imaging (Linux)

---

## PICERL Framework Overview

Every IR engagement follows the PICERL lifecycle:

| Phase | Key Actions | Skill Outputs |
|-------|------------|---------------|
| **P**reparation | Verify tools, comms, access | Readiness checklist |
| **I**dentification | Confirm incident, scope, severity | Incident classification |
| **C**ontainment | Isolate systems, stop spread | Containment actions list |
| **E**radication | Remove threat, close access | Eradication checklist |
| **R**ecovery | Restore systems, verify integrity | Recovery runbook |
| **L**essons Learned | Post-incident review | IR report + improvements |

---

## Core Capabilities

### 1. IR Playbook Creation

**When the user asks to create a playbook for a specific incident type:**

Claude generates detailed, role-assigned playbooks in this structure:

**Ransomware Response Playbook (Example):**

```markdown
# IR Playbook: Ransomware Attack
Version: 2.0 | Owner: SOC Manager | Review: Quarterly

## Trigger Conditions
- Multiple encrypted files discovered (ransom extension detected)
- Ransom note found on file shares or desktop
- EDR alert for mass file modification activity
- User reports files inaccessible with unfamiliar extensions

## Severity Classification
- CRITICAL: Domain controller / backup infrastructure affected
- HIGH: Production servers / business-critical data affected
- MEDIUM: Isolated workstation, contained environment

---

## Phase 1: Identification (Target: 15 minutes)
**IR Lead:**
- [ ] Confirm incident is ransomware (verify encrypted files + ransom note)
- [ ] Determine initial infection vector (phishing? RDP? Supply chain?)
- [ ] Identify Patient Zero — first encrypted system
- [ ] Assess scope: How many systems? Which business units?
- [ ] Declare incident severity and notify stakeholders
- [ ] Open incident ticket and begin documentation

**Forensics:**
- [ ] DO NOT REBOOT infected systems (preserve volatile evidence)
- [ ] Capture memory dump: `winpmem_mini_x64_rc2.exe output.raw`
- [ ] Collect running processes: `tasklist /v > processes.txt`
- [ ] Collect network connections: `netstat -ano > netstat.txt`

## Phase 2: Containment (Target: 30 minutes)
**Network Team:**
- [ ] Isolate affected systems (pull network cable or quarantine in VLAN)
- [ ] Block identified C2 IPs/domains at perimeter firewall
- [ ] Disable RDP externally if RDP was the initial vector
- [ ] Preserve network capture if encryption is still occurring

**Active Directory:**
- [ ] Identify all accounts used by the ransomware (service accounts, domain accounts)
- [ ] Reset passwords for all potentially compromised accounts
- [ ] Revoke active sessions for affected accounts
- [ ] Check for newly created privileged accounts

## Phase 3: Eradication
- [ ] Identify all persistence mechanisms (registry, services, scheduled tasks)
- [ ] Remove all malicious artifacts
- [ ] Verify no backdoors remain (check with Autoruns, process scanning)
- [ ] Patch the exploited vulnerability if one was used

## Phase 4: Recovery
- [ ] Restore from clean backup (verified pre-infection)
- [ ] Validate backup integrity before restoration
- [ ] Rebuild from gold image if backup compromised
- [ ] Verify data integrity after restoration
- [ ] Phased return to production

## Phase 5: Lessons Learned (Within 2 weeks)
- [ ] Full incident timeline documented
- [ ] Root cause identified and remediated
- [ ] Detection gaps addressed
- [ ] CSOC playbook updated
- [ ] Management report delivered
```

**Other supported playbook types:**
- Phishing Campaign Response
- Data Breach / Exfiltration
- Business Email Compromise (BEC)
- Insider Threat
- DDoS Attack
- Account Compromise / Credential Stuffing
- Supply Chain Compromise
- Cloud Misconfiguration / Breach

### 2. Evidence Collection & Chain of Custody

**When the user asks to collect forensic evidence:**

**Order of Volatility (most volatile → least volatile):**
```
1. CPU registers and cache
2. Routing tables, ARP cache, process table
3. Memory (RAM) — ALWAYS capture first
4. Temporary file systems, swap space
5. Running processes and open files
6. Network connections and open ports
7. Disk images
8. Log files (local + remote SIEM)
9. Physical media
```

**Evidence Collection Commands:**

```bash
# Windows — Live acquisition
winpmem_mini_x64_rc2.exe memory.raw              # Memory dump
tasklist /svc > processes.txt                     # Running processes
netstat -ano > connections.txt                    # Network connections
wmic process get caption,processid,parentprocessid,commandline > process_full.txt
reg export HKLM reg_hklm.reg                     # Registry
dir /s /a "C:\Users\*\AppData\Roaming\*" > appdata.txt

# Linux — Live acquisition
sudo avml /tmp/memory.lime                        # Memory dump (avml)
ps auxf > processes.txt                           # Process tree
netstat -tulnap > connections.txt                 # Network connections
cat /proc/*/cmdline | strings > process_cmdlines.txt
ls -la /tmp/ /var/tmp/ /dev/shm/ > temp_dirs.txt
crontab -l -u root > crontabs.txt
find / -mtime -7 -type f > recently_modified.txt  # Modified in last 7 days
```

**Chain of Custody Template:**
```markdown
## Evidence Chain of Custody Form

| Field | Value |
|-------|-------|
| Evidence ID | IR-2025-001-E01 |
| Incident ID | IR-2025-001 |
| Description | Memory dump from HOSTNAME (192.168.1.100) |
| Collected by | [Analyst Name] |
| Collection time | 2025-05-28 14:30 UTC |
| Collection method | winpmem_mini_x64_rc2.exe |
| MD5 hash | [hash of evidence file] |
| SHA256 hash | [hash of evidence file] |
| Storage location | \nas\ir\IR-2025-001\evidence\ |
| Chain of custody | Analyst → Evidence Locker → Lab |

**Access Log:**
| Date/Time | Person | Purpose | Signature |
|-----------|--------|---------|-----------|
| 2025-05-28 14:30 | [Analyst] | Initial collection | [Sig] |
```

### 3. Forensic Timeline Analysis

**When the user asks to build an incident timeline:**

1. **Collect timestamps from all available sources:**
   - Windows Event Logs (Security, System, Application, PowerShell)
   - Web server access logs
   - Firewall / proxy logs
   - Email server logs (delivery, read receipts)
   - File system timestamps (Modified, Accessed, Changed, Born)
   - Registry LastWrite timestamps
   - Prefetch timestamps (evidence of execution)

2. **Normalize to UTC** — Confirm system timezone before conversion

3. **Generate supertimeline:**
   ```bash
   python scripts/timeline_builder.py --logs ./collected_logs/ --output timeline.csv
   python scripts/timeline_builder.py --logs ./logs/ --format html --start "2025-05-20" --end "2025-05-28"
   ```

4. **Identify the kill chain progression:**

```markdown
## Incident Timeline — [Incident ID]

[T-72h] 2025-05-25 09:15 UTC — DELIVERY
  Phishing email received: "Invoice_May2025.pdf.exe" from spoofed sender
  Mail log: SMTP delivery to user@victim.com from 185.x.x.x

[T-48h] 2025-05-26 14:22 UTC — EXECUTION
  User executed attachment: Event 4688 (process creation)
  Parent: outlook.exe → Child: powershell.exe -enc [base64]

[T-48h] 2025-05-26 14:22 UTC — C2 ESTABLISHED
  Outbound connection: 203.x.x.x:443 (beacon_interval: 60s)
  DNS query: malicious-c2.evil.com → 203.x.x.x

[T-24h] 2025-05-27 02:00 UTC — LATERAL MOVEMENT
  PsExec from WORKSTATION01 to SERVER02 (admin$)
  Event 4624 (login type 3) on SERVER02 from WORKSTATION01

[T-2h]  2025-05-27 12:30 UTC — DATA EXFILTRATION
  Large POST request (450MB) to dropbox-like service

[T-0h]  2025-05-28 14:00 UTC — DETECTION
  SOC analyst detected anomalous outbound transfer
```

### 4. Memory Forensics

**When the user shares Volatility output or asks about memory forensics:**

**Essential Volatility 3 Commands:**
```bash
# Process listing
python vol.py -f memory.raw windows.pslist
python vol.py -f memory.raw windows.pstree           # Show parent-child
python vol.py -f memory.raw windows.psscan           # Find hidden processes

# Network connections
python vol.py -f memory.raw windows.netscan
python vol.py -f memory.raw windows.netstat

# DLL and module analysis
python vol.py -f memory.raw windows.dlllist --pid [PID]
python vol.py -f memory.raw windows.modscan          # All loaded modules

# Malware detection
python vol.py -f memory.raw windows.malfind           # Injected code
python vol.py -f memory.raw windows.hollowfind        # Process hollowing

# Registry from memory
python vol.py -f memory.raw windows.registry.hivelist
python vol.py -f memory.raw windows.registry.printkey --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# File artifacts
python vol.py -f memory.raw windows.filescan
python vol.py -f memory.raw windows.dumpfiles --physaddr [addr]
```

**Suspicious Memory Indicators:**
- Process without corresponding disk file (process hollowing)
- `explorer.exe` or `svchost.exe` with unusual parent
- Network connections from system processes (lsass.exe, csrss.exe)
- Executable memory regions flagged by `windows.malfind`
- Stacked THREADS in injected shellcode regions

### 5. Post-Incident Report

**When the user asks for an IR report for management or compliance:**

```markdown
# Post-Incident Report — [Incident ID]

**Classification:** CONFIDENTIAL
**Incident Type:** [Ransomware / Data Breach / etc.]
**Severity:** [Critical / High / Medium]
**Incident Window:** [Start] to [End] UTC
**Systems Affected:** [Count and names]
**Data Impact:** [Data at risk / confirmed exfiltrated]
**Report Date:** [Date]
**Report Author:** [IR Lead]

---

## 1. Executive Summary
[3-4 sentences: what happened, how it happened, impact, and current status]

## 2. Incident Timeline
[Key events table with timestamps]

## 3. Root Cause Analysis
**Initial Vector:** [Phishing / Unpatched service / Credential theft / etc.]
**Root Cause:** [Specific technical cause]
**Contributing Factors:**
- [Factor 1: e.g., no MFA on VPN]
- [Factor 2: e.g., delayed patch deployment]

## 4. Impact Assessment
- **Systems Compromised:** [List]
- **Data Accessed/Exfiltrated:** [Description + quantity]
- **Business Impact:** [Downtime hours, revenue impact, regulatory]
- **Customer/Partner Impact:** [If applicable]

## 5. Containment & Remediation Actions
[Chronological list of actions taken]

## 6. Compliance Notification Requirements
- **GDPR:** [Required if EU personal data — 72-hour notification to DPA]
- **HIPAA:** [Required if PHI — notify HHS within 60 days]
- **PCI-DSS:** [Required if cardholder data — notify card brands immediately]
- **State breach laws:** [Applicable laws and timelines]

## 7. Recommendations
| Priority | Recommendation | Owner | Due Date |
|----------|---------------|-------|---------|
| Critical | Deploy MFA for all remote access | IT | 2025-06-01 |
| High | Accelerate patch cycle for internet-facing systems | IT | 2025-06-15 |
| Medium | Implement email attachment sandboxing | Security | 2025-07-01 |

## 8. Lessons Learned
[What worked, what didn't, process improvements]
```

---

## Script Reference

### `timeline_builder.py`
```bash
python scripts/timeline_builder.py --logs ./collected_logs/ --output timeline.csv
python scripts/timeline_builder.py --logs ./logs/ --format html --start "2025-05-20" --end "2025-05-28"
```

---

## Skill Integration

| Condition | Adjacent Skill |
|-----------|---------------|
| Alert received from SOC → activate IR | ← Skill 11 (CSOC Automation) |
| Malware samples collected → analyze | → Skill 05 (Malware Analysis) |
| IOCs extracted → hunt in environment | → Skill 06 (Threat Hunting) |
| Log deep-dive needed | → Skill 12 (Log Analysis) |

---

## References

- [NIST SP 800-61 Rev. 2 — Computer Security Incident Handling](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Response Process](https://www.sans.org/white-papers/33901/)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [Velociraptor Documentation](https://docs.velociraptor.app/)
- [DFIR.training Resource Hub](https://www.dfir.training/)
- [The Art of Memory Forensics (Book)](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics-p-9781118825099)


---

## v3.0 Enhancements (2026 Update)

**Cloud- and identity-era IR:**

- **Cloud IR** — pull and triage AWS CloudTrail, Azure Activity/Entra sign-in & audit, and GCP Audit logs; preserve volatile cloud state (snapshots, IAM key disabling) before remediation.
- **Identity & SaaS compromise** — handle token theft/replay, OAuth consent abuse, and federated trust attacks; revoke sessions/refresh tokens, rotate signing keys, review conditional-access.
- **Modern toolkit** — Velociraptor for fleet-scale collection; Hayabusa/Chainsaw + Sigma over EVTX for rapid Windows timelining; KAPE for triage images.
- **Ransomware specifics** — identify double/triple-extortion, exfil-before-encrypt evidence, ESXi/Linux scope, and recovery validation against immutable backups.
- **Business Email Compromise** — inbox-rule and forwarding abuse, app-password persistence, mailbox audit log review.

**Process rule (unchanged priority):** follow NIST SP 800-61 / SANS PICERL; preserve chain of custody; in cloud/OT contexts weigh evidence preservation against service/safety continuity (→ Skill 18 for OT).
