---
name: Threat Hunting & IOC Analysis
description: IOC extraction, threat intelligence correlation, MITRE ATT&CK mapping, hunt hypothesis generation, and detection rule creation
version: 3.0.0
author: Masriyan
tags: [cybersecurity, threat-hunting, ioc, mitre-attack, threat-intelligence, sigma, detection, siem]
---

# Threat Hunting & IOC Analysis

## Purpose

Enable Claude to assist threat hunters with proactive threat detection, IOC extraction and normalization, MITRE ATT&CK mapping, hunt hypothesis generation, and converting threat intelligence into actionable detection rules across all major SIEM platforms.

---

## Activation Triggers

This skill activates when the user asks about:
- Extracting IOCs from threat reports, emails, or security advisories
- Mapping behaviors or TTPs to MITRE ATT&CK framework
- Generating hunt hypotheses for a specific threat actor or technique
- Creating Sigma rules, Splunk SPL queries, KQL, or EQL
- Converting threat intelligence into SIEM detection queries
- STIX/TAXII or MISP-compatible indicator formatting
- ATT&CK Navigator layer creation
- Threat intelligence correlation across multiple sources
- Proactive threat hunting in a SIEM or EDR

---

## Prerequisites

```bash
pip install requests pyyaml stix2 taxii2-client
```

**Optional platforms:**
- MISP — Threat intelligence sharing platform
- OpenCTI — Threat intelligence platform
- YARA — Pattern matching (→ Skill 05)
- Sigma CLI — Rule conversion tool
- SIEM access (Splunk, Elastic, QRadar, Microsoft Sentinel)

---

## Core Capabilities

### 1. IOC Extraction & Normalization

**When the user provides a threat report, article, email, or log snippet:**

Claude performs these extraction steps:

1. **Parse all text** for indicators using pattern matching:

| IOC Type | Pattern Examples |
|----------|----------------|
| IPv4 | `192.0.2.1`, defanged: `192[.]0[.]2[.]1` |
| IPv6 | `2001:db8::1` |
| Domain | `evil.example.com`, `evil[.]example[.]com` |
| URL | `hxxp://evil.com/path`, `https://malicious[.]io/c2` |
| Email | `attacker@evil.com`, `phish[at]evil.com` |
| MD5 | 32 hex chars |
| SHA1 | 40 hex chars |
| SHA256 | 64 hex chars |
| CVE | `CVE-2024-XXXXX` |
| ATT&CK ID | `T1059.001`, `TA0001` |
| Registry Key | `HKCU\Software\...` |
| File path | `C:\Windows\Temp\...`, `/tmp/...` |
| Mutex | Named mutex patterns |

2. **Defang extracted indicators** — refang before use:
   - `hxxp://` → `http://`
   - `[.]` → `.`
   - `[at]` → `@`
   - `[:]` → `:`

3. **Categorize by type**: Network / File / Host / Identity / Vulnerability

4. **Score by confidence**: High (specific, sourced), Medium (inferred), Low (generic)

5. **Output in multiple formats**:

```bash
python scripts/ioc_extractor.py --input threat_report.txt --output iocs.json
python scripts/ioc_extractor.py --input report.pdf --format stix --output iocs.stix.json
python scripts/ioc_extractor.py --input email.eml --defang --output iocs.csv
```

**STIX 2.1 output template:**
```json
{
  "type": "indicator",
  "id": "indicator--[uuid]",
  "created": "2025-05-28T00:00:00.000Z",
  "name": "Malicious IP — C2 Infrastructure",
  "pattern": "[ipv4-addr:value = '192.0.2.10']",
  "pattern_type": "stix",
  "valid_from": "2025-05-28T00:00:00Z",
  "labels": ["malicious-activity", "c2"],
  "confidence": 85
}
```

### 2. MITRE ATT&CK Mapping

**When the user provides TTPs, behaviors, or a malware report:**

```bash
python scripts/mitre_mapper.py --input techniques.txt --output attack_map.json
python scripts/mitre_mapper.py --technique T1059.001 --detection-query splunk
```

**Mapping process:**

1. Analyze each behavior against ATT&CK technique descriptions
2. Map to specific Tactic → Technique → Sub-technique (T1059 → T1059.001)
3. Assign confidence level based on evidence quality

**ATT&CK Tactics Reference:**
| Tactic | ID | Description |
|--------|----|-------------|
| Reconnaissance | TA0043 | Pre-attack information gathering |
| Resource Development | TA0042 | Establishing attack resources |
| Initial Access | TA0001 | Entry into target environment |
| Execution | TA0002 | Running malicious code |
| Persistence | TA0003 | Maintaining foothold |
| Privilege Escalation | TA0004 | Gaining higher permissions |
| Defense Evasion | TA0005 | Avoiding detection |
| Credential Access | TA0006 | Stealing credentials |
| Discovery | TA0007 | Understanding environment |
| Lateral Movement | TA0008 | Moving through network |
| Collection | TA0009 | Gathering data of interest |
| Command & Control | TA0011 | Communicating with compromised hosts |
| Exfiltration | TA0010 | Stealing data |
| Impact | TA0040 | Disrupting/destroying systems |

**ATT&CK Navigator Layer format** (JSON for visualization):
```json
{
  "name": "Threat Hunt Layer — [Threat Actor/Campaign]",
  "versions": {"attack": "14", "navigator": "4.9"},
  "domain": "enterprise-attack",
  "techniques": [
    {
      "techniqueID": "T1059.001",
      "color": "#ff6666",
      "comment": "Observed PowerShell download cradle",
      "enabled": true,
      "score": 100
    }
  ]
}
```

### 3. Hunt Hypothesis Generation

**When the user asks for hunt hypotheses:**

Use this structured hypothesis template:

```markdown
## Hunt Hypothesis — [ID]: [Short Name]

**Hypothesis Statement:**
"We believe [Threat Actor/TTPs] may be present in [Environment] based on
[Threat Intelligence / Recent Incidents / Industry Reports]."

**Rationale:**
[Why this threat is relevant to this organization — industry, exposure, recent news]

**ATT&CK Techniques Covered:**
- T1059.001 — PowerShell
- T1053.005 — Scheduled Task/Job
- T1021.001 — Remote Services: Remote Desktop Protocol

**Data Sources Required:**
- Windows Event Logs (Security, System, PowerShell/4104)
- EDR process execution telemetry
- DNS query logs
- Proxy/firewall logs

**Detection Logic:**
[SIEM query or pseudocode]

**Success Criteria:**
- POSITIVE: We find evidence of the technique → escalate to IR (Skill 07)
- NEGATIVE: No evidence after thorough search → document as cleared hunt
- INCONCLUSIVE: Insufficient data → identify logging gaps

**Estimated Hunt Duration:** [X hours]
**Priority:** [High / Medium / Low]
**Analyst:** [Name]
```

### 4. SIEM Detection Query Library

**When the user asks to build detection queries for specific techniques:**

#### Splunk SPL Queries

```spl
// T1059.001 — PowerShell Execution with suspicious flags
index=windows (source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)
| search ScriptBlockText IN ("*DownloadString*", "*IEX*", "*EncodedCommand*", "*bypass*", "*WebClient*")
| stats count by ComputerName, UserName, ScriptBlockText
| where count > 0

// T1003.001 — LSASS Memory Dump
index=windows EventCode=10 TargetImage="*lsass.exe"
| where NOT (SourceImage IN ("C:\\Windows\\System32\\*", "C:\\Program Files\\*"))
| table _time, SourceImage, TargetImage, GrantedAccess, CallTrace

// T1547.001 — Registry Run Key Persistence
index=windows EventCode=13 TargetObject IN ("*\\Run\\*", "*\\RunOnce\\*")
| where NOT (Image IN ("C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*"))
| table _time, ComputerName, Image, TargetObject, Details

// T1021.002 — Lateral Movement via SMB Admin Shares
index=windows EventCode=5140
| where ShareName IN ("\\\\*\\ADMIN$", "\\\\*\\C$", "\\\\*\\IPC$")
| stats count by SubjectUserName, IpAddress, ShareName, ObjectType
| where count > 3
```

#### Microsoft Sentinel KQL

```kql
// T1110.001 — Brute Force Login Attempt
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailCount=count() by TargetAccount, IpAddress=replace(@"\.", "[.]", tostring(parse_json(EventData).IpAddress))
| where FailCount > 20
| join kind=leftouter (
    SecurityEvent | where EventID == 4624
    | summarize SuccessCount=count() by TargetAccount
) on TargetAccount
| project TargetAccount, IpAddress, FailCount, SuccessCount
| where isnotnull(SuccessCount)  // Brute force succeeded!

// T1190 — Exploit Public-Facing Application
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where action_s == "Blocked"
| where ruleSetVersion_s startswith "3."
| summarize count() by clientIp_s, requestUri_s, ruleId_s
| where count_ > 100
| order by count_ desc
```

#### Elastic EQL

```eql
// T1055 — Process Injection
sequence by host.name
  [process where process.name : "notepad.exe" and event.type == "start"]
  [process where event.type == "start" and process.parent.name : "notepad.exe"
   and not process.name in ("conhost.exe")]

// T1566.001 — Spearphishing with attachment
sequence by user.name within 5m
  [file where file.extension in ("doc", "xls", "pdf") and 
   process.name : ("outlook.exe", "WINWORD.EXE")]
  [process where process.name : ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")]
```

#### Sigma Rule Template

```yaml
title: Suspicious PowerShell Download Cradle
id: a3c2f1b4-8e9d-4a2c-b7f6-1234567890ab
status: stable
description: Detects PowerShell commands used to download and execute code from the internet
author: Threat Hunter
date: 2025/05/28
modified: 2025/05/28
references:
  - https://attack.mitre.org/techniques/T1059/001/
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
logsource:
  category: ps_script
  product: windows
  definition: Script Block Logging enabled (EventID 4104)
detection:
  selection:
    ScriptBlockText|contains|all:
      - 'DownloadString'
      - 'IEX'
  selection2:
    ScriptBlockText|contains:
      - '-EncodedCommand'
      - '-enc '
      - '-WindowStyle Hidden'
      - 'Net.WebClient'
      - 'WebProxy'
  condition: selection or selection2
falsepositives:
  - Legitimate software installations
  - Administrative scripts
level: high
```

### 5. Threat Intelligence Correlation

**When the user asks to correlate IOCs or identify threat actors:**

1. Cross-reference infrastructure across known campaigns:
   - Same registrar + similar registration dates → likely related infrastructure
   - IP hosting multiple C2 domains → infrastructure cluster
   - Certificate SAN fields → reveal connected domains

2. Map to threat actor groups:
   - MITRE ATT&CK Groups: https://attack.mitre.org/groups/
   - VirusTotal/OpenCTI actor tracking
   - Mandiant / CrowdStrike / SentinelOne threat intel reports

3. Generate Threat Assessment:
   ```markdown
   ## Threat Assessment — [Campaign Name]
   
   **Threat Actor:** [APT Group / Criminal Group / Unknown]
   **Confidence:** [High / Medium / Low]
   **Motivation:** [Espionage / Financial / Hacktivism]
   **Targeting:** [Industries / Countries / Organization types]
   
   **Campaign IOCs:**
   - Infrastructure: [IPs, domains]
   - Malware: [Family names, hashes]
   - TTPs: [ATT&CK technique IDs]
   
   **Relevance to Organization:**
   [Why this threat is or isn't relevant]
   
   **Recommended Actions:**
   1. Block IOCs in firewall/proxy
   2. Hunt for T1XXX in SIEM
   3. Deploy YARA rules for detection
   ```

---

## Script Reference

### `ioc_extractor.py`
```bash
python scripts/ioc_extractor.py --input threat_report.txt --output iocs.json
python scripts/ioc_extractor.py --input report.pdf --format stix --output iocs.stix.json
python scripts/ioc_extractor.py --input email.eml --defang --output iocs.csv
```

### `mitre_mapper.py`
```bash
python scripts/mitre_mapper.py --input techniques.txt --output attack_map.json
python scripts/mitre_mapper.py --technique T1059.001 --detection-query splunk
python scripts/mitre_mapper.py --actor "APT29" --output apt29_layer.json
```

---

## Skill Integration

| Condition | Adjacent Skill |
|-----------|---------------|
| IOCs from malware samples | ← Skill 05 (Malware Analysis) |
| IOCs from IR engagement | ← Skill 07 (Incident Response) |
| Feed hunting queries to SIEM | → Skill 12 (Log Analysis) |
| Generate detection rules | → Skill 15 (Blue Team Defense) |
| Automate response to findings | → Skill 11 (CSOC Automation) |

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [STIX/TAXII Standards](https://oasis-open.github.io/cti-documentation/)
- [Threat Hunting Playbook](https://threathunterplaybook.com/)
- [MISP Threat Intelligence](https://www.misp-project.org/)
- [OpenCTI Platform](https://www.opencti.io/)
- [CISA Advisories](https://www.cisa.gov/cybersecurity-advisories)


---

## v3.0 Enhancements (2026 Update)

**Threat-informed, repeatable hunting:**

- **ATT&CK current version** — map to the latest Enterprise matrix (incl. updated cloud, identity, and containers techniques); call out sub-techniques explicitly.
- **PEAK hunting framework** — structure hunts as Prepare → Execute → Act with a documented hypothesis, data sources, and ABLE (Actor/Behavior/Location/Evidence) baselining.
- **Identity-centric hunting** — Entra ID / Okta logs: impossible travel, illicit OAuth consent grants, MFA-fatigue, token theft & replay, and risky sign-in correlation.
- **Living-off-the-land** — baseline LOLBin/LOLBAS usage and hunt deviations rather than static signatures.
- **Detection-as-code** — express hunt findings as Sigma rules under version control with test data, then promote validated hunts into Skill 12/15 detections.
- **Hunt maturity** — track from ad-hoc → data-driven → automated; record which hunts became scheduled detections.

**Precision rule:** every hunt yields a hypothesis, the query, the result (found/not-found/inconclusive), and a disposition (new detection / tuned alert / closed).
