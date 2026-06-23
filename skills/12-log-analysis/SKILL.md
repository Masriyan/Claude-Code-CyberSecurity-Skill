---
name: Log Analysis & SIEM Integration
description: Security log parsing, anomaly detection, SIEM query building, Sigma rule creation, and correlation rule development across Splunk, Elastic, QRadar, and Microsoft Sentinel
version: 3.0.0
author: Masriyan
tags: [cybersecurity, log-analysis, siem, splunk, elastic, sentinel, sigma, anomaly-detection, correlation]
---

# Log Analysis & SIEM Integration

## Purpose

Enable Claude to assist with security log analysis across all major platforms. Claude directly parses and analyzes log samples provided by the user, builds SIEM queries for any platform, creates Sigma rules for portable detection, develops correlation rules, and identifies anomalous patterns in log data.

---

## Activation Triggers

This skill activates when the user asks about:
- Parsing Windows Event Logs, Linux syslog, or application logs
- Building Splunk SPL, Elastic KQL/EQL, QRadar AQL, or Sentinel KQL queries
- Creating Sigma rules for platform-agnostic detection
- Detecting anomalies or attack patterns in log data
- Building SIEM correlation rules for complex attack scenarios
- Converting queries between SIEM platforms
- Log source health monitoring and gap analysis
- Detecting lateral movement, privilege escalation, or persistence in logs
- EVTX analysis or Windows audit log review

---

## Prerequisites

```bash
pip install pandas pyyaml python-dateutil
```

**Platform tools:**
- `Splunk` — Splunk Web, SPL, and SOAR
- `Elastic Stack` — Kibana, KQL, EQL
- `Microsoft Sentinel` — KQL, Workbooks
- `IBM QRadar` — AQL, Rules
- `Sigma` — Platform-agnostic rule format
- `python-evtx` — Parse Windows .evtx files without Windows

---

## Core Capabilities

### 1. Log Parsing & Analysis

**When the user pastes logs or provides log files:**

Claude directly reads and analyzes logs to extract security-relevant events.

**Windows Event Log — Critical Event IDs:**

| Event ID | Log | Description |
|----------|-----|-------------|
| 4624 | Security | Successful logon — Logon Type 3 (network) is interesting |
| 4625 | Security | Failed logon — track source IP for brute force |
| 4648 | Security | Logon with explicit credentials (RunAs) |
| 4688 | Security | New process created — needs CommandLine auditing enabled |
| 4698 | Security | Scheduled task created |
| 4702 | Security | Scheduled task updated |
| 4720 | Security | User account created |
| 4728/4732 | Security | Member added to security/local group |
| 4768/4769 | Security | Kerberos TGT/TGS requested |
| 4776 | Security | NTLM authentication |
| 4946 | Security | Windows Firewall rule added |
| 5140 | Security | Network share accessed |
| 5145 | Security | Network share file access |
| 7045 | System | New service installed |
| 1102 | Security | Audit log cleared |
| 4103/4104 | PowerShell | PowerShell module/script block logging |

**Linux Log Analysis — Key Patterns:**
```bash
# Failed SSH logins
grep "Failed password" /var/log/auth.log | awk '{print $1,$2,$3,$11}' | sort | uniq -c | sort -rn

# Successful logins after failures (brute force success)
grep "Accepted password\|Accepted publickey" /var/log/auth.log

# Sudo usage
grep "sudo:" /var/log/auth.log | grep -v "session"

# Cron job execution
grep CRON /var/log/syslog

# New user creation
grep "useradd\|usermod" /var/log/auth.log

# Privilege escalation
grep "su\b" /var/log/auth.log
```

**Log parsing script:**
```bash
python scripts/log_parser.py --input /var/log/auth.log --format json --output parsed.json
python scripts/log_parser.py --input events.evtx --normalize ecs --output normalized.json
```

### 2. SIEM Query Library

**When the user asks to build detection queries:**

#### Splunk SPL — Attack Pattern Queries

```spl
// Brute force attack detection
index=windows EventCode=4625
| bin _time span=5m
| stats count as FailedLogins, values(Account_Name) as Accounts by src_ip, _time
| where FailedLogins > 20
| sort -FailedLogins

// Pass-the-Hash detection (Logon Type 3 with NTLM)
index=windows EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| where NOT (Account_Name="ANONYMOUS LOGON" OR Account_Name="*$")
| stats count by Account_Name, Workstation_Name, src_ip
| where count > 1

// Lateral movement via PsExec / admin shares
index=windows EventCode=5145
| where (ShareName="\\\\*\\ADMIN$" OR ShareName="\\\\*\\C$") 
    AND RelativeTargetName="*PSEXESVC*"
| table _time, SubjectUserName, IpAddress, ShareName

// PowerShell encoded command execution
index=windows (source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)
    OR (EventCode=4688 CommandLine="*powershell*")
| search CommandLine IN ("*-EncodedCommand*", "*-enc *", "*-e *", "*-nop*", 
                          "*DownloadString*", "*IEX*", "*Invoke-Expression*")
| table _time, ComputerName, User, CommandLine

// Scheduled task creation for persistence
index=windows EventCode=4698
| rex field=TaskContent "<Command>(?P<command>[^<]+)</Command>"
| where NOT match(command, "(?i)\\\\windows\\\\|\\\\microsoft\\\\|\\\\system32\\\\")
| table _time, ComputerName, SubjectUserName, TaskName, command

// LSASS memory access (credential dumping)
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT (SourceImage IN 
    ("C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*",
     "C:\\Program Files\\*", "C:\\Program Files (x86)\\*"))
| table _time, SourceImage, GrantedAccess, CallTrace

// DCSync detection
index=windows EventCode=4662 
    (ObjectType="*domainDNS*" OR ObjectType="*19195a5b-6da0-11d0-afd3-00c04fd930c9*")
    (Properties="*Replicating Directory Changes All*" OR Properties="*1131f6ad*")
| where NOT match(SubjectUserName, "(?i)^.*\$$") 
| table _time, SubjectUserName, SubjectDomainName, Properties

// Kerberoasting detection
index=windows EventCode=4769 Ticket_Encryption_Type=0x17
| where NOT (Account_Name="*$" OR Service_Name IN ("krbtgt", "kadmin/changepw"))
| stats count by Account_Name, Client_Address, Service_Name
| where count > 3
```

#### Microsoft Sentinel KQL — Queries

```kql
// Impossible Travel (logins from geographically impossible locations)
let TimeDelta = 2h;
SigninLogs
| where ResultType == 0  // Successful logins only
| where TimeGenerated > ago(7d)
| project UserPrincipalName, Location, TimeGenerated, IPAddress
| sort by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend PreviousLogin = prev(TimeGenerated), PreviousLocation = prev(Location)
| where UserPrincipalName == prev(UserPrincipalName)
| extend TimeDiff = TimeGenerated - PreviousLogin
| where TimeDiff < TimeDelta and Location != PreviousLocation
| project UserPrincipalName, Location, PreviousLocation, TimeDiff, IPAddress

// Azure AD privilege escalation
AuditLogs
| where OperationName in ("Add member to role", "Add eligible member to role")
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend RoleAdded = tostring(TargetResources[0].displayName)  
| where RoleAdded in ("Global Administrator", "Security Administrator", 
                       "Exchange Administrator", "SharePoint Administrator")
| project TimeGenerated, TargetUser, RoleAdded, 
           InitiatedBy=tostring(InitiatedBy.user.userPrincipalName)

// Suspicious PowerShell activity
SecurityEvent
| where EventID == 4104
| where TimeGenerated > ago(24h)
| where ScriptBlockText has_any("IEX", "DownloadString", "EncodedCommand", 
                                  "WebClient", "Invoke-Expression", "bypass", "-nop")
| project TimeGenerated, Computer, Account, ScriptBlockText
| extend RiskScore = case(
    ScriptBlockText has "IEX" and ScriptBlockText has "DownloadString", 10,
    ScriptBlockText has "EncodedCommand", 7,
    ScriptBlockText has "bypass", 5, 3)
| where RiskScore >= 5
| order by RiskScore desc
```

#### Elastic EQL — Sequence Detection

```eql
// Detect fileless malware execution chain
sequence by host.name with maxspan=5m
  [process where event.type == "start" and
   process.name in ("outlook.exe", "winword.exe", "excel.exe")]
  [process where event.type == "start" and
   process.name in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")]
  [network where network.direction == "egress" and
   not network.destination.ip in ("127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16")]

// Ransomware detection: mass file extension changes + shadow copy deletion
sequence by host.name with maxspan=30m
  [file where event.type == "creation" and
   file.extension in ("locked", "encrypted", "crypted", "enc", "readme")]
  [file where event.type == "creation" and
   file.name in ("README.txt", "DECRYPT.txt", "HOW_TO_DECRYPT.txt")]
  [process where event.type == "start" and
   process.command_line : "* delete shadows *"]
```

### 3. Anomaly Detection Methodology

**When the user asks to detect anomalies in log data:**

**Statistical Anomaly Detection:**

```python
# Claude's approach to analyzing log data for anomalies:
import pandas as pd
from datetime import timedelta

# 1. Volume anomalies
# Calculate rolling average, flag if current > mean + 3*stddev

# 2. Time-based anomalies (off-hours activity)
# Business hours: Mon-Fri 08:00-18:00 local time
# Flag: admin activities on weekends, logins at 03:00 UTC

# 3. Never-before-seen entities
# - New admin account created
# - First-time login from country
# - New process never seen before
# - New domain in DNS queries

# 4. Impossible travel
# Calculate geographic distance / time delta
# Flag if impossible to travel physically in the time window
```

```bash
python scripts/anomaly_detector.py --logs parsed.json --baseline baseline.json --output anomalies.json
```

**Anomaly Categories:**

| Category | Indicators |
|----------|-----------|
| Volume spike | 10x normal event rate in 5 minutes |
| Off-hours activity | Admin access at 03:00 local time |
| New geography | Login from country with no prior history |
| New process | First-ever execution of binary |
| Large data transfer | Upload > 10x baseline for this user/system |
| Silent log source | No events received in 30+ minutes |
| Authentication pattern | Logon Type 3 from non-admin workstation |

### 4. Sigma Rule Development

**When the user asks to create Sigma rules:**

```yaml
title: Credential Dumping via Procdump
id: e5eb5a27-4a98-4c34-8b39-1fbe552d2aa4
status: stable
description: Detects the use of ProcDump to dump LSASS memory for credential theft
author: SOC Analyst
date: 2025/05/28
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://docs.microsoft.com/en-us/sysinternals/downloads/procdump
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_tool:
    Image|endswith:
      - '\procdump.exe'
      - '\procdump64.exe'
  selection_lsass:
    CommandLine|contains:
      - 'lsass'
      - '-ma 4'      # PID 4 = System, sometimes used
  selection_flags:
    CommandLine|contains|all:
      - '-accepteula'
      - '-ma'
  condition: selection_tool and (selection_lsass or selection_flags)
falsepositives:
  - Legitimate use by administrators for debugging (rare, should be investigated)
level: high
```

**Sigma rule conversion to SIEM platforms:**
```bash
# Install sigma-cli
pip install sigma-cli

# Convert to Splunk SPL
sigma convert -t splunk -p splunk_windows sigma_rule.yml

# Convert to Elastic KQL
sigma convert -t elasticsearch -p ecs_windows sigma_rule.yml

# Convert to Microsoft Sentinel KQL  
sigma convert -t kusto sigma_rule.yml
```

### 5. Correlation Rule Development

**When the user asks to create correlation rules for multi-event detection:**

```markdown
## Correlation Rule: Brute Force → Successful Login → Lateral Movement

**Trigger:** 
  Event 1: 4625 (Failed Login) × 20+ in 5 minutes (same source IP)
  THEN Event 2: 4624 (Successful Login) from same source IP within 10 minutes
  THEN Event 3: 5145 (Admin Share Access) from same host within 30 minutes

**Logic:**
```
Step 1: Bucket failed logins by source IP in 5-minute windows
Step 2: If count > 20 → mark IP as "brute force source"  
Step 3: Watch for successful login from same IP within 10 minutes
Step 4: If successful login → escalate to HIGH severity
Step 5: Watch for lateral movement from the successfully logged-in host
Step 6: Declare incident if all 3 events observed
```

**Splunk Correlation (corr_rule.conf):**
```spl
index=windows EventCode=4625
| bin _time span=5m
| stats count by src_ip, _time
| where count > 20
| join src_ip [
    search index=windows EventCode=4624 
    | bin _time span=10m
    | stats count by src_ip, _time, Account_Name, Workstation_Name
]
| table _time, src_ip, Account_Name, Workstation_Name, count
```

**Suppression & De-duplication:**
- Suppress same correlation alert from same source IP for 1 hour after first fire
- Exclude known vulnerability scanners (add scanner IP ranges to exception list)
- Exclude service accounts with documented scheduled tasks

---

## Log Source Health Monitoring

**When the user asks about log source health:**

```spl
// Splunk: Detect silent log sources (no events in 30 minutes)
| tstats count WHERE index=* BY host, sourcetype, _time span=30m
| where _time > relative_time(now(), "-30m@m")
| stats max(_time) as last_seen by host, sourcetype
| where last_seen < relative_time(now(), "-30m@m")
| eval lag = round((now() - last_seen) / 60, 1)
| table host, sourcetype, last_seen, lag
| sort -lag
```

---

## Script Reference

### `log_parser.py`
```bash
python scripts/log_parser.py --input /var/log/auth.log --format json --output parsed.json
python scripts/log_parser.py --input events.evtx --normalize ecs --output normalized.json
```

### `anomaly_detector.py`
```bash
python scripts/anomaly_detector.py --logs parsed.json --baseline baseline.json --output anomalies.json
```

---

## Skill Integration

| Condition | Adjacent Skill |
|-----------|---------------|
| Anomaly found → escalate to SOC | → Skill 11 (CSOC Automation) |
| Anomaly is a hunt lead | → Skill 06 (Threat Hunting) |
| Build timeline from logs for IR | → Skill 07 (Incident Response) |
| Create detection rules from findings | → Skill 15 (Blue Team Defense) |

---

## References

- [Splunk SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Elastic EQL Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html)
- [Microsoft Sentinel KQL](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- [Sigma Rules HQ Repository](https://github.com/SigmaHQ/sigma)
- [Windows Security Audit Policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/)
- [OCSF Schema](https://schema.ocsf.io/)
- [SANS Windows Logging Cheat Sheet](https://www.malwarearchaeology.com/cheat-sheets)


---

## v3.0 Enhancements (2026 Update)

**Normalized, testable detection content:**

- **OCSF / ECS normalization** — map sources to the Open Cybersecurity Schema Framework (or Elastic Common Schema) so one detection works across feeds; state the schema in each rule.
- **Sigma correlation rules** — use Sigma's correlation extension (count/temporal/value-count) for multi-event detections (e.g., brute force → success, low-and-slow exfil), not just single-event matches.
- **Detection-as-code CI** — every rule has unit tests with positive/negative sample events; rules are linted and converted per-backend (`sigma convert`) in CI before deployment.
- **UEBA & identity analytics** — baseline per-user/host behavior; alert on deviation (new admin action, abnormal data volume, impossible travel) rather than fixed thresholds.
- **Platform currency** — examples for Splunk (`tstats`/data models), Microsoft Sentinel (KQL, ASIM functions), and Elastic (ES|QL/EQL).

**Precision rule:** each rule documents data source + schema, false-positive conditions, ATT&CK mapping, and a tested sample event.
