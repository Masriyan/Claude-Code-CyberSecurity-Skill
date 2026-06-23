---
name: CSOC Operations & Playbook Automation
description: SOC alert triage, incident playbook automation, escalation workflows, shift reporting, and SOC KPI tracking
version: 3.0.0
author: Masriyan
tags: [cybersecurity, csoc, soc, automation, playbook, triage, alert, operations, siem]
---

# CSOC Operations & Playbook Automation

## Purpose

Enable Claude to assist Cyber Security Operations Center (CSOC) teams with structured alert triage, automated playbook creation, escalation workflow design, shift handover reporting, and SOC metrics analysis. Claude produces operational artifacts that analysts can execute directly or adapt to their SOAR platforms.

---

## Activation Triggers

This skill activates when the user asks about:
- Triaging SIEM alerts or security events
- Creating incident response playbooks for SOC analysts
- Designing escalation workflows and notification chains
- Generating SOC shift handover reports
- Calculating SOC metrics (MTTD, MTTR, FPR)
- Automating repetitive SOC tasks
- Playbook conversion to Splunk SOAR, Palo Alto XSOAR, or ServiceNow
- SOC analyst decision support and runbooks
- Alert fatigue reduction strategies
- Alert correlation and deduplication

---

## Prerequisites

```bash
pip install pyyaml jinja2 requests python-dateutil
```

**Platform integrations:**
- `Splunk SOAR` — Playbook automation
- `Palo Alto XSOAR` — SOAR platform
- `TheHive` — Open-source IR platform
- `ServiceNow` — ITSM ticketing
- `PagerDuty / OpsGenie` — Alerting and on-call

---

## Core Capabilities

### 1. Alert Triage Automation

**When the user provides SIEM alerts and asks to triage:**

**Triage Decision Framework:**

```
Step 1: Parse alert data
  - Source: SIEM, EDR, WAF, IDS, email security, cloud audit logs
  - Extract: timestamp, source IP, destination, user, process, alert type

Step 2: Asset criticality lookup
  - Is the asset business-critical? (production DB, domain controller, payment system)
  - Is the user privileged? (admin, developer, finance)
  - What is the asset's network exposure?

Step 3: Threat context enrichment
  - IP reputation: Check against blocklists (AbuseIPDB, VirusTotal, Shodan)
  - Hash reputation: VirusTotal lookup for file hashes
  - Domain reputation: Phishtank, URLhaus, MX Toolbox
  - User risk score: Recent activity anomalies, recent password resets

Step 4: Apply triage matrix
```

**Alert Triage Matrix:**

| Alert Confidence | Asset Criticality | Recommended Action | SLA |
|----------------|-------------------|--------------------|-----|
| High | Critical | Immediate escalation to Tier 2/3 — declare incident | 15 min |
| High | High | Tier 1 priority investigation | 30 min |
| High | Medium | Tier 1 standard investigation | 1 hour |
| High | Low | Tier 1 standard queue | 4 hours |
| Medium | Critical | Tier 1 priority investigation | 30 min |
| Medium | High | Tier 1 standard investigation | 2 hours |
| Medium | Low | Standard queue, investigate if pattern emerges | 8 hours |
| Low | Any | Auto-close with documentation and note | 24 hours |

**Triage Analysis Output Format:**
```markdown
## Alert Triage Summary

**Alert ID:** [ID]
**Alert Type:** [Type — e.g., Brute Force Login]
**Source:** [Source IP/User/Host]
**Time:** [UTC timestamp]
**SIEM Rule:** [Rule name that triggered]

**Asset Assessment:**
- Asset: [Hostname/IP]
- Criticality: [Critical / High / Medium / Low]
- Role: [e.g., Production Database Server]

**Threat Context:**
- Source IP Reputation: [Malicious / Suspicious / Clean / Unknown]
- Source IP Location: [Country, ASN]
- Known threat actor: [Yes/No — if yes, attribution]
- Related IOCs found: [Yes/No]

**Verdict:** [True Positive / False Positive / Undetermined]
**Triage Action:** [Escalate to Tier 2 / Investigate / Close / Watch]
**Recommended Playbook:** [Playbook name]
**Priority:** [P1 Critical / P2 High / P3 Medium / P4 Low]

**Analyst Notes:**
[Notes from triage]
```

```bash
# Automated triage with script
python scripts/alert_triager.py --alerts alerts.json --output triage_results.json
python scripts/alert_triager.py --alerts siem_export.csv --playbook default --auto-assign
```

### 2. Incident Playbook Creation

**When the user asks to create a SOC playbook:**

**Playbook YAML Template (SOAR-compatible):**

```yaml
# CSOC Playbook: Phishing Email Response
# Compatible with: Splunk SOAR, XSOAR, TheHive
# Last updated: 2025-05-28

name: phishing_email_response
version: "2.0"
trigger:
  alert_types:
    - "Email Security - Phishing Detected"
    - "User Reported Phishing"
  severity: [medium, high, critical]

variables:
  - name: sender_email
    type: string
  - name: recipient_email
    type: string
  - name: email_subject
    type: string
  - name: attachment_hash
    type: string
    required: false

tasks:
  - id: "1-extract-artifacts"
    name: "Extract Email Artifacts"
    type: automated
    actions:
      - Extract sender, recipients, subject, body, attachments
      - Defang all URLs and IPs found in email body
      - Calculate SHA256 of all attachments
      - Extract email headers (SPF, DKIM, DMARC results)
    output:
      - sender_ip
      - sender_domain
      - urls_in_body
      - attachment_hashes

  - id: "2-enrich-indicators"
    name: "Enrich IOCs with Threat Intelligence"
    type: automated
    depends_on: ["1-extract-artifacts"]
    actions:
      - VirusTotal lookup: sender_ip, attachment_hashes, urls_in_body
      - URLhaus lookup: all URLs
      - AbuseIPDB lookup: sender_ip
      - Check internal blocklists
    output:
      - vt_results
      - url_classification
      - ip_reputation

  - id: "3-assess-impact"
    name: "Assess Who Clicked / Opened Attachment"
    type: manual
    depends_on: ["2-enrich-indicators"]
    analyst_actions:
      - "Check email security gateway: did anyone click the link?"
      - "Check proxy logs: any traffic to phishing domain?"
      - "Check EDR: any process execution from attachment?"
    decision_point:
      - condition: "User clicked link OR opened attachment"
        action: escalate_to_incident
      - condition: "No user interaction confirmed"
        action: continue_to_containment

  - id: "4-contain"
    name: "Email and Infrastructure Containment"
    type: hybrid
    actions:
      - Block sender domain in email gateway
      - Block phishing URLs in web proxy and DNS
      - Block attachment hash in EDR/AV
      - Pull email from all mailboxes (if email platform supports)
      - If user clicked: isolate endpoint (→ IR Playbook)

  - id: "5-notify"
    name: "User and Management Notification"
    type: automated
    templates:
      user_notification: |
        Subject: Action Required — Phishing Email in Your Inbox
        You recently received a phishing email (Subject: {{email_subject}}).
        If you clicked any links or opened attachments, please contact the SOC immediately.
        Contact: soc@company.com | x4444
      management_notification: |
        CSOC Alert: Phishing campaign targeting [department] detected.
        [N] employees received the email. Status: [contained/investigating].

  - id: "6-close"
    name: "Close and Document"
    type: manual
    actions:
      - Document all IOCs in MISP/threat intel platform
      - Update email security rules
      - Create security awareness notification if targeted campaign
      - Complete incident ticket with findings
    metrics:
      - alert_received_time
      - triage_completed_time
      - contained_time
```

**Supported Playbook Types with Trigger Conditions:**
| Playbook | Trigger |
|----------|---------|
| Phishing Response | Email security alert, user report |
| Ransomware Response | Mass file encryption, EDR behavioral alert |
| Data Exfiltration | DLP alert, large outbound transfer |
| Brute Force | N failed logins in M minutes |
| Insider Threat | DLP, unusual access pattern, HR flag |
| Account Compromise | Impossible travel, new device login |
| Malware Alert | AV/EDR alert, email attachment detection |
| DDoS Response | Traffic volume spike, service degradation |
| Unauthorized Access | Access to restricted resource |
| Vulnerability Detected | Scanner finding, threat intel match |

### 3. Escalation Workflow Design

**When the user asks to design an escalation workflow:**

```markdown
## CSOC Escalation Workflow

### Severity Definitions
| Level | CVSS / Impact | Response Time | Team |
|-------|--------------|---------------|------|
| P1 — Critical | 9.0–10.0 or system breach | 15 minutes | Tier 3 + IR Lead + Management |
| P2 — High | 7.0–8.9 or data at risk | 30 minutes | Tier 2 + Tier 3 standby |
| P3 — Medium | 4.0–6.9 | 2 hours | Tier 1 → Tier 2 if unresolved |
| P4 — Low | 0.1–3.9 | 8 hours | Tier 1 |

### Escalation Paths
```
P1 Incident:
  Tier 1 Analyst → [immediately] → Tier 3 Lead (call)
  Tier 3 Lead → [within 5 min] → SOC Manager (call)
  SOC Manager → [within 15 min] → CISO + Legal (if data breach)

P2 Incident:
  Tier 1 Analyst → [after 30 min unresolved] → Tier 2 Analyst (ticket escalation)
  Tier 2 Analyst → [after 2 hours unresolved] → Tier 3 Lead (chat notification)

Out-of-hours escalation:
  On-call Tier 2 via PagerDuty → 15 min acknowledge → escalate to Tier 3
```

### Notification Templates

**Slack Critical Alert Template:**
```
🚨 *P1 SECURITY INCIDENT DECLARED* 🚨
*Type:* {{incident_type}}
*Affected:* {{affected_systems}}
*Time Detected:* {{detection_time}} UTC
*IR Lead:* @{{ir_lead}}
*Bridge:* [link to war room]
*Ticket:* {{ticket_id}}
ACTION REQUIRED: All IR team members join the bridge now.
```

**Email Escalation Template:**
```
Subject: [P{{severity}}] Security Incident — {{incident_type}} — {{ticket_id}}

CSOC has declared a security incident.

Incident ID: {{ticket_id}}
Type: {{incident_type}}
Severity: {{severity}}
Detected: {{detection_time}} UTC
Current Status: {{status}}
Affected Systems: {{affected_systems}}

Current Actions:
{{current_actions}}

Required Actions:
{{required_actions}}

Next Update: {{next_update_time}}

SOC Contact: soc@company.com | +1-555-SOC-HELP
```

### 4. Shift Handover Report Generation

**When the user asks to generate a shift report:**

```bash
python scripts/alert_triager.py --report shift --shift night --date 2025-05-28 --output report.md
```

**Shift Handover Report Template:**
```markdown
# CSOC Shift Handover Report
**Shift:** Night (22:00–06:00 UTC)
**Date:** 2025-05-28
**Outgoing Analyst:** [Name]
**Incoming Analyst:** [Name]

---

## Shift Summary
| Metric | Count |
|--------|-------|
| Total Alerts | 142 |
| True Positives | 8 |
| False Positives | 118 |
| Undetermined | 16 |
| Incidents Declared | 2 |
| Average Triage Time | 12 minutes |
| SLA Compliance | 94.4% |

## Open Incidents (Require Immediate Attention)
| ID | Type | Severity | Status | Owner | Next Action |
|----|------|----------|--------|-------|-------------|
| INC-2025-089 | Phishing Campaign | P2 | Investigating | [Name] | Awaiting EDR report |
| INC-2025-090 | Suspicious Login | P3 | Monitoring | [Name] | 24h watch, escalate if repeat |

## Alerts Closed This Shift
- 118 False Positives auto-closed (brute force from known scanners, pen test activity)
- 12 True Positives resolved (malware blocked by AV, no further action needed)

## Ongoing Watches (No Action Yet Required)
- Increased scan activity from 198.51.100.0/24 — monitoring trend
- User john.doe@company.com multiple failed VPN logins — watching for successful auth

## Tool/System Issues
- Splunk indexer latency 45 min this shift — events delayed, may affect investigation timing
- EDR console intermittently slow — reported to IT ops (ticket: OPS-4421)

## Recommended Actions for Next Shift
1. Follow up on INC-2025-089: EDR report expected from endpoint team by 08:00
2. Review john.doe@company.com VPN activity — if successful login from new location, triage
3. Watch for continued scanning from 198.51.100.x block
```

### 5. SOC Metrics & KPI Tracking

**When the user asks about SOC metrics or KPI analysis:**

**Key SOC Metrics:**

| Metric | Formula | Target |
|--------|---------|--------|
| **MTTD** (Mean Time to Detect) | Avg(detection_time − attack_start_time) | < 1 hour |
| **MTTR** (Mean Time to Respond) | Avg(response_complete − detection_time) | < 4 hours |
| **MTTC** (Mean Time to Contain) | Avg(contain_time − detection_time) | < 1 hour |
| **False Positive Rate** | FP / (FP + TP) × 100 | < 20% |
| **Alert-to-Ticket Ratio** | Tickets / Total Alerts | < 5% (healthy) |
| **SLA Compliance** | Alerts within SLA / Total Alerts | > 95% |
| **Analyst Capacity** | Alerts handled per analyst per shift | Track trend |
| **Escalation Rate** | Escalated to Tier 2/3 / Total Tickets | < 20% |

**Monthly KPI Dashboard Template:**
```markdown
## SOC Monthly Metrics Report — May 2025

### Volume
- Total Alerts: 4,215
- True Positives: 287 (6.8%)
- False Positives: 3,928 (93.2%)
- Incidents Declared: 14

### Response Performance
- MTTD: 23 minutes (↓ from 31 min last month) ✓
- MTTR: 3.2 hours (↑ from 2.8 hours) ⚠
- SLA Compliance: 96.1% ✓

### Top Alert Categories
1. Brute Force Attempts: 1,842 (94% FP from scanner IPs)
2. Malware Detected: 412 (78% TP)
3. Data Loss Prevention: 287 (32% TP)
4. Privilege Escalation: 156 (65% TP)

### Recommendations
1. Allowlist known scanner IPs to reduce brute force FP volume (-40% alert load)
2. MTTR increased due to EDR tool latency — investigate performance
```

---

## Script Reference

### `alert_triager.py`
```bash
python scripts/alert_triager.py --alerts alerts.json --output triage_results.json
python scripts/alert_triager.py --alerts siem_export.csv --playbook default --auto-assign
```

### `report_generator.py`
```bash
python scripts/report_generator.py --shift night --date 2025-05-28 --output report.md
python scripts/report_generator.py --metrics monthly --date 2025-05 --output metrics.json
```

---

## Skill Integration

| Condition | Adjacent Skill |
|-----------|---------------|
| Alert requires deep investigation | → Skill 07 (Incident Response) |
| Log deep-dive for alert context | → Skill 12 (Log Analysis) |
| Threat hunt based on alert patterns | → Skill 06 (Threat Hunting) |
| All detection skills feed alerts here | ← All detection skills |

---

## References

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS SOC Best Practices](https://www.sans.org/white-papers/)
- [Splunk SOAR Playbooks](https://docs.splunk.com/Documentation/SOAR)
- [Palo Alto XSOAR Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsoar)
- [TheHive Project](https://thehive-project.org/)
- [SOC Maturity Model (SOC-CMM)](https://www.soc-cmm.com/)


---

## v3.0 Enhancements (2026 Update)

**AI-augmented, metrics-driven SOC:**

- **AI-assisted triage** — use the LLM to summarize alerts, cluster duplicates, enrich with threat intel, and draft the analyst's first-pass disposition — with a human-in-the-loop gate before any containment action (see Skill 16 for safe agent design).
- **Detection-as-code & SOAR** — playbooks and detections in version control with tests; automated enrichment (WHOIS, VT, GeoIP, asset/identity context) before a human sees the ticket.
- **Alert tuning loop** — track false-positive rate per rule; auto-propose suppression/tuning when FP rate exceeds threshold to fight alert fatigue.
- **MITRE D3FEND** — map each playbook's containment/eradication steps to D3FEND countermeasures, complementing ATT&CK coverage.
- **Metrics** — report MTTD, MTTA, MTTR, dwell time, and detection coverage by ATT&CK tactic; trend them across shifts.

**Precision rule:** every automated action is logged, reversible where possible, and gated by severity; irreversible actions require explicit human approval.
