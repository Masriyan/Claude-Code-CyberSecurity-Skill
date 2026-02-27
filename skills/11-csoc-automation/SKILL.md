---
name: CSOC Operations & Playbook Automation
description: SOC alert triage automation, incident playbook creation, escalation workflows, and shift reporting
version: 1.0.0
author: Masriyan
tags: [cybersecurity, csoc, soc, automation, playbook, triage, operations]
---

# 🏢 CSOC Operations & Playbook Automation

## Overview

This skill enables Claude to assist Cyber Security Operations Center (CSOC) teams with alert triage automation, playbook creation and execution, escalation workflow management, shift handover reports, and SOC metrics tracking. It focuses on operational efficiency and standardized incident handling.

---

## Prerequisites

- Python 3.8+
- `pyyaml`, `jinja2`, `requests`

```bash
pip install pyyaml jinja2 requests python-dateutil
```

---

## Core Capabilities

### 1. Alert Triage Automation

**When the user asks to triage alerts:**

1. Parse incoming alert data (JSON, CSV, SIEM export)
2. Classify alerts by type (malware, intrusion, policy violation, etc.)
3. Assign severity based on asset criticality, threat context, and confidence
4. Deduplicate and correlate related alerts
5. Enrich alerts with contextual information (IP reputation, hash lookup)
6. Determine true positive / false positive likelihood
7. Auto-assign to appropriate analyst tier
8. Generate triage summary with recommended actions

**Triage Decision Matrix:**
| Alert Confidence | Asset Criticality | Action |
|---|---|---|
| High | High | Immediate escalation to Tier 2/3 |
| High | Medium | Tier 1 investigation within SLA |
| High | Low | Tier 1 standard queue |
| Medium | High | Priority Tier 1 investigation |
| Medium | Medium | Standard Tier 1 queue |
| Low | Any | Auto-close with documentation |

### 2. Incident Playbook Creation

**When the user asks to create a playbook:**

1. Define the incident type and trigger conditions
2. Specify the initial response steps (containment, evidence preservation)
3. Define investigation procedures with decision trees
4. Specify escalation criteria and notification chains
5. Include remediation and recovery steps
6. Add post-incident review tasks
7. Format as executable YAML for automation platforms
8. Include runbook links and reference documentation

**Supported Playbook Types:**

- Phishing incident response
- Ransomware response
- Data breach / exfiltration
- Insider threat
- DDoS attack
- Account compromise
- Malware outbreak
- Unauthorized access
- Policy violation

### 3. Escalation Workflow Management

**When the user asks about escalation:**

1. Define escalation tiers and response times
2. Map incident severity to escalation paths
3. Create notification templates for each tier
4. Define escalation triggers (time-based, severity-based, type-based)
5. Document out-of-hours procedures
6. Track escalation SLA compliance

### 4. Shift Reporting & Handover

**When the user asks to generate shift reports:**

1. Summarize all alerts processed during the shift
2. Document open investigations and their status
3. Highlight critical incidents requiring follow-up
4. Report on SLA compliance metrics
5. Note any system issues or tool outages
6. List pending tasks for the next shift
7. Export in professional report format

### 5. SOC Metrics & KPI Tracking

**When the user asks about SOC metrics:**

1. Mean Time to Detect (MTTD)
2. Mean Time to Respond (MTTR)
3. Alert volume and trends
4. True positive / false positive ratios
5. Escalation rates by category
6. Analyst workload distribution
7. SLA compliance percentages

---

## Usage Instructions

### Example Prompts

```
> Create an incident response playbook for a phishing campaign
> Triage these 50 SIEM alerts and prioritize them
> Generate a SOC shift handover report for the night shift
> Build an escalation workflow for our 24/7 SOC
> Calculate our SOC KPIs from this month's alert data
> Automate the triage process for our most common alert types
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
python scripts/report_generator.py --shift night --date 2024-01-15 --output report.md
python scripts/report_generator.py --metrics monthly --date 2024-01 --output metrics.json
```

---

## Integration Guide

- **← All Detection Skills**: Receive alerts from vulnerability scanners, network monitors, log analysis
- **→ Incident Response (07)**: Escalate confirmed incidents for full IR
- **→ Threat Hunting (06)**: Feed triage insights for proactive hunting
- **→ Log Analysis (12)**: Deep-dive into specific alert sources

---

## References

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS SOC Best Practices](https://www.sans.org/white-papers/)
- [The SOC Analyst Guide](https://www.cybrary.it/)
- [Splunk SOAR Playbooks](https://docs.splunk.com/Documentation/SOAR)
