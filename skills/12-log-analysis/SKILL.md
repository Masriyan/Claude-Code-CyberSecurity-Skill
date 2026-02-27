---
name: Log Analysis & SIEM Integration
description: Log parsing, anomaly detection, SIEM query building, and correlation rule development
version: 1.0.0
author: Masriyan
tags:
  [
    cybersecurity,
    log-analysis,
    siem,
    splunk,
    elastic,
    anomaly-detection,
    correlation,
  ]
---

# 📊 Log Analysis & SIEM Integration

## Overview

This skill enables Claude to assist with security log analysis, SIEM query construction, anomaly detection, correlation rule development, and log pipeline optimization across multiple platforms (Splunk, Elastic, QRadar, Microsoft Sentinel).

---

## Prerequisites

- Python 3.8+
- `pandas`, `pyyaml`

```bash
pip install pandas pyyaml python-dateutil
```

---

## Core Capabilities

### 1. Log Parsing & Normalization

**When the user asks to parse logs:**

1. Auto-detect log format (syslog, JSON, CSV, Windows Event, CEF, LEEF)
2. Parse and extract structured fields
3. Normalize timestamps to UTC
4. Map fields to common schema (ECS, CIM, OCSF)
5. Handle multi-line log entries
6. Output in structured format (JSON, CSV)

### 2. SIEM Query Building

**When the user asks to build SIEM queries:**

**Splunk SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625
| stats count by src_ip, Account_Name
| where count > 5
| sort -count
```

**Elastic KQL/EQL:**

```
event.code:4625 AND source.ip:* | stats count by source.ip, user.name
```

**Microsoft Sentinel KQL:**

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogons=count() by SourceIP=IpAddress, Account=Account
| where FailedLogons > 5
```

### 3. Anomaly Detection

**When the user asks to detect anomalies:**

1. Establish baseline behavior from historical data
2. Detect statistical anomalies (volume spikes, new patterns)
3. Identify never-before-seen events
4. Detect timing anomalies (off-hours activity)
5. Flag geolocation anomalies (impossible travel)
6. Identify behavioral deviations from baselines

### 4. Correlation Rule Development

**When the user asks to create correlation rules:**

1. Define the attack scenario to detect
2. Identify the individual log events involved
3. Build temporal correlation logic (events within time window)
4. Add context enrichment (asset criticality, user roles)
5. Set threshold conditions
6. Define suppression and de-duplication logic
7. Generate Sigma rules for platform-agnostic detection

### 5. Log Source Health Monitoring

**When the user asks about log source health:**

1. Monitor log volume per source for gaps
2. Detect silent log sources (no events received)
3. Validate expected event types are present
4. Check timestamp accuracy and drift
5. Alert on parsing errors or format changes

---

## Usage Instructions

### Example Prompts

```
> Parse these Windows Event Logs and extract authentication events
> Build a Splunk query to detect lateral movement via PsExec
> Create a correlation rule for detecting brute force followed by successful login
> Analyze these logs for anomalous behavior patterns
> Convert this Splunk query to Elastic KQL
> Build a Sigma rule for detecting credential dumping
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

## Integration Guide

- **← CSOC Automation (11)**: Receive triaged alerts for deep log analysis
- **← Incident Response (07)**: Provide log evidence for IR timelines
- **→ Threat Hunting (06)**: Feed anomalies as hunt leads
- **→ Blue Team Defense (15)**: Generate detection rules from findings

---

## References

- [Splunk SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Elastic EQL](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [OCSF Schema](https://schema.ocsf.io/)
