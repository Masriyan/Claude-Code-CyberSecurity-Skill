---
name: Incident Response & Digital Forensics
description: IR playbook execution, evidence collection, timeline analysis, memory forensics, and post-incident reporting
version: 1.0.0
author: Masriyan
tags: [cybersecurity, incident-response, forensics, dfir, evidence, timeline]
---

# 🚨 Incident Response & Digital Forensics

## Overview

This skill enables Claude to assist with structured incident response operations, digital evidence collection and preservation, forensic timeline analysis, memory forensics, and comprehensive post-incident reporting. It follows NIST SP 800-61 and SANS incident handling methodology.

---

## Prerequisites

### Required

- Python 3.8+
- `pyyaml`, `jinja2`, `pandas`

### Optional

- **Volatility 3** — Memory forensics
- **Autopsy / Sleuth Kit** — Disk forensics
- **plaso / log2timeline** — Timeline generation
- **KAPE** — Evidence collection (Windows)
- **velociraptor** — Endpoint forensics

```bash
pip install pyyaml jinja2 pandas python-dateutil
```

---

## Core Capabilities

### 1. IR Playbook Creation & Execution

**When the user asks to create or follow an IR playbook:**

1. Identify the incident type (ransomware, phishing, data breach, insider threat, DDoS, malware, account compromise)
2. Generate a step-by-step playbook following the PICERL framework:
   - **P**reparation — Verify tools, access, and communication channels
   - **I**dentification — Confirm the incident, scope, and severity
   - **C**ontainment — Short-term and long-term containment strategies
   - **E**radication — Remove threat actors, malware, and persistence
   - **R**ecovery — Restore systems and verify integrity
   - **L**essons Learned — Post-incident review and improvement
3. Include role assignments (IR Lead, Forensics, Comms, Legal)
4. Define escalation criteria and communication templates
5. Set timeline expectations for each phase

### 2. Evidence Collection & Preservation

**When the user asks to collect evidence:**

1. Follow order of volatility (most volatile first):
   - Running processes, network connections, memory
   - Temporary files, login sessions
   - Disk images, log files
   - Backup media, physical evidence
2. Document chain of custody for each evidence item
3. Calculate and verify cryptographic hashes
4. Create forensic images where applicable
5. Preserve log files from relevant sources
6. Generate evidence inventory manifest

### 3. Forensic Timeline Analysis

**When the user asks to build a timeline:**

1. Collect timestamps from all available sources (logs, filesystem, registry, memory)
2. Normalize timestamps to UTC
3. Correlate events across multiple data sources
4. Identify the initial compromise (patient zero)
5. Map the kill chain progression
6. Highlight critical events with context
7. Export timeline in CSV/JSON/HTML format

### 4. Memory Forensics

**When the user asks about memory forensics:**

1. Guide memory acquisition (live vs. dead analysis)
2. Profile identification for Volatility
3. Process listing and analysis (pstree, pslist, psscan)
4. Network connection extraction (netscan)
5. DLL and module analysis
6. Registry hive extraction from memory
7. Malware detection in memory artifacts
8. Code injection detection

### 5. Post-Incident Reporting

**When the user asks for an IR report:**

1. Executive summary (non-technical audience)
2. Incident timeline with visual representation
3. Scope and impact assessment
4. Root cause analysis
5. Remediation actions taken
6. Recommendations to prevent recurrence
7. Compliance notification requirements (GDPR, HIPAA, PCI-DSS)

---

## Usage Instructions

### Example Prompts

```
> Create an incident response playbook for a ransomware attack
> Help me collect forensic evidence from this compromised Windows server
> Build a timeline from these log files to trace the attack
> Guide me through memory forensics with Volatility on this dump
> Generate a post-incident report for management
```

---

## Script Reference

### `evidence_collector.py`

```bash
python scripts/evidence_collector.py --host 192.168.1.100 --output evidence/ --type full
python scripts/evidence_collector.py --logs /var/log/ --output evidence/ --type logs-only
```

### `timeline_builder.py`

```bash
python scripts/timeline_builder.py --logs ./collected_logs/ --output timeline.csv
python scripts/timeline_builder.py --logs ./logs/ --format html --start "2024-01-15" --end "2024-01-16"
```

---

## Integration Guide

- **← CSOC Automation (11)**: Receive triaged alerts requiring IR
- **→ Threat Hunting (06)**: Feed IOCs for environment-wide hunting
- **→ Malware Analysis (05)**: Analyze collected malware samples
- **→ Log Analysis (12)**: Deep-dive into specific log sources

---

## References

- [NIST SP 800-61 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Response Process](https://www.sans.org/white-papers/33901/)
- [Volatility Documentation](https://volatility3.readthedocs.io/)
- [The Art of Memory Forensics (Book)](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics-p-9781118825099)
