---
name: Threat Hunting & IOC Analysis
description: IOC extraction, threat intelligence correlation, MITRE ATT&CK mapping, and hunt hypothesis generation
version: 1.0.0
author: Masriyan
tags:
  [
    cybersecurity,
    threat-hunting,
    ioc,
    mitre-attack,
    threat-intelligence,
    detection,
  ]
---

# 🎯 Threat Hunting & IOC Analysis

## Overview

This skill enables Claude to assist threat hunters with proactive threat detection, IOC extraction and analysis, MITRE ATT&CK framework mapping, hunt hypothesis generation, and threat intelligence correlation. It bridges the gap between raw threat data and actionable hunting queries.

---

## Prerequisites

### Required

- Python 3.8+
- `requests`, `pyyaml`, `jinja2`

### Optional

- **MISP** — Threat intelligence sharing platform
- **OpenCTI** — Threat intelligence platform
- **YARA** — Pattern matching
- **Sigma** — Generic detection rules
- SIEM access (Splunk, Elastic, QRadar, Sentinel)

```bash
pip install requests pyyaml stix2 taxii2-client
```

---

## Core Capabilities

### 1. IOC Extraction & Analysis

Extract and validate indicators of compromise from any text source:

**When the user asks to extract IOCs:**

1. Parse input text for indicators (reports, logs, emails, articles)
2. Extract all indicator types:
   - **Network**: IPv4/IPv6 addresses, domains, URLs, email addresses
   - **File**: MD5, SHA1, SHA256, SSDeep hashes, filenames
   - **Host**: Registry keys, mutex names, service names, file paths
   - **Other**: CVE IDs, MITRE technique IDs, Bitcoin addresses
3. Validate and defang extracted indicators
4. Deduplicate and categorize results
5. Enrich with threat intelligence lookups
6. Score indicators by confidence and relevance
7. Output in STIX, CSV, JSON, or MISP-compatible format

### 2. MITRE ATT&CK Mapping

Map threat behaviors to the ATT&CK framework:

**When the user asks to map to ATT&CK:**

1. Analyze the threat description, behavior, or TTPs
2. Map each behavior to specific ATT&CK techniques
3. Identify the tactics (why) and techniques (how)
4. Provide sub-technique precision where possible
5. Link to ATT&CK Navigator layer export
6. Suggest detection opportunities for each technique
7. Identify gaps in detection coverage

### 3. Hunt Hypothesis Generation

Create structured hunt hypotheses:

**When the user asks to generate hunt hypotheses:**

1. Analyze the threat landscape relevant to the organization
2. Consider known adversary TTPs and recent threat intel
3. Generate hypotheses following the format:
   - **Hypothesis**: What are we looking for?
   - **Rationale**: Why do we think this might be present?
   - **Data Sources**: What logs/data do we need?
   - **Detection Logic**: How do we find it?
   - **ATT&CK Mapping**: Which techniques does this cover?
   - **Success Criteria**: How do we know if we found it?
4. Prioritize hypotheses by likelihood and impact
5. Generate corresponding SIEM queries

### 4. Threat Intelligence Correlation

Correlate IOCs and behaviors across multiple sources:

**When the user asks to correlate threat intel:**

1. Cross-reference IOCs across threat feeds
2. Identify common infrastructure between campaigns
3. Map IOCs to known threat actor groups
4. Determine the likely malware family
5. Assess the threat's relevance to the organization
6. Generate a threat assessment report
7. Recommend defensive actions

### 5. Detection Rule Generation

Create detection rules from threat intelligence:

**When the user asks to create detection rules:**

1. Analyze the threat behavior or IOCs
2. Generate Sigma rules for platform-agnostic detection
3. Convert to SIEM-specific queries (Splunk SPL, KQL, EQL)
4. Create YARA rules for file-based detection
5. Generate Snort/Suricata rules for network detection
6. Test rules against sample data
7. Document false positive considerations

---

## Usage Instructions

### Example Prompts

```
> Extract all IOCs from this threat intelligence report
> Map these TTPs to MITRE ATT&CK and suggest detection queries
> Generate hunt hypotheses for detecting APT29 in our Windows environment
> Create Sigma detection rules for this lateral movement technique
> Correlate these IOCs with known threat actor campaigns
> Build a Splunk query to hunt for T1053.005 (Scheduled Task)
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
```

---

## Integration Guide

### Chaining with Other Skills

- **← Malware Analysis (05)**: Receive IOCs from malware analysis
- **← Incident Response (07)**: Receive artifacts from IR for hunting
- **→ Log Analysis (12)**: Feed hunting queries to SIEM
- **→ Blue Team Defense (15)**: Generate detection rules
- **→ CSOC Automation (11)**: Automate response to hunting findings

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [STIX/TAXII Standards](https://oasis-open.github.io/cti-documentation/)
- [Threat Hunting Playbook](https://threathunterplaybook.com/)
- [MISP Project](https://www.misp-project.org/)
