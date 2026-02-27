---
name: Blue Team Defense & Hardening
description: System hardening, detection engineering, baseline monitoring, and patch management
version: 1.0.0
author: Masriyan
tags: [cybersecurity, blue-team, defense, hardening, detection]
---

# 🔵 Blue Team Defense & Hardening

## Overview

This skill assists defenders with system hardening, detection rule engineering, security baselines, patch management, and security architecture review.

---

## Prerequisites

- Python 3.8+, `pyyaml`, `jinja2`

```bash
pip install pyyaml jinja2 requests
```

---

## Core Capabilities

### 1. System Hardening

**Linux:** Disable unnecessary services, SSH hardening, fail2ban, firewall (iptables/nftables), auditd, SELinux/AppArmor, sysctl tuning, SUID cleanup.

**Windows:** CIS Benchmark GPOs, Defender ASR rules, AppLocker/WDAC, disable LLMNR/NBT-NS, PowerShell logging, Credential Guard, LAPS, Sysmon.

### 2. Detection Engineering

Create Sigma, Splunk SPL, KQL, EQL, YARA, and Snort/Suricata rules. Define TP/FP criteria, test against known data, document in detection catalog.

### 3. Security Baseline Monitoring

Define normal behavior, monitor deviations (new services/processes/connections), FIM, track privileged account usage, software inventory.

### 4. Patch Management

Assess CVSS criticality, plan deployment timelines, pre-patch testing, rollback procedures, compliance reports, patch debt tracking.

### 5. Security Architecture Review

Defense-in-depth, network segmentation, zero trust, IAM maturity, endpoint protection stack, logging coverage, backup/DR.

---

## Script Reference

### `hardening_checker.py`

```bash
python scripts/hardening_checker.py --os ubuntu --output report.json
python scripts/hardening_checker.py --os windows --cis-level 1 --output report.json
```

---

## Integration Guide

- **← All Offensive Skills**: Receive findings for defensive improvements
- **→ CSOC Automation (11)**: Deploy detection rules
- **→ Log Analysis (12)**: Feed baselines for anomaly detection
- **→ Threat Hunting (06)**: Identify coverage gaps

---

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE D3FEND](https://d3fend.mitre.org/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
