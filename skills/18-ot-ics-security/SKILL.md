---
name: OT / ICS / SCADA Security
description: Operational Technology and industrial control system security — Purdue model segmentation, industrial protocol analysis (Modbus, DNP3, S7, EtherNet/IP), PLC/HMI exposure, IEC 62443 alignment, and MITRE ATT&CK for ICS, for authorized and safety-conscious assessments
version: 3.0.0
author: Masriyan
tags: [cybersecurity, ot-security, ics, scada, modbus, dnp3, plc, iec62443, attack-ics, purdue-model]
---

# OT / ICS / SCADA Security

## Purpose

Enable Claude to assess Operational Technology (OT) and Industrial Control System (ICS) environments — PLCs, RTUs, HMIs, SCADA servers, historians, and field devices — with **safety as the first constraint**. Claude reasons about the Purdue/ISA-95 model, analyzes industrial protocols passively, maps adversary behavior to **MITRE ATT&CK for ICS**, and aligns recommendations to **IEC 62443** and the **NIST SP 800-82** guidance.

> **SAFETY & AUTHORIZATION — READ FIRST**: OT systems control physical processes; a crashed PLC can mean equipment damage, environmental release, or loss of life. **Default to passive, non-intrusive methods.** Never send active scans, writes, or protocol fuzzing to production OT without written authorization, asset-owner sign-off, and a tested rollback/safety plan — ideally on a test bench or during a maintenance window. Confirm scope and the "do-no-harm" boundary before proceeding.

---

## Activation Triggers

This skill activates when the user asks about:
- ICS / SCADA / OT / DCS security or industrial network assessment
- Modbus, DNP3, S7comm, EtherNet/IP, BACnet, OPC-UA, IEC 61850/104 protocols
- PLC, RTU, HMI, historian, or engineering-workstation security
- Purdue model / ISA-95 segmentation and IT/OT boundary review
- IEC 62443, NIST SP 800-82, or NERC CIP alignment
- MITRE ATT&CK for ICS technique mapping
- Internet-exposed ICS devices (Shodan/Censys dorks) or ICS asset inventory
- OT threat detection, anomaly monitoring, or ICS incident response

---

## Prerequisites

```bash
pip install requests pyyaml
# Protocol libraries (lab use): pip install pymodbus scapy
```

**Optional enhanced capabilities:**
- Wireshark / `tshark` with ICS dissectors (Modbus, DNP3, S7, ENIP, GOOSE)
- `nmap` ICS NSE scripts (use read-only scripts only, with care)
- GRASSMARLIN / passive asset-discovery tooling
- Shodan/Censys access for exposure checks (passive, external)

---

## Core Capabilities

### 1. Architecture & Purdue Model Review

When asked to review OT architecture, map assets to Purdue levels and assess the boundaries:

| Level | Zone | Assets | Key control |
|-------|------|--------|-------------|
| 4–5 | Enterprise / IT | ERP, business network, internet | Should never directly reach L0–L2 |
| 3.5 | **IDMZ** | Jump hosts, patch/AV relays, historian replica | Brokered, inspected IT↔OT traffic only |
| 3 | Operations | SCADA servers, historians, engineering WS | Hardened, monitored |
| 2 | Supervisory | HMIs, control servers | |
| 1 | Control | PLCs, RTUs, IEDs | |
| 0 | Process | Sensors, actuators, drives | |

Flag: missing IDMZ, flat IT/OT networks, dual-homed engineering workstations, remote vendor access bypassing the DMZ, and any direct path from L4/L5 to L0–L2.

### 2. Industrial Protocol Analysis (Passive-First)

Prefer reading a SPAN/TAP capture over active probing. From a PCAP, identify:
- **Modbus/TCP (502)** — function codes; flag writes (FC 5/6/15/16), unauthenticated reads, exposure beyond the cell.
- **DNP3 (20000)** — operate/direct-operate, lack of Secure Authentication (SAv5).
- **S7comm / S7comm-plus (102)** — PLC start/stop, program upload/download.
- **EtherNet/IP + CIP (44818/2222)** — forward-open, attribute writes.
- **OPC-UA (4840)** — security policy `None`, anonymous sessions.
- **IEC 61850 GOOSE/MMS, IEC 60870-5-104 (2404), BACnet (47808)** as present.

Note that **most ICS protocols have no authentication or encryption by design** — any reachable client can issue commands. Use `scripts/ics_protocol_analyzer.py` to summarize an exported PCAP and flag write/control operations and unexpected talkers.

### 3. Exposure & Asset Discovery

- **Passive inventory** from captures (MAC/OUI → vendor, protocol → device role).
- **External exposure** (read-only, external) via Shodan/Censys dorks — never expose live device details publicly:
  - `port:502 product:Modbus`, `port:20000 source address`, `tag:ics`, `"Siemens, SIMATIC"`, `port:47808`, `"Schneider Electric"`.
- For any device that *must* be reachable, document why, the compensating controls, and whether it should be behind the IDMZ instead.
- Active scanning, if authorized: use only read-only `nmap` NSE (`modbus-discover`, `s7-info`, `bacnet-info`, `enip-info`) with low rate, never against safety-instrumented systems (SIS).

### 4. Threat Modeling — MITRE ATT&CK for ICS

Map plausible adversary paths using the ICS matrix tactics: Initial Access → Execution → Persistence → Evasion → Discovery → Lateral Movement → Collection → Command-and-Control → **Inhibit Response Function** → **Impair Process Control** → **Impact**. Reference high-signal techniques (e.g., T0883 Internet-Accessible Device, T0836 Modify Parameter, T0831 Manipulation of Control, T0814 Denial of Service, T0816 Device Restart/Shutdown). Anchor scenarios to real tradecraft (Stuxnet, TRITON/TRISIS targeting SIS, Industroyer/CRASHOVERRIDE, PIPEDREAM/INCONTROLLER).

### 5. IEC 62443 / NIST SP 800-82 Alignment

- Define **zones and conduits**; assign **Security Levels (SL 1–4)** per zone based on threat.
- Review against IEC 62443-3-3 system requirements (FR1 IAC, FR2 UC, FR3 system integrity, FR4 data confidentiality, FR5 restricted data flow, FR6 timely response, FR7 resource availability).
- Map to NIST SP 800-82r3 control overlays and NERC CIP where the asset owner is in scope (BES).

### 6. OT-Aware Detection & Incident Response

- Detection: baseline normal protocol talkers and command rates; alert on unexpected write/program-download, new engineering connections, off-hours commands, and L4→L1 traffic.
- IR (coordinate with → Skill 07, but OT-modified): **safety and process continuity outrank evidence preservation**; involve process/safety engineers; prefer passive collection; have a manual-operations fallback before isolating anything.

---

## Output Standards

```markdown
# OT/ICS Security Assessment — [Site / System]
Date: [Date] | Scope: [Zones/Assets] | Method: [Passive/Active] | Analyst: [Name]
Safety constraints honored: [yes — passive only / window used / etc.]

## Executive Summary
[Posture, top safety-relevant risks]

## Purdue / Zone-Conduit Map
[Levels, boundaries, IDMZ status]

## Findings
### [O-01] Modbus writes reachable from IT VLAN  (Critical)
- ATT&CK ICS: T0883, T0836 | IEC 62443 FR5
- Evidence: [pcap flow IT-host → PLC FC16]
- Process impact: [what physical effect is possible]
- Remediation: [conduit/firewall rule, IDMZ broker, read-only segmentation]

## IEC 62443 Zone/SL Recommendations
| Zone | Current SL | Target SL | Gap |

## Prioritized Remediation (safety-weighted)
```

---

## Script Reference

### `ics_protocol_analyzer.py`
```bash
# Summarize an exported PCAP CSV/JSON (from tshark) and flag control/write ops
tshark -r capture.pcap -T json > capture.json
python scripts/ics_protocol_analyzer.py --input capture.json --output ics_report.json

# Generate Shodan/Censys exposure dorks for a vendor/protocol set
python scripts/ics_protocol_analyzer.py --dorks --vendor siemens --output dorks.txt
```

---

## Skill Integration

| Next Step | Condition | Target Skill |
|-----------|-----------|--------------|
| Deep PCAP / IDS rules | Network capture available | → Skill 08 |
| Firmware / device RE | PLC/RTU firmware obtained | → Skill 04 |
| OT incident handling | Active incident | → Skill 07 |
| Detection content | SIEM/OT-monitoring rules needed | → Skill 12 |
| IT-side segmentation hardening | IT/OT boundary hosts | → Skill 15 |

---

## References

- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- [NIST SP 800-82 Rev. 3 — Guide to OT Security](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [IEC 62443 series — Industrial Automation and Control Systems Security](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)
- [CISA — ICS Recommended Practices & Advisories](https://www.cisa.gov/topics/industrial-control-systems)
- [NERC CIP Standards](https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx)
