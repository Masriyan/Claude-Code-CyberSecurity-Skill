---
name: Network Security & Traffic Analysis
description: Network traffic analysis, PCAP parsing, IDS/IPS rule creation, and firewall configuration auditing
version: 1.0.0
author: Masriyan
tags:
  [
    cybersecurity,
    network,
    traffic-analysis,
    pcap,
    ids,
    firewall,
    snort,
    suricata,
  ]
---

# 🌐 Network Security & Traffic Analysis

## Overview

This skill enables Claude to assist with network security operations including traffic analysis, PCAP parsing, IDS/IPS rule creation, firewall configuration review, and network architecture assessment.

---

## Prerequisites

### Required

- Python 3.8+
- `scapy`, `dpkt`

### Optional

- **Wireshark / tshark** — Packet capture and analysis
- **Suricata** — IDS/IPS engine
- **Snort** — IDS/IPS engine
- **Zeek (Bro)** — Network analysis framework
- **tcpdump** — Command-line packet capture
- **nmap** — Network scanning

```bash
pip install scapy dpkt requests
```

---

## Core Capabilities

### 1. PCAP Traffic Analysis

**When the user asks to analyze network traffic:**

1. Parse PCAP/PCAPNG files for packet-level data
2. Extract protocol statistics (TCP, UDP, DNS, HTTP, TLS)
3. Identify top talkers (source/destination IP pairs)
4. Detect suspicious patterns (port scanning, beaconing, data exfiltration)
5. Extract DNS queries and identify suspicious domains
6. Parse HTTP requests/responses for IOCs
7. Identify TLS certificates and analyze SNI values
8. Detect tunneling (DNS tunneling, ICMP tunneling)
9. Generate network flow summaries
10. Export findings in structured format

### 2. IDS/IPS Rule Creation

**When the user asks to create detection rules:**

1. Analyze the attack pattern or malicious traffic
2. Create Snort-compatible rules with proper syntax
3. Create Suricata rules with advanced features
4. Test rules for performance and false positives
5. Organize rules by category (malware, exploit, policy, info)
6. Include metadata (SID, revision, classification, reference)
7. Generate Zeek scripts for behavioral detection

**Rule Template:**

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"[Description]";
    content:"|hex pattern|";
    flow:established,to_server;
    sid:1000001;
    rev:1;
    classtype:trojan-activity;
    reference:cve,CVE-YYYY-XXXX;
)
```

### 3. Firewall Configuration Auditing

**When the user asks to review firewall rules:**

1. Parse firewall rule sets (iptables, pf, Windows Firewall, cloud security groups)
2. Identify overly permissive rules (any-any, 0.0.0.0/0)
3. Check for shadowed/redundant rules
4. Verify deny-by-default posture
5. Audit logging configuration
6. Check for management access restrictions
7. Generate compliance-ready audit report

### 4. Network Anomaly Detection

**When the user asks to detect anomalies:**

1. Establish baseline network behavior profiles
2. Detect beaconing patterns (regular interval callbacks)
3. Identify data exfiltration attempts (large uploads, unusual protocols)
4. Detect lateral movement indicators
5. Identify port scanning and reconnaissance activity
6. Monitor for DNS anomalies (DGA, tunneling, unusual TXT queries)

### 5. Network Architecture Security Review

**When the user asks to review network architecture:**

1. Analyze network segmentation and zones
2. Review DMZ configuration
3. Assess east-west traffic controls
4. Evaluate network access control policies
5. Check for proper micro-segmentation
6. Review VPN and remote access configurations

---

## Usage Instructions

### Example Prompts

```
> Analyze this PCAP file for suspicious network activity
> Create Suricata rules to detect C2 beaconing over HTTP
> Review these iptables rules for security issues
> Detect DNS tunneling in this network capture
> Generate a network security assessment report
```

---

## Script Reference

### `pcap_analyzer.py`

```bash
python scripts/pcap_analyzer.py --file capture.pcap --output analysis.json
python scripts/pcap_analyzer.py --file traffic.pcapng --dns --http --top-talkers 20
```

---

## Integration Guide

- **← Recon & OSINT (01)**: Receive network scan results for deeper analysis
- **→ Threat Hunting (06)**: Feed network IOCs for correlation
- **→ Incident Response (07)**: Provide network evidence for IR timelines
- **→ CSOC Automation (11)**: Automate alert responses for network-based detections

---

## References

- [Suricata Documentation](https://suricata.readthedocs.io/)
- [Snort Rule Writing Guide](https://docs.snort.org/)
- [Wireshark User Guide](https://www.wireshark.org/docs/)
- [Zeek Documentation](https://docs.zeek.org/)
- [SANS Network Forensics](https://www.sans.org/reading-room/)
