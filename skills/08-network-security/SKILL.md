---
name: Network Security & Traffic Analysis
description: Network traffic analysis, PCAP parsing, IDS/IPS rule creation, firewall configuration auditing, and network anomaly detection
version: 3.0.0
author: Masriyan
tags: [cybersecurity, network, traffic-analysis, pcap, ids, ips, firewall, snort, suricata, zeek]
---

# Network Security & Traffic Analysis

## Purpose

Enable Claude to assist with network security operations including traffic analysis from PCAP files, IDS/IPS rule authoring for Snort and Suricata, firewall rule auditing, network anomaly detection, and network architecture security reviews.

---

## Activation Triggers

This skill activates when the user asks about:
- Analyzing PCAP or PCAPNG files for suspicious activity
- Creating Snort or Suricata detection rules
- Writing Zeek (Bro) scripts for network analysis
- Reviewing firewall rules (iptables, nftables, pf, cloud security groups)
- Detecting C2 beaconing, DNS tunneling, or data exfiltration in network traffic
- Network architecture security review
- IDS/IPS signature development
- Network segmentation and east-west traffic analysis
- TLS inspection and certificate analysis

---

## Prerequisites

```bash
pip install scapy dpkt requests
```

**Recommended tools:**
- `Wireshark / tshark` — Packet capture and GUI analysis
- `Suricata` — Modern IDS/IPS engine
- `Snort 3` — Classic IDS/IPS engine
- `Zeek (Bro)` — Network analysis and scripting framework
- `tcpdump` — Command-line packet capture
- `NetworkMiner` — PCAP artifact extraction
- `nmap` — Network scanning and discovery

---

## Core Capabilities

### 1. PCAP Traffic Analysis

**When the user provides a PCAP file or asks to analyze network traffic:**

```bash
# Quick summary with tshark
tshark -r capture.pcap -q -z io,phs           # Protocol hierarchy
tshark -r capture.pcap -q -z conv,tcp         # TCP conversations
tshark -r capture.pcap -q -z endpoints,ip     # IP endpoints

# Extract HTTP requests
tshark -r capture.pcap -Y http.request -T fields -e ip.src -e http.host -e http.request.uri

# Extract DNS queries
tshark -r capture.pcap -Y dns.flags.response==0 -T fields -e ip.src -e dns.qry.name

# Extract files
tshark -r capture.pcap --export-objects http,./extracted_files/
tshark -r capture.pcap --export-objects smb,./smb_files/

# Run automated analysis
python scripts/pcap_analyzer.py --file capture.pcap --output analysis.json
python scripts/pcap_analyzer.py --file traffic.pcapng --dns --http --top-talkers 20
```

**Traffic Analysis Checklist:**
```
[ ] Protocol distribution — any unexpected protocols?
[ ] Top talkers — unusual source/destination combinations
[ ] DNS analysis — DGA domains, unusually long queries, high volume
[ ] HTTP analysis — suspicious user agents, unusual methods, encoded data
[ ] TLS analysis — invalid certificates, unusual SNI, cert fingerprints
[ ] ICMP analysis — large payloads (tunneling), ping sweeps
[ ] SMB analysis — authentication attempts, file access patterns
[ ] Data volume — large uploads (exfiltration?), irregular transfer sizes
[ ] Timing analysis — regular interval beaconing patterns
```

**Beaconing Detection:**
Beaconing shows as consistent time intervals between outbound connections:
```bash
# tshark: extract connection timestamps to check for regularity
tshark -r capture.pcap -Y "ip.dst == 203.0.113.10 and tcp.flags.syn==1" \
  -T fields -e frame.time_epoch | \
  awk 'NR>1{printf "%.0f\n", ($1-prev)} {prev=$1}' | sort | uniq -c | sort -rn
# Consistent counts at specific intervals = beaconing
```

**DNS Tunneling Detection:**
```bash
# Long DNS query names (>50 chars for subdomain) = likely tunneling
tshark -r capture.pcap -Y "dns.qry.name.len > 50" \
  -T fields -e ip.src -e dns.qry.name | head -50

# High-volume DNS to single domain = tunneling
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | \
  awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -20
```

### 2. Suricata Rule Creation

**When the user asks to create Suricata IDS rules:**

**Suricata Rule Syntax Reference:**
```
action protocol src_ip src_port -> dst_ip dst_port (options)
```

**Rule Templates:**

```suricata
# Template: C2 Beaconing over HTTP
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"MALWARE Suspicious C2 Beacon - Regular Interval HTTP POST";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/api/check" endswith;
    http.header; content:"User-Agent: Mozilla/4.0 (compatible)";
    threshold:type both, track by_src, count 5, seconds 300;
    classtype:trojan-activity;
    sid:9000001;
    rev:1;
    metadata:affected_product Windows_XP_Vista_7_8_10_Server, attack_target Client_Endpoint,
              created_at 2025_05_28, deployment Perimeter;
)

# Template: DNS Tunneling Detection
alert dns $HOME_NET any -> any any (
    msg:"POLICY Possible DNS Tunneling - Long Subdomain Query";
    dns.query;
    content:".";
    byte_test:1,>,50,0,relative;  # Query length > 50 chars
    threshold:type both, track by_src, count 20, seconds 60;
    classtype:policy-violation;
    sid:9000002;
    rev:1;
)

# Template: Lateral Movement via SMB
alert smb $HOME_NET any -> $HOME_NET 445 (
    msg:"LATERAL-MOVEMENT PsExec Lateral Movement Detected";
    flow:established,to_server;
    content:"PSEXESVC";
    nocase;
    classtype:trojan-activity;
    sid:9000003;
    rev:1;
)

# Template: Data Exfiltration - Large Upload
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"EXFILTRATION Possible Data Exfiltration - Large HTTP POST";
    flow:established,to_server;
    http.method; content:"POST";
    http.request_body; content:!"";
    dsize:>1000000;   # > 1MB body
    threshold:type both, track by_src, count 3, seconds 300;
    classtype:policy-violation;
    sid:9000004;
    rev:1;
)

# Template: Malicious TLS Certificate (self-signed with suspicious CN)
alert tls $EXTERNAL_NET any -> $HOME_NET any (
    msg:"MALWARE Suspicious TLS Certificate - Self-Signed C2";
    tls.cert_subject; content:"CN=localhost";
    tls.cert_issuer; content:"CN=localhost";
    classtype:trojan-activity;
    sid:9000005;
    rev:1;
)

# Template: Web Shell Access
alert http $EXTERNAL_NET any -> $HOME_NET 80 (
    msg:"WEBSHELL Possible Web Shell Access";
    flow:established,to_server;
    http.uri; content:".php";
    http.request_body; content:"cmd="; nocase;
    content:"exec"; nocase; distance:0;
    classtype:web-application-attack;
    sid:9000006;
    rev:1;
)
```

**Suricata Testing:**
```bash
# Test rules against PCAP (offline)
suricata -r capture.pcap -S custom.rules -l ./logs/

# Test rule syntax
suricata --dump-config

# Check for rule performance issues
suricata -r test.pcap -S rules.rules --runmode single 2>&1 | grep "perf"
```

### 3. Snort 3 Rule Creation

```snort
# Snort 3 format — note different syntax from Snort 2
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (
    msg:"WEB-ATTACK SQL Injection Attempt";
    flow:established,to_server;
    http_uri;
    content:"' OR '1'='1";
    nocase;
    sid:9001001;
    rev:1;
    classtype:web-application-attack;
)
```

### 4. Zeek Script Templates

```zeek
# Detect connections with unusually regular intervals (beaconing)
module BeaconDetect;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts: time &log;
        src: addr &log;
        dst: addr &log;
        interval: interval &log;
    };
}

global connection_times: table[addr, addr] of vector of time;

event connection_established(c: connection) {
    local key = [c$id$orig_h, c$id$resp_h];
    if (key !in connection_times)
        connection_times[key] = vector();
    connection_times[key] += network_time();
}

event connection_state_remove(c: connection) {
    local key = [c$id$orig_h, c$id$resp_h];
    if (key in connection_times && |connection_times[key]| > 5) {
        # Calculate intervals and check for regularity
        # Flag if standard deviation < 5% of mean
    }
}
```

### 5. Firewall Configuration Auditing

**When the user provides firewall rules or asks to audit:**

**iptables Review Checklist:**
```bash
# View current rules
iptables -L -n -v --line-numbers
iptables -L INPUT -n -v --line-numbers
iptables -L OUTPUT -n -v --line-numbers

# Check for dangerous rules:
iptables -L | grep "ACCEPT"  # List all ACCEPT rules
iptables -L | grep "0.0.0.0"  # Any-source rules
```

**iptables Security Checklist:**
```
[ ] Default policy is DROP (not ACCEPT) for all chains
[ ] INPUT chain: only established/related + specific allowed services
[ ] OUTPUT chain: restrict to necessary outbound (optional but best practice)
[ ] FORWARD chain: DROP by default unless this is a router
[ ] Management access (SSH/22) restricted to specific source IPs
[ ] No rules accepting from 0.0.0.0/0 to ALL ports
[ ] Logging enabled for DROPPED packets
[ ] Anti-spoofing rules for RFC 1918 addresses on external interfaces
[ ] ICMP restricted (allow echo-reply/time-exceeded, block ping from internet)
[ ] Port 0 blocked (often used in scans)
```

**AWS Security Group Audit:**
```
Rules that should NEVER exist in production:
✗ Inbound: 0.0.0.0/0 → Port 22 (SSH open to internet)
✗ Inbound: 0.0.0.0/0 → Port 3389 (RDP open to internet)
✗ Inbound: 0.0.0.0/0 → Port 0-65535 (any port from internet)
✗ Outbound: 0.0.0.0/0 → Port 0-65535 (unrestricted outbound)

Rules that are acceptable:
✓ Inbound: 0.0.0.0/0 → Port 443 (HTTPS for public web service)
✓ Inbound: 10.0.0.0/8 → Port 22 (SSH from internal VPC only)
✓ Inbound: [known IP] → Port 22 (SSH from jump box)
```

**Firewall Audit Report Template:**
```markdown
## Firewall Audit Report — [Device/Platform]

**Risk Summary:**
| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 5 |
| Medium | 8 |

**CRITICAL: SSH exposed to internet**
- Rule: `iptables -A INPUT -p tcp --dport 22 -j ACCEPT`
- Risk: Exposed to brute-force and CVE exploitation
- Fix: `iptables -A INPUT -p tcp --dport 22 -s [admin_ip] -j ACCEPT`

**HIGH: No default deny policy**
- Current: `-P INPUT ACCEPT`
- Fix: `-P INPUT DROP` + explicit allow rules
```

### 6. Network Architecture Security Review

**When the user describes or provides a network architecture:**

**Review Framework:**
```
Zone Model (most to least trusted):
  Internal (Core) → DMZ → Internet

Checkpoints:
[ ] Clear network zones with enforced boundaries
[ ] DMZ properly isolated from internal network
[ ] No direct internet-to-internal traffic allowed
[ ] East-west traffic controls between internal zones (microsegmentation)
[ ] Management network isolated from production
[ ] Out-of-band management for network devices
[ ] VPN gateway in DMZ, not directly on internal segment
[ ] DNS resolvers not exposed to internet
[ ] Log aggregation on separate isolated segment
```

---

## Script Reference

### `pcap_analyzer.py`
```bash
python scripts/pcap_analyzer.py --file capture.pcap --output analysis.json
python scripts/pcap_analyzer.py --file traffic.pcapng --dns --http --top-talkers 20
python scripts/pcap_analyzer.py --file capture.pcap --detect-beaconing --output beacons.json
```

---

## Skill Integration

| Condition | Adjacent Skill |
|-----------|---------------|
| Discovered services from recon | ← Skill 01 (Recon & OSINT) |
| Network IOCs for threat correlation | → Skill 06 (Threat Hunting) |
| Network evidence for IR timeline | → Skill 07 (Incident Response) |
| Automate alert responses | → Skill 11 (CSOC Automation) |

---

## References

- [Suricata Documentation](https://suricata.readthedocs.io/)
- [Snort 3 Rule Writing Guide](https://docs.snort.org/start/rules)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Zeek Documentation](https://docs.zeek.org/)
- [SANS Network Forensics](https://www.sans.org/reading-room/)
- [The TCP/IP Guide](http://www.tcpipguide.com/)


---

## v3.0 Enhancements (2026 Update)

**Encrypted-traffic-era analysis:**

- **JA4+ fingerprinting** — adopt the JA4/JA4S/JA4H/JA4X suite (successor to JA3) to fingerprint clients, servers, and malware over TLS without decryption; pivot on these in Zeek/Suricata.
- **QUIC / HTTP3** — parse QUIC (UDP/443); recognize that classic TCP-centric rules miss it. Inspect Initial packets and SNI where visible.
- **Encrypted DNS** — detect DoH/DoT/DoQ usage and tunneling; baseline resolvers and flag rogue endpoints.
- **Beaconing detection refinement** — jitter-aware interval analysis, byte-count regularity, and long-connection scoring (RITA-style) to surface C2 over HTTPS/QUIC.
- **Zeek-first pipeline** — generate `conn`, `ssl`, `http`, `dns`, `x509`, and JA4 logs as the analysis substrate; write detections against Zeek notices.

**Precision rule:** report flows with the 5-tuple, JA4 fingerprint, bytes/duration, and a confidence-scored verdict; provide both a Suricata rule and a Zeek detection where applicable.
