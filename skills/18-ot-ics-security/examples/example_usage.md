# OT / ICS / SCADA Security — Example Usage

> **Safety first**: default to passive analysis. Active probing only with asset-owner sign-off, on a bench or maintenance window, never against Safety Instrumented Systems (SIS).

## Passive PCAP Analysis

```bash
# Export a capture to tshark JSON, then summarize ICS protocols + control ops
tshark -r plant_capture.pcap -T json > capture.json
python scripts/ics_protocol_analyzer.py --input capture.json --output ics_report.json
```

Flags Modbus writes (FC 5/6/15/16), S7 program ops, unexpected talkers, and IT→OT flows.

## Exposure Dork Generation (external, read-only)

```bash
# Generic ICS exposure dorks
python scripts/ics_protocol_analyzer.py --dorks --output dorks.txt

# Vendor-specific
python scripts/ics_protocol_analyzer.py --dorks --vendor siemens --output siemens_dorks.txt
```

## Read-Only Active Discovery (only if authorized)

```bash
# Low-rate, read-only NSE scripts — never against SIS
nmap -sT -p 502 --script modbus-discover 10.10.20.0/24
nmap -sT -p 102 --script s7-info 10.10.20.0/24
nmap -sT -p 47808 --script bacnet-info 10.10.20.0/24
```

## Conversational Examples (skill activates automatically)

```
> Review this OT network diagram against the Purdue model and flag boundary violations
> From this capture, which hosts are issuing Modbus write commands to PLCs?
> Map a TRITON-style attack path to MITRE ATT&CK for ICS for our DCS
> Recommend IEC 62443 zones, conduits, and target Security Levels for this plant
> Generate Shodan dorks to check if any of our Schneider PLCs are internet-exposed
```

## Integration Workflow

```bash
# 1. Passive capture summary (this skill)
python scripts/ics_protocol_analyzer.py --input capture.json -o ics_report.json
# 2. Deep PCAP + IDS rule authoring  → Skill 08
# 3. PLC/RTU firmware reverse engineering → Skill 04
# 4. OT detection content for SIEM/OT monitoring → Skill 12
# 5. IT/OT boundary host hardening → Skill 15
```
