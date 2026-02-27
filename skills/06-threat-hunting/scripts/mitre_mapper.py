#!/usr/bin/env python3
"""
MITRE ATT&CK Mapper
Maps threat behaviors and techniques to the MITRE ATT&CK framework.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import sys
import time
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Core MITRE ATT&CK technique database (subset for offline use)
ATTACK_TECHNIQUES = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
        "subtechniques": {
            "T1059.001": {"name": "PowerShell", "detection": "Monitor for powershell.exe execution with unusual arguments"},
            "T1059.003": {"name": "Windows Command Shell", "detection": "Monitor for cmd.exe with encoded commands"},
            "T1059.004": {"name": "Unix Shell", "detection": "Monitor for bash/sh with base64 decoded commands"},
            "T1059.006": {"name": "Python", "detection": "Monitor for python execution from unusual paths"},
        },
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Execution, Persistence, Privilege Escalation",
        "description": "Adversaries may abuse task scheduling to execute malicious code.",
        "subtechniques": {
            "T1053.005": {"name": "Scheduled Task", "detection": "Monitor schtasks.exe /create commands"},
            "T1053.003": {"name": "Cron", "detection": "Monitor modifications to crontab and /etc/cron.*"},
        },
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Adversaries may inject code into processes to evade process-based defenses.",
        "subtechniques": {
            "T1055.001": {"name": "DLL Injection", "detection": "Monitor for LoadLibrary calls from unusual sources"},
            "T1055.003": {"name": "Thread Execution Hijacking", "detection": "Monitor for SuspendThread/SetThreadContext"},
            "T1055.012": {"name": "Process Hollowing", "detection": "Monitor for NtUnmapViewOfSection followed by WriteProcessMemory"},
        },
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols.",
        "subtechniques": {
            "T1071.001": {"name": "Web Protocols", "detection": "Monitor HTTP/HTTPS traffic for C2 patterns"},
            "T1071.004": {"name": "DNS", "detection": "Monitor for DNS tunneling (high query volume, TXT records)"},
        },
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": "Adversaries may use valid accounts to gain access.",
        "subtechniques": {
            "T1078.001": {"name": "Default Accounts", "detection": "Monitor for logons with default/built-in accounts"},
            "T1078.002": {"name": "Domain Accounts", "detection": "Monitor for unusual domain account activity"},
            "T1078.003": {"name": "Local Accounts", "detection": "Monitor for local account creation and usage"},
        },
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "subtechniques": {
            "T1110.001": {"name": "Password Guessing", "detection": "Monitor for multiple failed logon attempts"},
            "T1110.003": {"name": "Password Spraying", "detection": "Monitor for single password against many accounts"},
        },
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems or networks to interrupt availability.",
        "subtechniques": {},
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obfuscate files or information to hinder detection.",
        "subtechniques": {
            "T1027.001": {"name": "Binary Padding", "detection": "Monitor for unusually large binaries"},
            "T1027.002": {"name": "Software Packing", "detection": "Detect known packer signatures"},
        },
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get detailed information about the operating system.",
        "subtechniques": {},
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use remote services to move laterally.",
        "subtechniques": {
            "T1021.001": {"name": "Remote Desktop Protocol", "detection": "Monitor for unusual RDP connections"},
            "T1021.002": {"name": "SMB/Windows Admin Shares", "detection": "Monitor for C$/ADMIN$ share access"},
            "T1021.004": {"name": "SSH", "detection": "Monitor for SSH connections from unusual sources"},
            "T1021.006": {"name": "Windows Remote Management", "detection": "Monitor for WinRM connections"},
        },
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversaries may configure system settings to automatically execute at startup.",
        "subtechniques": {
            "T1547.001": {"name": "Registry Run Keys", "detection": "Monitor HKLM/HKCU Run key modifications"},
            "T1547.004": {"name": "Winlogon Helper DLL", "detection": "Monitor Winlogon registry changes"},
        },
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials from the OS.",
        "subtechniques": {
            "T1003.001": {"name": "LSASS Memory", "detection": "Monitor for LSASS process access"},
            "T1003.002": {"name": "Security Account Manager", "detection": "Monitor for SAM database access"},
            "T1003.003": {"name": "NTDS", "detection": "Monitor for ntdsutil or volume shadow copy access"},
        },
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may exploit vulnerabilities in internet-facing applications.",
        "subtechniques": {},
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access.",
        "subtechniques": {
            "T1566.001": {"name": "Spearphishing Attachment", "detection": "Monitor for suspicious email attachments"},
            "T1566.002": {"name": "Spearphishing Link", "detection": "Monitor for email links to known bad domains"},
        },
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating over alternative protocols.",
        "subtechniques": {
            "T1048.001": {"name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "detection": "Monitor for unusual encrypted outbound traffic"},
            "T1048.003": {"name": "Exfiltration Over Unencrypted Non-C2 Protocol", "detection": "Monitor for large DNS/ICMP transfers"},
        },
    },
}

# SIEM query templates
SIEM_TEMPLATES = {
    "splunk": {
        "T1059.001": 'index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*powershell*" | table _time, Computer, Account_Name, NewProcessName, Process_Command_Line',
        "T1053.005": 'index=windows sourcetype=WinEventLog:Security EventCode=4698 OR (EventCode=4688 NewProcessName="*schtasks*") | table _time, Computer, Account_Name, Task_Name',
        "T1110.001": 'index=windows sourcetype=WinEventLog:Security EventCode=4625 | stats count by src_ip, Account_Name | where count > 5',
        "T1021.001": 'index=windows sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=10 | table _time, Source_Network_Address, Account_Name, Computer',
        "T1003.001": 'index=windows sourcetype=WinEventLog:Security EventCode=4663 ObjectName="*lsass*" | table _time, Computer, Account_Name, Process_Name',
    },
    "elastic": {
        "T1059.001": 'event.code:4688 AND process.name:powershell.exe',
        "T1053.005": 'event.code:(4698 OR 4688) AND process.name:schtasks.exe',
        "T1110.001": 'event.code:4625 | stats count by source.ip, user.name | where count > 5',
        "T1021.001": 'event.code:4624 AND winlog.event_data.LogonType:10',
        "T1003.001": 'event.code:4663 AND file.path:*lsass*',
    },
}


class MITREMapper:
    """MITRE ATT&CK technique mapping and query generation engine."""

    def __init__(self):
        self.techniques = ATTACK_TECHNIQUES
        self.siem_templates = SIEM_TEMPLATES

    def lookup_technique(self, technique_id: str) -> Optional[Dict]:
        """Look up a technique by ID."""
        # Check top-level
        if technique_id in self.techniques:
            return {"id": technique_id, **self.techniques[technique_id]}

        # Check sub-techniques
        parent_id = technique_id.split(".")[0]
        if parent_id in self.techniques:
            subtechniques = self.techniques[parent_id].get("subtechniques", {})
            if technique_id in subtechniques:
                return {
                    "id": technique_id,
                    "parent": parent_id,
                    "parent_name": self.techniques[parent_id]["name"],
                    "tactic": self.techniques[parent_id]["tactic"],
                    **subtechniques[technique_id],
                }
        return None

    def map_techniques(self, technique_ids: List[str]) -> Dict[str, Any]:
        """Map multiple technique IDs to ATT&CK details."""
        mapped = []
        unmapped = []

        for tid in technique_ids:
            result = self.lookup_technique(tid.strip())
            if result:
                mapped.append(result)
            else:
                unmapped.append(tid)

        # Group by tactic
        by_tactic = {}
        for tech in mapped:
            tactics = tech.get("tactic", "Unknown")
            for tactic in tactics.split(", "):
                if tactic not in by_tactic:
                    by_tactic[tactic] = []
                by_tactic[tactic].append(tech)

        return {
            "total_mapped": len(mapped),
            "total_unmapped": len(unmapped),
            "techniques": mapped,
            "unmapped": unmapped,
            "by_tactic": {k: [t["id"] for t in v] for k, v in by_tactic.items()},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def generate_detection_query(self, technique_id: str, siem: str = "splunk") -> Optional[str]:
        """Generate a SIEM detection query for a technique."""
        templates = self.siem_templates.get(siem, {})
        return templates.get(technique_id)

    def generate_navigator_layer(self, technique_ids: List[str], name: str = "Threat Map") -> Dict:
        """Generate an ATT&CK Navigator layer JSON."""
        techniques = []
        for tid in technique_ids:
            tech = self.lookup_technique(tid)
            if tech:
                techniques.append({
                    "techniqueID": tid,
                    "color": "#e60d0d",
                    "comment": tech.get("name", ""),
                    "enabled": True,
                })

        return {
            "name": name,
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"Generated by CyberSkill MITRE Mapper — {time.strftime('%Y-%m-%d')}",
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 1,
            },
        }


def main():
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Mapper",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--input", "-i", help="File with technique IDs (one per line)")
    parser.add_argument("--technique", "-t", help="Single technique ID to look up")
    parser.add_argument("--detection-query", choices=["splunk", "elastic"], help="Generate SIEM query")
    parser.add_argument("--navigator", action="store_true", help="Export ATT&CK Navigator layer")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    mapper = MITREMapper()

    if args.technique:
        technique_ids = [args.technique]
    elif args.input:
        with open(args.input, "r") as f:
            technique_ids = [line.strip() for line in f if line.strip()]
    else:
        parser.error("Either --technique or --input is required")

    if args.detection_query:
        for tid in technique_ids:
            query = mapper.generate_detection_query(tid, args.detection_query)
            if query:
                print(f"\n# {tid} — {args.detection_query.upper()} Query:")
                print(query)
            else:
                print(f"\n# {tid} — No query template available")
        return

    if args.navigator:
        result = mapper.generate_navigator_layer(technique_ids)
    else:
        result = mapper.map_techniques(technique_ids)

    output_data = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_data)
        logger.info("Results saved to %s", args.output)
    else:
        print(output_data)


if __name__ == "__main__":
    main()
