#!/usr/bin/env python3
"""
Red Team Engagement Planner
Generates structured red team engagement plans.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

KILL_CHAIN_PHASES = [
    {"phase": "1. Reconnaissance", "techniques": ["OSINT", "DNS/Subdomain enum", "Social media profiling", "Technology fingerprinting"],
     "tools": ["theHarvester", "Recon-ng", "Maltego", "Shodan"]},
    {"phase": "2. Weaponization", "techniques": ["Payload development", "C2 infrastructure setup", "Phishing templates", "Exploit customization"],
     "tools": ["msfvenom", "Cobalt Strike", "Sliver", "GoPhish"]},
    {"phase": "3. Delivery", "techniques": ["Spearphishing", "Watering hole", "USB drop", "Supply chain"],
     "tools": ["GoPhish", "SET", "Evilginx2"]},
    {"phase": "4. Exploitation", "techniques": ["Client-side exploits", "Web app exploits", "Credential attacks", "Zero-day"],
     "tools": ["Metasploit", "Burp Suite", "CrackMapExec"]},
    {"phase": "5. Installation", "techniques": ["Backdoors", "Web shells", "Registry persistence", "Scheduled tasks"],
     "tools": ["Cobalt Strike", "Empire", "Sliver"]},
    {"phase": "6. Command & Control", "techniques": ["HTTPS C2", "DNS C2", "Domain fronting", "Peer-to-peer"],
     "tools": ["Cobalt Strike", "Sliver", "Havoc", "Mythic"]},
    {"phase": "7. Actions on Objectives", "techniques": ["Data exfiltration", "Lateral movement", "Privilege escalation", "Impact"],
     "tools": ["BloodHound", "Impacket", "Rubeus", "Mimikatz"]},
]


def generate_plan(scope: dict) -> dict:
    engagement_name = scope.get("name", "Red Team Engagement")
    target_org = scope.get("target", "Target Organization")

    plan = {
        "engagement_name": engagement_name,
        "target": target_org,
        "generated": time.strftime("%Y-%m-%d"),
        "rules_of_engagement": {
            "authorized_scope": scope.get("scope", ["All external-facing assets"]),
            "excluded": scope.get("excluded", ["Production databases", "Safety-critical systems"]),
            "testing_hours": scope.get("hours", "Business hours (Mon-Fri 09:00-18:00)"),
            "emergency_contact": scope.get("contact", "SOC Lead — security@org.com"),
            "deconfliction": "All C2 IPs registered with SOC prior to engagement",
        },
        "kill_chain_plan": KILL_CHAIN_PHASES,
        "success_criteria": [
            "Achieve domain admin in Active Directory",
            "Access sensitive data stores",
            "Maintain persistence for 48+ hours undetected",
            "Exfiltrate sample data to authorized C2",
        ],
        "reporting": {
            "daily_sitrep": True,
            "final_report_deadline": "5 business days post-engagement",
            "debrief_session": "Within 2 weeks of completion",
        },
    }
    return plan


def main():
    parser = argparse.ArgumentParser(description="Red Team Engagement Planner",
                                     epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill")
    parser.add_argument("--scope", "-s", help="Scope JSON file")
    parser.add_argument("--output", "-o", help="Output file")
    args = parser.parse_args()

    scope = {}
    if args.scope:
        with open(args.scope) as f:
            scope = json.load(f)

    plan = generate_plan(scope)
    output = json.dumps(plan, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        logger.info("Plan saved to %s", args.output)
    else:
        print(output)


if __name__ == "__main__":
    main()
