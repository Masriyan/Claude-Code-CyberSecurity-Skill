#!/usr/bin/env python3
"""
Red Team Engagement Planner (v3.0)

Generates a structured, ATT&CK-aligned red team engagement plan with full Rules
of Engagement, OPSEC plan, and an attack-log scaffold for the purple-team
debrief. Outputs JSON or Markdown.

For AUTHORIZED engagements only — the plan template enforces an authorization
section so scope/RoE/de-confliction are explicit before any operational step.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Phases mapped to MITRE ATT&CK tactics + representative technique IDs.
KILL_CHAIN_PHASES = [
    {"phase": "1. Reconnaissance", "attack_tactic": "TA0043 Reconnaissance",
     "techniques": ["OSINT (T1589/T1591)", "Subdomain & DNS enum (T1590)",
                    "Search victim-owned sites (T1594)", "Tech fingerprinting"],
     "tools": ["theHarvester", "Amass", "Maltego", "Shodan", "BloodHound CE"]},
    {"phase": "2. Resource Development / Weaponization", "attack_tactic": "TA0042 Resource Development",
     "techniques": ["C2 infra + redirectors (T1583)", "Malleable profiles",
                    "Phishing pretext dev (T1585/T1586)", "Payload tradecraft"],
     "tools": ["Sliver", "Mythic", "Havoc", "Cobalt Strike", "GoPhish", "Evilginx"]},
    {"phase": "3. Initial Access / Delivery", "attack_tactic": "TA0001 Initial Access",
     "techniques": ["Spearphishing link/attachment (T1566)", "Valid accounts (T1078)",
                    "Device-code / consent phishing", "External-facing exploit (T1190)"],
     "tools": ["Evilginx", "GoPhish", "Burp Suite"]},
    {"phase": "4. Execution & Persistence", "attack_tactic": "TA0002/TA0003",
     "techniques": ["In-memory execution (T1059)", "Scheduled task/service (T1053/T1543)",
                    "Account manipulation (T1098)", "EDR-aware loaders"],
     "tools": ["Sliver", "Mythic", "Custom loaders"]},
    {"phase": "5. Privilege Escalation & Defense Evasion", "attack_tactic": "TA0004/TA0005",
     "techniques": ["AD CS abuse ESC1-ESC14", "Token theft/replay", "BYOVD considerations",
                    "AMSI/ETW awareness (T1562)"],
     "tools": ["Certify/Certipy", "Rubeus", "BloodHound CE"]},
    {"phase": "6. Command & Control", "attack_tactic": "TA0011 Command and Control",
     "techniques": ["HTTPS C2 (T1071)", "Domain fronting alt / SaaS C2 (T1102)",
                    "DNS C2 (T1071.004)"],
     "tools": ["Sliver", "Mythic", "Havoc"]},
    {"phase": "7. Discovery, Lateral Movement & Collection", "attack_tactic": "TA0007/TA0008/TA0009",
     "techniques": ["AD recon (T1087/T1482)", "Pass-the-* / remote svc (T1021)",
                    "Cloud control-plane pivot", "Data staging (T1074)"],
     "tools": ["Impacket", "BloodHound CE", "Rubeus"]},
    {"phase": "8. Actions on Objectives / Impact", "attack_tactic": "TA0010/TA0040",
     "techniques": ["Exfil to authorized C2 (T1041)", "Objective data access",
                    "Demonstrate impact (no destructive action unless authorized)"],
     "tools": ["Authorized exfil channel"]},
]


def generate_plan(scope: dict) -> dict:
    plan = {
        "engagement_name": scope.get("name", "Red Team Engagement"),
        "target": scope.get("target", "Target Organization"),
        "generated": time.strftime("%Y-%m-%d"),
        "authorization": {
            "authorized": bool(scope.get("authorized", False)),
            "authorizing_party": scope.get("authorizing_party", "<REQUIRED — signed authorization>"),
            "authorization_ref": scope.get("authorization_ref", "<contract / letter of authorization #>"),
            "engagement_window": scope.get("window", "<start> to <end>"),
            "note": "No operational step proceeds without signed authorization and RoE acknowledgement.",
        },
        "rules_of_engagement": {
            "authorized_scope": scope.get("scope", ["All external-facing assets"]),
            "excluded": scope.get("excluded", ["Production databases", "Safety-critical / OT systems",
                                               "Third-party / shared infrastructure"]),
            "testing_hours": scope.get("hours", "Business hours (Mon-Fri 09:00-18:00)"),
            "permitted_techniques": scope.get("permitted", ["Phishing", "External exploitation", "Lateral movement"]),
            "prohibited_techniques": scope.get("prohibited", ["DoS/DDoS", "Destructive actions", "Social engineering of personal devices"]),
            "data_handling": "Exfil only sample/canary data; encrypt at rest; destroy post-engagement.",
            "emergency_contact": scope.get("contact", "SOC Lead — security@org.com"),
            "deconfliction": "All C2 IPs/domains registered with the SOC prior to start; stop-work signal defined.",
        },
        "opsec_plan": {
            "infrastructure": "Dedicated redirectors fronting C2; per-campaign domains; categorized & aged.",
            "rotation": "Rotate infra on suspected detection; segregate phishing vs. C2 infra.",
            "edr_assumption": "Assume modern EDR/XDR; prefer in-memory; record telemetry generated for debrief.",
            "attribution_control": "No reuse of infra across clients; sanitized user-agents and beacon jitter.",
        },
        "kill_chain_plan": KILL_CHAIN_PHASES,
        "success_criteria": scope.get("success_criteria", [
            "Obtain Domain Admin / Global Admin equivalent",
            "Access designated 'crown jewel' data store",
            "Maintain persistence 48+ hours",
            "Demonstrate exfil path to authorized C2",
        ]),
        "attack_log_schema": ["timestamp", "operator", "source_host", "target",
                              "technique", "attack_id", "expected_telemetry", "outcome"],
        "reporting": {
            "daily_sitrep": True,
            "final_report_deadline": "5 business days post-engagement",
            "debrief_session": "Purple-team debrief within 2 weeks; map every action to a detection opportunity.",
        },
    }
    return plan


def to_markdown(plan: dict) -> str:
    out = [f"# {plan['engagement_name']}",
           f"**Target:** {plan['target']}  |  **Generated:** {plan['generated']}", ""]
    auth = plan["authorization"]
    out += ["## Authorization",
            f"- Authorized: **{auth['authorized']}**",
            f"- Authorizing party: {auth['authorizing_party']}",
            f"- Reference: {auth['authorization_ref']}",
            f"- Window: {auth['engagement_window']}",
            f"- _{auth['note']}_", ""]
    roe = plan["rules_of_engagement"]
    out += ["## Rules of Engagement",
            f"- **In scope:** {', '.join(roe['authorized_scope'])}",
            f"- **Excluded:** {', '.join(roe['excluded'])}",
            f"- **Hours:** {roe['testing_hours']}",
            f"- **Prohibited:** {', '.join(roe['prohibited_techniques'])}",
            f"- **Deconfliction:** {roe['deconfliction']}",
            f"- **Emergency contact:** {roe['emergency_contact']}", ""]
    out += ["## ATT&CK-Aligned Plan"]
    for ph in plan["kill_chain_plan"]:
        out.append(f"### {ph['phase']}  ·  _{ph['attack_tactic']}_")
        out.append(f"- Techniques: {', '.join(ph['techniques'])}")
        out.append(f"- Tooling: {', '.join(ph['tools'])}")
        out.append("")
    out += ["## Success Criteria"] + [f"- {c}" for c in plan["success_criteria"]] + [""]
    out += ["## Attack Log Schema (for purple-team debrief)",
            "| " + " | ".join(plan["attack_log_schema"]) + " |",
            "|" + "|".join(["---"] * len(plan["attack_log_schema"])) + "|", ""]
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description="Red Team Engagement Planner (ATT&CK-aligned)",
                                     epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill")
    parser.add_argument("--scope", "-s", help="Scope JSON file")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--format", "-f", choices=["json", "markdown"], default="json")
    args = parser.parse_args()

    scope = {}
    if args.scope:
        with open(args.scope) as f:
            scope = json.load(f)

    plan = generate_plan(scope)
    if not plan["authorization"]["authorized"]:
        logger.warning("Plan generated as a TEMPLATE — 'authorized' is false. "
                       "Do not execute until signed authorization is in place.")

    output = to_markdown(plan) if args.format == "markdown" else json.dumps(plan, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        logger.info("Plan saved to %s", args.output)
    else:
        print(output)


if __name__ == "__main__":
    main()
