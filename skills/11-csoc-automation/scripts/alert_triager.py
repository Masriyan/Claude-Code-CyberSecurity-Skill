#!/usr/bin/env python3
"""
SOC Alert Triager
Automated alert classification, prioritization, and assignment for CSOC operations.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import sys
import time
from typing import Any, Dict, List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

ALERT_CATEGORIES = {
    "malware": {"keywords": ["malware", "virus", "trojan", "ransomware", "worm", "backdoor"], "base_severity": "HIGH"},
    "intrusion": {"keywords": ["intrusion", "breach", "unauthorized", "exploit", "attack"], "base_severity": "CRITICAL"},
    "phishing": {"keywords": ["phishing", "spearphishing", "social engineering", "credential"], "base_severity": "MEDIUM"},
    "policy_violation": {"keywords": ["policy", "violation", "compliance", "unauthorized access"], "base_severity": "LOW"},
    "reconnaissance": {"keywords": ["scan", "probe", "enumeration", "reconnaissance"], "base_severity": "LOW"},
    "data_exfiltration": {"keywords": ["exfiltration", "data loss", "dlp", "upload", "transfer"], "base_severity": "HIGH"},
    "dos": {"keywords": ["ddos", "dos", "flood", "volumetric", "amplification"], "base_severity": "HIGH"},
    "account_compromise": {"keywords": ["compromised", "account", "credential", "brute force", "login"], "base_severity": "HIGH"},
}

ASSET_CRITICALITY = {
    "critical": 4,  # Domain controllers, databases, key infrastructure
    "high": 3,      # Application servers, email servers
    "medium": 2,    # Workstations, standard servers
    "low": 1,       # Printers, IoT devices, test systems
}

TIER_ASSIGNMENT = {
    "CRITICAL": "Tier 3 / IR Lead",
    "HIGH": "Tier 2 Senior Analyst",
    "MEDIUM": "Tier 1 Analyst",
    "LOW": "Auto-Process / Tier 1",
    "INFO": "Auto-Close",
}


class AlertTriager:
    """Automated SOC alert triage engine."""

    def __init__(self):
        self.processed = 0
        self.results = []

    def classify_alert(self, alert: Dict) -> Dict[str, Any]:
        """Classify and prioritize a single alert."""
        title = alert.get("title", "").lower()
        description = alert.get("description", "").lower()
        combined_text = f"{title} {description}"
        source_severity = alert.get("severity", "MEDIUM").upper()

        # Categorize
        category = "unknown"
        for cat, info in ALERT_CATEGORIES.items():
            if any(kw in combined_text for kw in info["keywords"]):
                category = cat
                break

        # Determine asset criticality
        asset_crit = alert.get("asset_criticality", "medium").lower()
        crit_score = ASSET_CRITICALITY.get(asset_crit, 2)

        # Calculate final severity
        severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        base_score = severity_map.get(source_severity, 2)
        adjusted_score = min(4, base_score + (1 if crit_score >= 3 else 0))
        final_severity = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}.get(adjusted_score, "MEDIUM")

        # Determine false positive likelihood
        fp_indicators = ["test", "scanner", "scheduled", "maintenance", "expected"]
        fp_likelihood = "HIGH" if any(kw in combined_text for kw in fp_indicators) else "LOW"

        # Assign tier
        assigned_tier = TIER_ASSIGNMENT.get(final_severity, "Tier 1 Analyst")

        # Recommended actions
        actions = self._recommend_actions(category, final_severity)

        return {
            "alert_id": alert.get("id", f"ALERT-{self.processed:05d}"),
            "original_title": alert.get("title", "N/A"),
            "category": category,
            "original_severity": source_severity,
            "adjusted_severity": final_severity,
            "asset_criticality": asset_crit,
            "false_positive_likelihood": fp_likelihood,
            "assigned_to": assigned_tier,
            "recommended_actions": actions,
            "sla_minutes": {"CRITICAL": 15, "HIGH": 60, "MEDIUM": 240, "LOW": 480}.get(final_severity, 480),
        }

    def _recommend_actions(self, category: str, severity: str) -> List[str]:
        """Generate recommended triage actions."""
        actions = ["Verify alert source and raw event data"]

        category_actions = {
            "malware": ["Check file hash against VT/malware databases", "Isolate affected endpoint", "Collect memory dump if active"],
            "intrusion": ["Verify authenticity of alert", "Check for lateral movement", "Escalate to IR team immediately"],
            "phishing": ["Analyze email headers and URLs", "Check if user clicked/submitted credentials", "Block sender domain"],
            "data_exfiltration": ["Check data transfer volume and destination", "Verify if endpoint is authorized", "Block outbound connection"],
            "account_compromise": ["Check login source IP and geolocation", "Verify with account owner", "Force password reset if confirmed"],
            "dos": ["Verify traffic patterns", "Engage network team", "Consider upstream mitigation"],
            "reconnaissance": ["Check source IP reputation", "Monitor for follow-up activity", "Add to watchlist"],
        }

        actions.extend(category_actions.get(category, ["Investigate manually"]))

        if severity in ("CRITICAL", "HIGH"):
            actions.append("Document findings in incident tracking system")
            actions.append("Notify shift lead / SOC manager")

        return actions

    def triage_batch(self, alerts: List[Dict]) -> Dict[str, Any]:
        """Triage a batch of alerts."""
        logger.info("=" * 60)
        logger.info("SOC Alert Triage — Processing %d alerts", len(alerts))
        logger.info("=" * 60)

        triaged = []
        for alert in alerts:
            self.processed += 1
            result = self.classify_alert(alert)
            triaged.append(result)
            logger.info(
                "[%s] %s — %s → %s (Assigned: %s)",
                result["alert_id"],
                result["category"],
                result["original_severity"],
                result["adjusted_severity"],
                result["assigned_to"],
            )

        # Summary statistics
        severity_dist = {}
        category_dist = {}
        for t in triaged:
            sev = t["adjusted_severity"]
            cat = t["category"]
            severity_dist[sev] = severity_dist.get(sev, 0) + 1
            category_dist[cat] = category_dist.get(cat, 0) + 1

        return {
            "total_processed": len(triaged),
            "severity_distribution": severity_dist,
            "category_distribution": category_dist,
            "triaged_alerts": triaged,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }


def main():
    parser = argparse.ArgumentParser(
        description="SOC Alert Triager",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--alerts", "-a", required=True, help="JSON file with alerts to triage")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    with open(args.alerts, "r") as f:
        alerts = json.load(f)

    if isinstance(alerts, dict):
        alerts = alerts.get("alerts", [alerts])

    triager = AlertTriager()
    results = triager.triage_batch(alerts)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("Results saved to %s", args.output)
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
