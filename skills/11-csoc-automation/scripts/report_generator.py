#!/usr/bin/env python3
"""
SOC Shift Report Generator
Generates structured shift handover reports for Security Operations Centers.
Reads alert data from JSON files and produces Markdown or JSON reports.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SHIFT_WINDOWS = {
    "day":     ("06:00", "14:00"),
    "evening": ("14:00", "22:00"),
    "night":   ("22:00", "06:00"),
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class ShiftReportGenerator:
    """Generate SOC shift handover reports from alert data."""

    def __init__(self, shift: str, date: str, analyst: str = "SOC Analyst",
                 alerts_file: Optional[str] = None):
        self.shift = shift.lower()
        self.date = date
        self.analyst = analyst
        self.alerts: List[Dict] = []
        self.metrics: Dict[str, Any] = {}
        self.open_incidents: List[Dict] = []
        self.escalations: List[Dict] = []
        self.actions_taken: List[str] = []

        if alerts_file:
            self._load_alerts(alerts_file)

    def _load_alerts(self, path: str) -> None:
        """Load alerts from a JSON file."""
        try:
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, list):
                self.alerts = data
            elif isinstance(data, dict):
                self.alerts = data.get("alerts", data.get("data", []))
            logger.info("Loaded %d alerts from %s", len(self.alerts), path)
        except (IOError, json.JSONDecodeError) as e:
            logger.error("Failed to load alerts: %s", e)

    def add_alert(self, alert: Dict) -> None:
        self.alerts.append(alert)

    def add_open_incident(self, incident: Dict) -> None:
        self.open_incidents.append(incident)

    def add_escalation(self, escalation: Dict) -> None:
        self.escalations.append(escalation)

    def add_action(self, action: str) -> None:
        self.actions_taken.append(action)

    def compute_metrics(self) -> Dict[str, Any]:
        """Compute summary statistics from loaded alerts."""
        total = len(self.alerts)
        by_severity: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        mttr_values: List[float] = []

        for alert in self.alerts:
            sev = alert.get("severity", "UNKNOWN").upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1

            status = alert.get("status", "open").lower()
            by_status[status] = by_status.get(status, 0) + 1

            cat = alert.get("category", alert.get("type", "unknown"))
            by_category[cat] = by_category.get(cat, 0) + 1

            # MTTR: if alert has created_at and resolved_at timestamps
            if "created_at" in alert and "resolved_at" in alert:
                try:
                    created = datetime.fromisoformat(alert["created_at"])
                    resolved = datetime.fromisoformat(alert["resolved_at"])
                    mttr_values.append((resolved - created).total_seconds() / 60)
                except (ValueError, TypeError):
                    pass

        closed = by_status.get("closed", 0) + by_status.get("resolved", 0)
        self.metrics = {
            "total_alerts": total,
            "by_severity": by_severity,
            "by_status": by_status,
            "by_category": by_category,
            "closed_in_shift": closed,
            "open_at_eod": total - closed,
            "mttr_minutes": round(sum(mttr_values) / len(mttr_values), 1) if mttr_values else None,
            "escalations": len(self.escalations),
            "open_incidents": len(self.open_incidents),
        }
        return self.metrics

    def generate_markdown(self) -> str:
        """Generate a Markdown shift handover report."""
        self.compute_metrics()
        shift_start, shift_end = SHIFT_WINDOWS.get(self.shift, ("??:??", "??:??"))
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines = [
            f"# SOC Shift Handover Report",
            f"",
            f"| Field      | Value |",
            f"|------------|-------|",
            f"| Date       | {self.date} |",
            f"| Shift      | {self.shift.capitalize()} ({shift_start}–{shift_end}) |",
            f"| Analyst    | {self.analyst} |",
            f"| Generated  | {now} |",
            f"",
            f"---",
            f"",
            f"## Alert Summary",
            f"",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Total alerts received | {self.metrics.get('total_alerts', 0)} |",
            f"| Closed/Resolved | {self.metrics.get('closed_in_shift', 0)} |",
            f"| Open at end of shift | {self.metrics.get('open_at_eod', 0)} |",
            f"| Escalations | {self.metrics.get('escalations', 0)} |",
            f"| Open incidents | {self.metrics.get('open_incidents', 0)} |",
        ]

        mttr = self.metrics.get("mttr_minutes")
        if mttr is not None:
            lines.append(f"| MTTR (avg) | {mttr} minutes |")

        lines += ["", "### By Severity", ""]
        by_sev = self.metrics.get("by_severity", {})
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in SEVERITY_ORDER:
            count = by_sev.get(sev, 0)
            if count:
                lines.append(f"| {sev} | {count} |")

        by_cat = self.metrics.get("by_category", {})
        if by_cat:
            lines += ["", "### By Category", ""]
            lines.append("| Category | Count |")
            lines.append("|----------|-------|")
            for cat, count in sorted(by_cat.items(), key=lambda x: -x[1])[:10]:
                lines.append(f"| {cat} | {count} |")

        lines += ["", "---", "", "## Open Incidents (Handover Required)", ""]
        if self.open_incidents:
            lines.append("| ID | Title | Severity | Owner | Status |")
            lines.append("|----|-------|----------|-------|--------|")
            for inc in self.open_incidents:
                lines.append(
                    f"| {inc.get('id', 'N/A')} | {inc.get('title', 'N/A')} | "
                    f"{inc.get('severity', 'N/A')} | {inc.get('owner', 'Unassigned')} | "
                    f"{inc.get('status', 'open')} |"
                )
        else:
            lines.append("_No open incidents to hand over._")

        lines += ["", "---", "", "## Escalations This Shift", ""]
        if self.escalations:
            for esc in self.escalations:
                lines.append(f"- **{esc.get('time', '??:??')}** — {esc.get('description', 'N/A')}")
                if esc.get("escalated_to"):
                    lines.append(f"  - Escalated to: {esc['escalated_to']}")
                if esc.get("outcome"):
                    lines.append(f"  - Outcome: {esc['outcome']}")
        else:
            lines.append("_No escalations during this shift._")

        lines += ["", "---", "", "## Actions Taken", ""]
        if self.actions_taken:
            for action in self.actions_taken:
                lines.append(f"- {action}")
        else:
            lines.append("_No significant actions recorded._")

        lines += [
            "",
            "---",
            "",
            "## Recommendations for Incoming Shift",
            "",
            "> Fill this section with watch items, pending investigations, and priorities.",
            "",
            "- [ ] Review open incidents above and assign owners",
            "- [ ] Check threat intelligence feeds for new IOCs",
            "- [ ] Monitor escalated cases for updates",
            "",
            "---",
            "",
            f"_Report generated by report_generator.py — {now}_",
        ]

        return "\n".join(lines)

    def generate_json(self) -> Dict[str, Any]:
        """Generate a structured JSON report."""
        self.compute_metrics()
        shift_start, shift_end = SHIFT_WINDOWS.get(self.shift, ("??:??", "??:??"))
        return {
            "report_type": "soc_shift_handover",
            "date": self.date,
            "shift": self.shift,
            "shift_window": f"{shift_start}–{shift_end}",
            "analyst": self.analyst,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "metrics": self.metrics,
            "open_incidents": self.open_incidents,
            "escalations": self.escalations,
            "actions_taken": self.actions_taken,
            "top_alert_categories": sorted(
                self.metrics.get("by_category", {}).items(),
                key=lambda x: -x[1]
            )[:5],
        }


def _load_sample_alerts() -> List[Dict]:
    """Return sample alerts for demo/testing purposes."""
    return [
        {"id": "ALT-001", "severity": "HIGH", "category": "brute_force",
         "status": "closed", "title": "SSH brute force from 185.220.101.x",
         "created_at": "2024-01-15T06:05:00", "resolved_at": "2024-01-15T06:35:00"},
        {"id": "ALT-002", "severity": "CRITICAL", "category": "malware",
         "status": "open", "title": "Trojan detected on WORKSTATION-042"},
        {"id": "ALT-003", "severity": "MEDIUM", "category": "phishing",
         "status": "closed", "title": "Phishing email blocked — 3 recipients",
         "created_at": "2024-01-15T07:12:00", "resolved_at": "2024-01-15T07:45:00"},
        {"id": "ALT-004", "severity": "HIGH", "category": "lateral_movement",
         "status": "open", "title": "Suspicious WMI execution detected"},
        {"id": "ALT-005", "severity": "LOW", "category": "policy_violation",
         "status": "closed", "title": "USB device connected to finance workstation",
         "created_at": "2024-01-15T09:00:00", "resolved_at": "2024-01-15T09:15:00"},
    ]


def main():
    parser = argparse.ArgumentParser(
        description="SOC Shift Report Generator",
        epilog=(
            "Examples:\n"
            "  report_generator.py --shift night --date 2024-01-15\n"
            "  report_generator.py --shift day --date 2024-01-15 --alerts alerts.json --output report.md\n"
            "  report_generator.py --shift evening --date 2024-01-15 --format json --output report.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--shift", required=True, choices=["day", "evening", "night"],
                        help="Shift type")
    parser.add_argument("--date", required=True,
                        help="Shift date (YYYY-MM-DD)")
    parser.add_argument("--analyst", default="SOC Analyst",
                        help="Analyst name (default: 'SOC Analyst')")
    parser.add_argument("--alerts", "-a",
                        help="Path to JSON file containing alert data")
    parser.add_argument("--output", "-o",
                        help="Output file path (.md or .json)")
    parser.add_argument("--format", "-f", choices=["markdown", "json"], default="markdown",
                        help="Output format (default: markdown)")
    parser.add_argument("--demo", action="store_true",
                        help="Use sample data to demo the report")
    args = parser.parse_args()

    generator = ShiftReportGenerator(
        shift=args.shift,
        date=args.date,
        analyst=args.analyst,
        alerts_file=args.alerts,
    )

    if args.demo and not generator.alerts:
        generator.alerts = _load_sample_alerts()
        generator.add_open_incident({
            "id": "INC-2024-001",
            "title": "Active malware on WORKSTATION-042",
            "severity": "CRITICAL",
            "owner": "Analyst-B",
            "status": "investigating",
        })
        generator.add_escalation({
            "time": "08:30",
            "description": "Lateral movement detected from WORKSTATION-042 to DC-01",
            "escalated_to": "Incident Commander",
            "outcome": "IR team engaged",
        })
        generator.add_action("Isolated WORKSTATION-042 from network at 08:45")
        generator.add_action("Blocked IP 185.220.101.0/24 at perimeter firewall")

    if args.format == "json" or (args.output and args.output.endswith(".json")):
        content = json.dumps(generator.generate_json(), indent=2)
    else:
        content = generator.generate_markdown()

    if args.output:
        with open(args.output, "w") as f:
            f.write(content)
        logger.info("Report saved to %s", args.output)
    else:
        print(content)


if __name__ == "__main__":
    main()
