#!/usr/bin/env python3
"""
Detection Validator — scores a purple-team adversary-emulation results plan.

Reads a list of executed ATT&CK techniques with their detection outcomes and
computes per-tactic and overall coverage, detection/prevention rates, MTTD, a
prioritized gap list, and an ATT&CK Navigator layer. Optionally diffs against a
prior engagement to report coverage drift.

Standard library only; `pyyaml` is optional (only to load YAML plans).
It validates the results you record — it does not execute any technique.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import sys
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Coverage ladder: higher is better. "none" = no telemetry at all.
OUTCOME_RANK = {"none": 0, "telemetry": 1, "detection": 2, "prevention": 3}

# ATT&CK Navigator score per outcome (0-100), used to color the heatmap.
OUTCOME_SCORE = {"none": 0, "telemetry": 33, "detection": 66, "prevention": 100}
OUTCOME_COLOR = {
    "none": "#e60d0d", "telemetry": "#e8b000",
    "detection": "#5aa469", "prevention": "#1f6f3d",
}

SAMPLE_PLAN: List[Dict[str, Any]] = [
    {"technique_id": "T1566.001", "technique": "Spearphishing Attachment",
     "tactic": "Initial Access", "executed": True, "data_source": "Email Gateway",
     "outcome": "detection", "time_to_detect_seconds": 95},
    {"technique_id": "T1059.001", "technique": "PowerShell",
     "tactic": "Execution", "executed": True, "data_source": "Script Block Logging",
     "outcome": "detection", "time_to_detect_seconds": 210},
    {"technique_id": "T1558.003", "technique": "Kerberoasting",
     "tactic": "Credential Access", "executed": True, "data_source": "Security 4769",
     "outcome": "detection", "time_to_detect_seconds": 252},
    {"technique_id": "T1070.001", "technique": "Clear Windows Event Logs",
     "tactic": "Defense Evasion", "executed": True, "data_source": "Security 1102",
     "outcome": "telemetry"},
    {"technique_id": "T1021.001", "technique": "Remote Desktop Protocol",
     "tactic": "Lateral Movement", "executed": True, "data_source": "Security 4624 T10",
     "outcome": "telemetry"},
    {"technique_id": "T1486", "technique": "Data Encrypted for Impact",
     "tactic": "Impact", "executed": True, "data_source": "EDR file events",
     "outcome": "prevention", "time_to_detect_seconds": 40},
    {"technique_id": "T1048", "technique": "Exfiltration Over Alternative Protocol",
     "tactic": "Exfiltration", "executed": True, "data_source": "-",
     "outcome": "none"},
]


def load_plan(path: str) -> List[Dict[str, Any]]:
    """Load an emulation results plan from JSON or YAML."""
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    if path.endswith((".yml", ".yaml")):
        if yaml is None:
            raise RuntimeError("pyyaml not installed — install it or use a JSON plan")
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    # Accept either a bare list or an object with a "tests"/"techniques" key.
    if isinstance(data, dict):
        for key in ("tests", "techniques", "results", "plan"):
            if key in data:
                data = data[key]
                break
    if not isinstance(data, list):
        raise ValueError("plan must be a list of technique result entries")
    return data


def _normalize_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    outcome = str(entry.get("outcome", "none")).lower().strip()
    if outcome not in OUTCOME_RANK:
        logger.warning("Unknown outcome %r for %s — treating as 'none'",
                       outcome, entry.get("technique_id", "?"))
        outcome = "none"
    return {
        "technique_id": entry.get("technique_id", "?"),
        "technique": entry.get("technique", ""),
        "tactic": entry.get("tactic", "Unknown"),
        "executed": bool(entry.get("executed", True)),
        "data_source": entry.get("data_source", "-"),
        "outcome": outcome,
        "ttd": entry.get("time_to_detect_seconds"),
    }


class DetectionValidator:
    """Scores coverage and gaps from a normalized results plan."""

    def __init__(self, plan: List[Dict[str, Any]]) -> None:
        self.entries = [_normalize_entry(e) for e in plan]

    def score(self) -> Dict[str, Any]:
        executed = [e for e in self.entries if e["executed"]]
        total = len(executed)
        detected = [e for e in executed if OUTCOME_RANK[e["outcome"]] >= OUTCOME_RANK["detection"]]
        prevented = [e for e in executed if e["outcome"] == "prevention"]
        ttds = [e["ttd"] for e in detected if isinstance(e["ttd"], (int, float))]

        by_tactic: Dict[str, Dict[str, int]] = {}
        for e in executed:
            bucket = by_tactic.setdefault(
                e["tactic"], {"total": 0, "detected": 0, "prevented": 0})
            bucket["total"] += 1
            if OUTCOME_RANK[e["outcome"]] >= OUTCOME_RANK["detection"]:
                bucket["detected"] += 1
            if e["outcome"] == "prevention":
                bucket["prevented"] += 1

        gaps = self._gaps(executed)
        return {
            "executed": total,
            "detected": len(detected),
            "prevented": len(prevented),
            "detection_rate": round(100 * len(detected) / total, 1) if total else 0.0,
            "prevention_rate": round(100 * len(prevented) / total, 1) if total else 0.0,
            "mttd_seconds": round(sum(ttds) / len(ttds), 1) if ttds else None,
            "slowest_detection": max(
                (e for e in detected if isinstance(e["ttd"], (int, float))),
                key=lambda e: e["ttd"], default=None),
            "by_tactic": by_tactic,
            "gaps": gaps,
        }

    def _gaps(self, executed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank gaps: no telemetry (High) before detect-only (Med)."""
        gaps: List[Dict[str, Any]] = []
        for e in executed:
            if e["outcome"] == "none":
                gaps.append({"priority": "High", "technique_id": e["technique_id"],
                             "technique": e["technique"], "tactic": e["tactic"],
                             "issue": "No telemetry — onboard a data source",
                             "handoff": "Skill 15 / Skill 12"})
            elif e["outcome"] == "telemetry":
                gaps.append({"priority": "High", "technique_id": e["technique_id"],
                             "technique": e["technique"], "tactic": e["tactic"],
                             "issue": "Telemetry exists but no detection fires — write a rule",
                             "handoff": "Skill 12 (Sigma)"})
            elif e["outcome"] == "detection":
                gaps.append({"priority": "Medium", "technique_id": e["technique_id"],
                             "technique": e["technique"], "tactic": e["tactic"],
                             "issue": "Detect-only — consider a prevention control",
                             "handoff": "Skill 15"})
        order = {"High": 0, "Medium": 1, "Low": 2}
        return sorted(gaps, key=lambda g: order[g["priority"]])

    def navigator_layer(self, name: str = "Purple Team Coverage") -> Dict[str, Any]:
        """Build an ATT&CK Navigator (v4.5) layer colored by outcome."""
        techniques = [{
            "techniqueID": e["technique_id"],
            "score": OUTCOME_SCORE[e["outcome"]],
            "color": OUTCOME_COLOR[e["outcome"]],
            "comment": f"{e['outcome']} via {e['data_source']}",
            "enabled": True,
        } for e in self.entries if e["executed"]]
        return {
            "name": name,
            "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "Coverage from purple-team emulation results",
            "techniques": techniques,
            "gradient": {"colors": ["#e60d0d", "#e8b000", "#1f6f3d"],
                         "minValue": 0, "maxValue": 100},
            "legendItems": [{"label": k, "color": v} for k, v in OUTCOME_COLOR.items()],
        }

    def render(self, score: Dict[str, Any], baseline: Optional[Dict[str, Any]] = None) -> str:
        lines = ["Purple Team Detection Validation", "=" * 44,
                 f"Techniques executed : {score['executed']}",
                 f"Detected            : {score['detected']} ({score['detection_rate']}%)",
                 f"Prevented           : {score['prevented']} ({score['prevention_rate']}%)"]
        if score["mttd_seconds"] is not None:
            m, s = divmod(int(score["mttd_seconds"]), 60)
            lines.append(f"Mean time-to-detect : {m:02d}:{s:02d}")
        if score["slowest_detection"]:
            sd = score["slowest_detection"]
            lines.append(f"Slowest detection   : {sd['technique_id']} {sd['technique']} "
                         f"({sd['ttd']}s)")
        if baseline is not None:
            delta = score["detected"] - baseline.get("detected", 0)
            lines.append(f"Coverage delta      : {delta:+d} detected vs. baseline")

        lines += ["", "Coverage by tactic", "-" * 44]
        for tactic in sorted(score["by_tactic"]):
            b = score["by_tactic"][tactic]
            lines.append(f"  {tactic:<22} {b['detected']}/{b['total']} detected, "
                         f"{b['prevented']} prevented")

        if score["gaps"]:
            lines += ["", "Prioritized gaps", "-" * 44]
            for g in score["gaps"]:
                lines.append(f"  [{g['priority']:<6}] {g['technique_id']:<10} "
                             f"{g['technique']}: {g['issue']}")
        return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detection Validator — score purple-team emulation coverage.",
        epilog=(
            "Examples:\n"
            "  detection_validator.py --plan results.json\n"
            "  detection_validator.py --plan results.json --navigator layer.json --output report.json\n"
            "  detection_validator.py --plan results.json --baseline prior.json\n"
            "  detection_validator.py --demo"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--plan", "-p", help="Emulation results plan (JSON or YAML)")
    parser.add_argument("--baseline", "-b", help="Prior engagement plan to diff coverage against")
    parser.add_argument("--navigator", help="Write an ATT&CK Navigator layer to this path")
    parser.add_argument("--output", "-o", help="Write the full score report as JSON")
    parser.add_argument("--demo", action="store_true", help="Run against a bundled sample plan")
    args = parser.parse_args()

    if args.demo:
        plan = SAMPLE_PLAN
    elif args.plan:
        try:
            plan = load_plan(args.plan)
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            logger.error("Could not load plan: %s", exc)
            return 1
    else:
        parser.error("provide --plan <file> or --demo")
        return 2  # unreachable; parser.error exits

    validator = DetectionValidator(plan)
    score = validator.score()

    baseline_score = None
    if args.baseline:
        try:
            baseline_score = DetectionValidator(load_plan(args.baseline)).score()
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            logger.warning("Could not load baseline (%s) — skipping delta", exc)

    print(validator.render(score, baseline_score))

    if args.navigator:
        with open(args.navigator, "w", encoding="utf-8") as fh:
            json.dump(validator.navigator_layer(), fh, indent=2)
        logger.info("Navigator layer written to %s", args.navigator)
    if args.output:
        report = {"score": score, "entries": validator.entries}
        if baseline_score is not None:
            report["baseline"] = {"detected": baseline_score["detected"],
                                  "executed": baseline_score["executed"]}
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        logger.info("Report written to %s", args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
