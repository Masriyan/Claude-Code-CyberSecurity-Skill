#!/usr/bin/env python3
"""
Log Anomaly Detector
Detects statistical anomalies in parsed log data using baseline comparison,
frequency analysis, and heuristic pattern matching.

Works on JSON output from log_parser.py or any JSON log array.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import math
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------

def mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def stdev(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = mean(values)
    variance = sum((x - m) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)


def zscore(value: float, mu: float, sigma: float) -> float:
    return (value - mu) / sigma if sigma > 0 else 0.0


# ---------------------------------------------------------------------------
# Anomaly Detector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """Detect anomalies in log event streams using statistical and heuristic methods."""

    SEVERITY_MAP = {
        "brute_force":          "HIGH",
        "rare_source":          "MEDIUM",
        "high_frequency":       "HIGH",
        "after_hours_access":   "MEDIUM",
        "privilege_escalation": "HIGH",
        "lateral_movement":     "HIGH",
        "data_exfiltration":    "CRITICAL",
        "new_user_agent":       "LOW",
        "spike":                "MEDIUM",
    }

    def __init__(self, threshold_zscore: float = 3.0, brute_force_threshold: int = 10,
                 spike_multiplier: float = 3.0):
        self.threshold_zscore = threshold_zscore
        self.brute_force_threshold = brute_force_threshold
        self.spike_multiplier = spike_multiplier
        self.anomalies: List[Dict] = []

    def add_anomaly(self, anomaly_type: str, description: str,
                    evidence: Any, source: str = "") -> None:
        severity = self.SEVERITY_MAP.get(anomaly_type, "MEDIUM")
        self.anomalies.append({
            "type": anomaly_type,
            "severity": severity,
            "description": description,
            "source": source,
            "evidence": evidence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        logger.warning("[%s] %s — %s", severity, anomaly_type, description)

    # -------------------------------------------------------------------------
    # Brute-force detection
    # -------------------------------------------------------------------------
    def detect_brute_force(self, events: List[Dict],
                            user_field: str = "user",
                            status_field: str = "status",
                            source_field: str = "src_ip",
                            fail_values: Optional[List[str]] = None) -> None:
        """Flag sources with many failed authentication attempts."""
        if fail_values is None:
            fail_values = ["failure", "failed", "invalid", "error", "401", "403"]

        fail_by_source: Counter = Counter()
        fail_by_user: Counter = Counter()

        for ev in events:
            status = str(ev.get(status_field, "")).lower()
            if any(v in status for v in fail_values):
                src = ev.get(source_field, ev.get("src", "unknown"))
                user = ev.get(user_field, "unknown")
                fail_by_source[src] += 1
                fail_by_user[user] += 1

        for src, count in fail_by_source.items():
            if count >= self.brute_force_threshold:
                self.add_anomaly(
                    "brute_force",
                    f"Brute-force detected: {count} failures from {src}",
                    {"source_ip": src, "failure_count": count},
                    source=src,
                )

        for user, count in fail_by_user.items():
            if count >= self.brute_force_threshold:
                self.add_anomaly(
                    "brute_force",
                    f"Credential stuffing suspected: {count} failures for user '{user}'",
                    {"user": user, "failure_count": count},
                    source=user,
                )

    # -------------------------------------------------------------------------
    # Frequency spike detection
    # -------------------------------------------------------------------------
    def detect_frequency_spikes(self, events: List[Dict],
                                 time_field: str = "timestamp",
                                 window_minutes: int = 5) -> None:
        """Detect time-windowed event spikes compared to rolling average."""
        buckets: Dict[int, int] = defaultdict(int)

        for ev in events:
            ts_raw = ev.get(time_field, "")
            try:
                if isinstance(ts_raw, (int, float)):
                    epoch = int(ts_raw)
                else:
                    dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                    epoch = int(dt.timestamp())
                bucket = epoch // (window_minutes * 60)
                buckets[bucket] += 1
            except (ValueError, TypeError, OSError):
                continue

        if len(buckets) < 3:
            return

        counts = list(buckets.values())
        mu = mean(counts)
        sd = stdev(counts)

        for bucket, count in buckets.items():
            z = zscore(count, mu, sd)
            if z > self.threshold_zscore or count > mu * self.spike_multiplier:
                window_start = datetime.fromtimestamp(
                    bucket * window_minutes * 60, tz=timezone.utc
                ).isoformat()
                self.add_anomaly(
                    "spike",
                    f"Event spike: {count} events in {window_minutes}-min window at {window_start} (z={z:.1f})",
                    {"window_start": window_start, "event_count": count, "mean": round(mu, 1), "zscore": round(z, 2)},
                )

    # -------------------------------------------------------------------------
    # After-hours access
    # -------------------------------------------------------------------------
    def detect_after_hours(self, events: List[Dict],
                            time_field: str = "timestamp",
                            business_start: int = 8,
                            business_end: int = 18,
                            user_field: str = "user") -> None:
        """Flag user activity outside business hours."""
        after_hours_users: Counter = Counter()

        for ev in events:
            ts_raw = ev.get(time_field, "")
            user = ev.get(user_field, "unknown")
            try:
                if isinstance(ts_raw, (int, float)):
                    dt = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
                else:
                    dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                hour = dt.hour
                if not (business_start <= hour < business_end):
                    after_hours_users[user] += 1
            except (ValueError, TypeError, OSError):
                continue

        for user, count in after_hours_users.items():
            if count >= 3:
                self.add_anomaly(
                    "after_hours_access",
                    f"After-hours access: user '{user}' has {count} events outside business hours",
                    {"user": user, "event_count": count, "business_hours": f"{business_start}:00–{business_end}:00 UTC"},
                    source=user,
                )

    # -------------------------------------------------------------------------
    # Rare source detection
    # -------------------------------------------------------------------------
    def detect_rare_sources(self, events: List[Dict],
                             source_field: str = "src_ip",
                             rare_threshold: int = 2) -> None:
        """Flag sources that appear very rarely (potential new/external actors)."""
        source_counts: Counter = Counter()
        for ev in events:
            src = ev.get(source_field, ev.get("src", ""))
            if src:
                source_counts[src] += 1

        total_sources = len(source_counts)
        if total_sources < 5:
            return  # Not enough data

        for src, count in source_counts.items():
            if count <= rare_threshold:
                self.add_anomaly(
                    "rare_source",
                    f"Rare source: '{src}' appears only {count} time(s) — may be a new/external actor",
                    {"source": src, "occurrence_count": count},
                    source=src,
                )

    # -------------------------------------------------------------------------
    # Privilege escalation heuristic
    # -------------------------------------------------------------------------
    def detect_privilege_escalation(self, events: List[Dict],
                                    message_field: str = "message") -> None:
        """Detect keywords indicative of privilege escalation attempts."""
        keywords = [
            "sudo", "su -", "runas", "privilege", "elevation",
            "admin", "root", "wheel", "passwd", "shadow",
            "net localgroup administrators", "add-localgroupmember",
            "seimpersonateprivilege", "token impersonation",
        ]

        for ev in events:
            msg = str(ev.get(message_field, ev.get("msg", ev.get("log", "")))).lower()
            matched = [kw for kw in keywords if kw in msg]
            if len(matched) >= 2:
                self.add_anomaly(
                    "privilege_escalation",
                    f"Possible privilege escalation: matched keywords {matched}",
                    {"event": ev, "matched_keywords": matched},
                )

    # -------------------------------------------------------------------------
    # Lateral movement heuristic
    # -------------------------------------------------------------------------
    def detect_lateral_movement(self, events: List[Dict],
                                 dest_field: str = "dst_ip",
                                 user_field: str = "user",
                                 min_unique_dests: int = 5) -> None:
        """Flag users connecting to many distinct destination IPs."""
        user_dests: Dict[str, set] = defaultdict(set)
        for ev in events:
            user = ev.get(user_field, "")
            dest = ev.get(dest_field, ev.get("dst", ""))
            if user and dest:
                user_dests[user].add(dest)

        for user, dests in user_dests.items():
            if len(dests) >= min_unique_dests:
                self.add_anomaly(
                    "lateral_movement",
                    f"Lateral movement suspected: user '{user}' connected to {len(dests)} unique destinations",
                    {"user": user, "destination_count": len(dests), "sample_dests": list(dests)[:10]},
                    source=user,
                )

    # -------------------------------------------------------------------------
    # Baseline comparison
    # -------------------------------------------------------------------------
    def compare_baseline(self, events: List[Dict],
                          baseline: Dict[str, Any],
                          source_field: str = "src_ip") -> None:
        """Compare current event sources against a known baseline."""
        baseline_sources = set(baseline.get("known_sources", []))
        baseline_users = set(baseline.get("known_users", []))
        current_sources: set = set()
        current_users: set = set()

        for ev in events:
            src = ev.get(source_field, ev.get("src", ""))
            user = ev.get("user", "")
            if src:
                current_sources.add(src)
            if user:
                current_users.add(user)

        new_sources = current_sources - baseline_sources
        new_users = current_users - baseline_users

        if new_sources:
            self.add_anomaly(
                "rare_source",
                f"{len(new_sources)} new source IP(s) not in baseline",
                {"new_sources": list(new_sources)[:20]},
            )
        if new_users:
            self.add_anomaly(
                "rare_source",
                f"{len(new_users)} new user(s) not in baseline",
                {"new_users": list(new_users)[:20]},
            )

    def run(self, events: List[Dict], baseline: Optional[Dict] = None) -> List[Dict]:
        """Run all detectors against the event list."""
        logger.info("Analyzing %d events for anomalies...", len(events))

        self.detect_brute_force(events)
        self.detect_frequency_spikes(events)
        self.detect_after_hours(events)
        self.detect_privilege_escalation(events)
        self.detect_lateral_movement(events)

        if len(events) > 50:
            self.detect_rare_sources(events)

        if baseline:
            self.compare_baseline(events, baseline)

        logger.info("Anomaly detection complete: %d anomalies found", len(self.anomalies))
        return self.anomalies


def print_summary(anomalies: List[Dict]) -> None:
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    by_sev: Dict[str, int] = {}
    for a in anomalies:
        sev = a["severity"]
        by_sev[sev] = by_sev.get(sev, 0) + 1

    print(f"\n{'=' * 60}")
    print("Anomaly Detection Results")
    print(f"{'=' * 60}")
    print(f"Total anomalies: {len(anomalies)}")
    for sev in severity_order:
        if by_sev.get(sev):
            print(f"  {sev:<10}: {by_sev[sev]}")
    print()

    for sev in severity_order:
        for a in anomalies:
            if a["severity"] == sev:
                print(f"  [{a['severity']}] {a['type']}")
                print(f"    {a['description']}")
                if a.get("source"):
                    print(f"    Source: {a['source']}")
                print()


def _generate_sample_events() -> List[Dict]:
    """Generate sample events for testing."""
    base_time = int(time.time()) - 3600
    events = []
    # Normal traffic
    for i in range(50):
        events.append({
            "timestamp": datetime.fromtimestamp(base_time + i * 60, tz=timezone.utc).isoformat(),
            "src_ip": f"192.168.1.{(i % 10) + 10}",
            "user": f"user{i % 5}",
            "status": "success",
            "message": "Login successful",
        })
    # Brute-force: many failures from single IP
    for i in range(20):
        events.append({
            "timestamp": datetime.fromtimestamp(base_time + 500 + i * 5, tz=timezone.utc).isoformat(),
            "src_ip": "10.0.0.1",
            "user": "admin",
            "status": "failed",
            "message": "Authentication failure",
        })
    # After-hours access
    events.append({
        "timestamp": datetime.fromtimestamp(base_time + 3000, tz=timezone.utc).replace(hour=2).isoformat(),
        "src_ip": "192.168.1.50",
        "user": "user3",
        "status": "success",
        "message": "Login at 02:00 UTC",
    })
    # Privilege escalation keywords
    events.append({
        "timestamp": datetime.fromtimestamp(base_time + 3100, tz=timezone.utc).isoformat(),
        "src_ip": "192.168.1.10",
        "user": "user1",
        "status": "success",
        "message": "sudo su - root: privilege elevation granted",
    })
    return events


def main():
    parser = argparse.ArgumentParser(
        description="Log Anomaly Detector — statistical and heuristic analysis",
        epilog=(
            "Examples:\n"
            "  anomaly_detector.py --logs parsed.json\n"
            "  anomaly_detector.py --logs parsed.json --baseline baseline.json --output anomalies.json\n"
            "  anomaly_detector.py --demo"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--logs", "-l", help="JSON log file to analyze")
    parser.add_argument("--baseline", "-b", help="JSON baseline file (known sources/users)")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--zscore", type=float, default=3.0,
                        help="Z-score threshold for spike detection (default: 3.0)")
    parser.add_argument("--brute-threshold", type=int, default=10,
                        help="Failure count threshold for brute-force (default: 10)")
    parser.add_argument("--demo", action="store_true",
                        help="Run with sample data to demonstrate detection")
    args = parser.parse_args()

    if not args.logs and not args.demo:
        parser.print_help()
        sys.exit(1)

    events: List[Dict] = []
    if args.demo:
        events = _generate_sample_events()
        logger.info("Using %d sample events for demo", len(events))
    elif args.logs:
        try:
            with open(args.logs) as f:
                data = json.load(f)
            events = data if isinstance(data, list) else data.get("events", data.get("logs", []))
        except (IOError, json.JSONDecodeError) as e:
            logger.error("Failed to load logs: %s", e)
            sys.exit(1)

    baseline: Optional[Dict] = None
    if args.baseline:
        try:
            with open(args.baseline) as f:
                baseline = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            logger.warning("Failed to load baseline: %s — continuing without it", e)

    detector = AnomalyDetector(
        threshold_zscore=args.zscore,
        brute_force_threshold=args.brute_threshold,
    )
    anomalies = detector.run(events, baseline=baseline)

    print_summary(anomalies)

    if args.output:
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_events_analyzed": len(events),
            "total_anomalies": len(anomalies),
            "anomalies": anomalies,
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        logger.info("Results saved to %s", args.output)


if __name__ == "__main__":
    main()
