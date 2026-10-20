#!/usr/bin/env python3
"""
Security Log Parser
Parses and normalizes security logs from various sources.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import csv
import json
import logging
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# Common log patterns
LOG_PATTERNS = {
    "syslog": re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*"
        r"(?P<message>.*)"
    ),
    "auth_log": re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*"
        r"(?P<message>.*)"
    ),
    "apache_access": re.compile(
        r"(?P<client_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+"
        r"\[(?P<timestamp>[^\]]+)\]\s+"
        r"\"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>\S+)\"\s+"
        r"(?P<status>\d+)\s+(?P<bytes>\d+|-)"
    ),
    "nginx_access": re.compile(
        r"(?P<client_ip>\S+)\s+-\s+(?P<user>\S+)\s+"
        r"\[(?P<timestamp>[^\]]+)\]\s+"
        r"\"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>\S+)\"\s+"
        r"(?P<status>\d+)\s+(?P<bytes>\d+)"
    ),
}

# Sub-patterns for pulling user/src_ip/status out of an auth_log "message"
# field. anomaly_detector.py's brute-force/after-hours/lateral-movement
# detectors default to exactly these three field names (this module's own
# docstring says "Works on JSON output from log_parser.py"), but the
# syslog/auth_log LOG_PATTERNS above only capture timestamp/hostname/
# process/pid/message -- without this enrichment those detectors silently
# find nothing on real auth_log input, no matter how anomalous it is.
AUTH_LOG_SUBPATTERNS = [
    (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>[0-9a-fA-F.:]+)"), "failed"),
    (re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<src_ip>[0-9a-fA-F.:]+)"), "success"),
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<src_ip>[0-9a-fA-F.:]+)"), "failed"),
]

# Security-relevant event keywords
SECURITY_KEYWORDS = {
    "authentication_success": ["accepted", "session opened", "logged in", "authentication success"],
    "authentication_failure": ["failed", "denied", "invalid", "authentication failure", "wrong password"],
    "account_change": ["useradd", "userdel", "usermod", "password changed", "account created", "account deleted"],
    "privilege_escalation": ["sudo", "su:", "root", "privilege", "elevation"],
    "service_change": ["started", "stopped", "restarted", "enabled", "disabled"],
    "file_access": ["opened", "read", "write", "deleted", "modified", "created"],
    "network": ["connection", "listening", "bound", "accept", "connect"],
}


class LogParser:
    """Security log parsing and normalization engine."""

    def __init__(self, log_format: str = "auto"):
        self.log_format = log_format

    def detect_format(self, line: str) -> str:
        """Auto-detect log format from a sample line."""
        if line.strip().startswith("{"):
            return "json"
        for fmt, pattern in LOG_PATTERNS.items():
            if pattern.match(line):
                return fmt
        return "raw"

    def parse_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Parse a log file into structured events."""
        logger.info("[Parse] Processing: %s", filepath)
        events = []

        with open(filepath, "r", errors="ignore") as f:
            first_line = f.readline().strip()
            if self.log_format == "auto":
                detected = self.detect_format(first_line)
                logger.info("[Parse] Detected format: %s", detected)
            else:
                detected = self.log_format

            f.seek(0)

            if detected == "json":
                events = self._parse_json_logs(f)
            elif detected in LOG_PATTERNS:
                events = self._parse_pattern_logs(f, LOG_PATTERNS[detected], filepath)
                # syslog and auth_log share one regex, so auto-detection reports
                # "syslog" for auth lines too. Enrich both: the subpatterns only
                # add fields when a line actually matches an auth event, so this
                # is safe for ordinary syslog and fixes auto-mode enrichment.
                if detected in ("auth_log", "syslog"):
                    for event in events:
                        self._enrich_auth_log_event(event)
            else:
                events = self._parse_raw_logs(f, filepath)

        # Classify security events. Include the process/daemon name (e.g. sshd,
        # sudo, su) — for syslog that field carries as much signal as the message.
        for event in events:
            text = f"{event.get('process', '')} {event.get('message', '')}"
            event["security_category"] = self._classify_event(text)

        logger.info("[Parse] Extracted %d events", len(events))
        return events

    def _parse_json_logs(self, f) -> List[Dict]:
        """Parse JSON-formatted logs (one JSON per line)."""
        events = []
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                event["_line_number"] = line_num
                events.append(event)
            except json.JSONDecodeError:
                pass
        return events

    def _parse_pattern_logs(self, f, pattern, filepath: str) -> List[Dict]:
        """Parse logs matching a regex pattern."""
        events = []
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            match = pattern.match(line)
            if match:
                event = match.groupdict()
                event["_source_file"] = os.path.basename(filepath)
                event["_line_number"] = line_num
                events.append(event)
        return events

    def _parse_raw_logs(self, f, filepath: str) -> List[Dict]:
        """Parse unstructured logs."""
        events = []
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            events.append({
                "message": line,
                "_source_file": os.path.basename(filepath),
                "_line_number": line_num,
            })
        return events

    def _enrich_auth_log_event(self, event: Dict[str, Any]) -> None:
        """Pull user/src_ip/status out of an auth_log message in place, for
        downstream tools (e.g. anomaly_detector.py) that key off those
        field names rather than re-parsing raw message text themselves."""
        message = event.get("message", "")
        for pattern, status in AUTH_LOG_SUBPATTERNS:
            match = pattern.search(message)
            if match:
                event["user"] = match.group("user")
                event["src_ip"] = match.group("src_ip")
                event["status"] = status
                return

    def _classify_event(self, message: str) -> str:
        """Classify a log event into security categories."""
        msg_lower = message.lower()
        for category, keywords in SECURITY_KEYWORDS.items():
            if any(kw in msg_lower for kw in keywords):
                return category
        return "other"

    def summarize(self, events: List[Dict]) -> Dict[str, Any]:
        """Generate summary statistics from parsed events."""
        categories = {}
        for event in events:
            cat = event.get("security_category", "other")
            categories[cat] = categories.get(cat, 0) + 1

        hosts = set()
        users = set()
        ips = set()
        for event in events:
            if "hostname" in event:
                hosts.add(event["hostname"])
            if "user" in event:
                users.add(event["user"])
            if "client_ip" in event:
                ips.add(event["client_ip"])

        return {
            "total_events": len(events),
            "security_categories": categories,
            "unique_hosts": len(hosts),
            "unique_users": len(users),
            "unique_ips": len(ips),
        }


def _run_demo() -> int:
    """Offline self-test: auto-detect, auth-log enrichment, and classification."""
    import tempfile
    lines = [
        "Jan  2 10:00:00 host sshd[111]: Failed password for invalid user admin from 10.0.0.9 port 22 ssh2",
        "Jan  2 10:00:05 host sshd[112]: Accepted password for alice from 192.168.1.5 port 22 ssh2",
        "Jan  2 10:01:00 host sudo: alice : TTY=pts/0 ; COMMAND=/bin/bash",
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        fh.write("\n".join(lines) + "\n")
        path = fh.name
    try:
        lp = LogParser(log_format="auto")
        events = lp.parse_file(path)
    finally:
        os.unlink(path)
    enriched = [e for e in events if e.get("src_ip")]
    checks = [
        ("all 3 lines parsed", len(events) == 3),
        ("auto-mode enriches auth events", len(enriched) >= 2),
        ("failed login src_ip extracted", any(e.get("src_ip") == "10.0.0.9"
                                              and e.get("status") == "failed" for e in events)),
        ("accepted login user extracted", any(e.get("user") == "alice"
                                              and e.get("status") == "success" for e in events)),
        ("sudo classified as priv-esc", any(e.get("security_category") == "privilege_escalation"
                                            for e in events)),
    ]
    ok = all(p for _, p in checks)
    for label, p in checks:
        print(f"  [{'OK' if p else 'FAIL'}] {label}")
    print("[+] demo passed" if ok else "[!] demo FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(
        description="Security Log Parser",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--input", "-i", help="Log file to parse")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--format", "-f", choices=["auto", "json", "syslog", "auth_log", "apache_access", "nginx_access", "raw"], default="auto")
    parser.add_argument("--summary", action="store_true", help="Output summary only")
    parser.add_argument("--demo", action="store_true", help="Run an offline self-test and exit")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.demo:
        sys.exit(_run_demo())
    if not args.input:
        parser.error("--input/-i is required (or use --demo)")

    log_parser = LogParser(log_format=args.format)
    events = log_parser.parse_file(args.input)

    if args.summary:
        output = log_parser.summarize(events)
    else:
        output = {"total_events": len(events), "events": events}

    output["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    if args.output:
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        logger.info("Results saved to %s", args.output)
    else:
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
