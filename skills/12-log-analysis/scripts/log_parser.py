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
            else:
                events = self._parse_raw_logs(f, filepath)

        # Classify security events
        for event in events:
            event["security_category"] = self._classify_event(event.get("message", ""))

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


def main():
    parser = argparse.ArgumentParser(
        description="Security Log Parser",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--input", "-i", required=True, help="Log file to parse")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--format", "-f", choices=["auto", "json", "syslog", "auth_log", "apache_access", "nginx_access", "raw"], default="auto")
    parser.add_argument("--summary", action="store_true", help="Output summary only")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

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
