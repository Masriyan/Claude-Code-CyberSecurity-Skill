#!/usr/bin/env python3
"""
Forensic Timeline Builder
Creates chronological timelines from multiple log sources.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import csv
import html
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Common log timestamp patterns
TIMESTAMP_PATTERNS = [
    # ISO 8601
    (re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"), "%Y-%m-%dT%H:%M:%S"),
    # Common syslog
    (re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
    # Apache/Nginx
    (re.compile(r"\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]"), "%d/%b/%Y:%H:%M:%S %z"),
    # Windows Event Log
    (re.compile(r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\s+(?:AM|PM))"), "%m/%d/%Y %I:%M:%S %p"),
    # Generic datetime
    (re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"), "%Y-%m-%d %H:%M:%S"),
    # Epoch seconds
    (re.compile(r"\b(\d{10})\b"), "epoch"),
]


class TimelineBuilder:
    """Build forensic timelines from multiple log sources."""

    def __init__(self):
        self.events: List[Dict[str, Any]] = []

    def parse_log_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Parse a log file and extract timestamped events."""
        logger.info("[Parse] Reading: %s", filepath)
        events = []
        filename = os.path.basename(filepath)

        try:
            with open(filepath, "r", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    timestamp = self._extract_timestamp(line)
                    if timestamp:
                        severity = self._classify_severity(line)
                        events.append({
                            "timestamp": timestamp,
                            "source": filename,
                            "line_number": line_num,
                            "event": line[:500],
                            "severity": severity,
                        })
        except Exception as e:
            logger.error("[Parse] Error reading %s: %s", filepath, str(e))

        logger.info("[Parse] Extracted %d events from %s", len(events), filename)
        return events

    def _extract_timestamp(self, line: str) -> Optional[str]:
        """Extract timestamp from a log line."""
        for pattern, fmt in TIMESTAMP_PATTERNS:
            match = pattern.search(line)
            if match:
                ts_str = match.group(1)
                try:
                    if fmt == "epoch":
                        dt = datetime.fromtimestamp(int(ts_str), tz=timezone.utc)
                    else:
                        # Handle timezone-aware timestamps
                        ts_clean = re.sub(r"[Z]$", "+00:00", ts_str)
                        try:
                            dt = datetime.fromisoformat(ts_clean)
                        except (ValueError, AttributeError):
                            dt = datetime.strptime(ts_str.split(".")[0], fmt.split(".")[0])
                            # Yearless formats (e.g. syslog) default to 1900; assume
                            # the current year so events sort correctly.
                            if "%Y" not in fmt and "%y" not in fmt:
                                dt = dt.replace(year=datetime.now(timezone.utc).year)
                    # Normalize tz-aware timestamps to UTC so the trailing 'Z' is honest.
                    if dt.tzinfo is not None:
                        dt = dt.astimezone(timezone.utc)
                    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                except (ValueError, OSError):
                    continue
        return None

    def _classify_severity(self, line: str) -> str:
        """Classify event severity based on content."""
        line_lower = line.lower()
        if any(w in line_lower for w in ["critical", "emergency", "fatal", "panic"]):
            return "CRITICAL"
        if any(w in line_lower for w in ["error", "fail", "denied", "blocked", "violation"]):
            return "HIGH"
        if any(w in line_lower for w in ["warn", "alert", "suspicious", "unusual"]):
            return "MEDIUM"
        if any(w in line_lower for w in ["notice", "info", "success", "accepted"]):
            return "LOW"
        return "INFO"

    def process_directory(self, directory: str) -> None:
        """Process all log files in a directory."""
        logger.info("[Timeline] Processing directory: %s", directory)
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                if os.path.getsize(filepath) > 100 * 1024 * 1024:  # Skip >100MB
                    logger.warning("[Skip] File too large: %s", filepath)
                    continue
                events = self.parse_log_file(filepath)
                self.events.extend(events)

    def build_timeline(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Build a chronological timeline from all collected events."""
        # Sort by timestamp
        self.events.sort(key=lambda e: e.get("timestamp", ""))

        # Filter by time range
        if start_time or end_time:
            filtered = []
            for event in self.events:
                ts = event.get("timestamp", "")
                if start_time and ts < start_time:
                    continue
                if end_time and ts > end_time:
                    continue
                filtered.append(event)
            self.events = filtered

        logger.info("[Timeline] Total events: %d", len(self.events))
        return self.events

    def export_csv(self, filepath: str) -> None:
        """Export timeline to CSV."""
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=["timestamp", "severity", "source", "line_number", "event"]
            )
            writer.writeheader()
            writer.writerows(self.events)
        logger.info("[Export] CSV saved to %s", filepath)

    def export_json(self, filepath: str) -> None:
        """Export timeline to JSON."""
        with open(filepath, "w") as f:
            json.dump({
                "total_events": len(self.events),
                "sources": list(set(e["source"] for e in self.events)),
                "time_range": {
                    "start": self.events[0]["timestamp"] if self.events else None,
                    "end": self.events[-1]["timestamp"] if self.events else None,
                },
                "events": self.events,
                "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }, f, indent=2)
        logger.info("[Export] JSON saved to %s", filepath)

    def export_html(self, filepath: str) -> None:
        """Export timeline as HTML report."""
        severity_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
            "INFO": "#6c757d",
        }

        rows = ""
        for event in self.events:
            color = severity_colors.get(event["severity"], "#6c757d")
            # Escape all log-derived fields: raw log content is attacker-influenced
            # and would otherwise allow stored XSS / log injection in the report.
            ts = html.escape(str(event["timestamp"]))
            sev = html.escape(str(event["severity"]))
            src = html.escape(str(event["source"]))
            evt = html.escape(str(event["event"])[:200])
            rows += f"""
            <tr>
                <td>{ts}</td>
                <td><span style="color:{color};font-weight:bold">{sev}</span></td>
                <td>{src}</td>
                <td><code>{evt}</code></td>
            </tr>"""

        html_doc = f"""<!DOCTYPE html>
<html><head><title>Forensic Timeline</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
h1 {{ color: #00d4ff; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
th {{ background: #16213e; color: #00d4ff; }}
tr:nth-child(even) {{ background: #0f3460; }}
code {{ background: #111; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }}
</style></head>
<body>
<h1>🔍 Forensic Timeline Report</h1>
<p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
<p>Total Events: {len(self.events)}</p>
<table><thead><tr>
<th>Timestamp</th><th>Severity</th><th>Source</th><th>Event</th>
</tr></thead><tbody>{rows}</tbody></table>
</body></html>"""

        with open(filepath, "w") as f:
            f.write(html_doc)
        logger.info("[Export] HTML saved to %s", filepath)


def _run_demo() -> int:
    """Offline self-test: parse mixed-format log lines, classify, and order them."""
    b = TimelineBuilder()
    lines = [
        "2026-01-02T10:00:05Z CRITICAL ransomware note dropped",
        "2026-01-02 09:59:00 user login accepted",
        "Jan  2 09:58:00 sshd: Failed password for root",
        "<script>alert(1)</script> error denied at 2026-01-01T00:00:00Z",
    ]
    for ln in lines:
        ts = b._extract_timestamp(ln)
        if ts:
            b.events.append({"timestamp": ts, "source": "demo", "line_number": 1,
                             "event": ln, "severity": b._classify_severity(ln)})
    b.build_timeline()
    sev = {e["event"][:10]: e["severity"] for e in b.events}
    checks = [
        ("≥3 timestamps parsed", len(b.events) >= 3),
        ("chronologically sorted", [e["timestamp"] for e in b.events] == sorted(e["timestamp"] for e in b.events)),
        ("critical classified", any(e["severity"] == "CRITICAL" for e in b.events)),
        ("severity for failed password is HIGH", any(e["severity"] == "HIGH" for e in b.events)),
    ]
    # HTML export must escape attacker-controlled log content.
    import tempfile
    with tempfile.NamedTemporaryFile("r+", suffix=".html", delete=False) as fh:
        path = fh.name
    try:
        b.export_html(path)
        with open(path, encoding="utf-8") as fh:
            htmltext = fh.read()
    finally:
        os.unlink(path)
    checks.append(("HTML escapes injected markup", "<script>alert(1)</script>" not in htmltext
                   and "&lt;script&gt;" in htmltext))
    ok = all(p for _, p in checks)
    for label, p in checks:
        print(f"  [{'OK' if p else 'FAIL'}] {label}")
    print("[+] demo passed" if ok else "[!] demo FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(
        description="Forensic Timeline Builder",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--logs", "-l", help="Log file or directory")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--format", "-f", choices=["csv", "json", "html"], default="csv")
    parser.add_argument("--start", help="Start time filter (YYYY-MM-DD or ISO 8601)")
    parser.add_argument("--end", help="End time filter (YYYY-MM-DD or ISO 8601)")
    parser.add_argument("--demo", action="store_true", help="Run an offline self-test and exit")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.demo:
        sys.exit(_run_demo())
    if not args.logs or not args.output:
        parser.error("--logs and --output are required (or use --demo)")

    builder = TimelineBuilder()

    if os.path.isdir(args.logs):
        builder.process_directory(args.logs)
    elif os.path.isfile(args.logs):
        builder.events = builder.parse_log_file(args.logs)
    else:
        logger.error("Path not found: %s", args.logs)
        sys.exit(1)

    builder.build_timeline(start_time=args.start, end_time=args.end)

    if args.format == "csv":
        builder.export_csv(args.output)
    elif args.format == "json":
        builder.export_json(args.output)
    elif args.format == "html":
        builder.export_html(args.output)


if __name__ == "__main__":
    main()
