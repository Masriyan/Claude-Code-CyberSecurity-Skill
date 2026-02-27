#!/usr/bin/env python3
"""
System Hardening Checker
Validates system configuration against security best practices.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import os
import platform
import re
import subprocess
import sys
import time
from typing import Any, Dict, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class LinuxHardeningChecker:
    """Check Linux system hardening against CIS-style benchmarks."""

    def __init__(self):
        self.findings: List[Dict] = []

    def check_ssh_config(self) -> None:
        config = "/etc/ssh/sshd_config"
        if not os.path.exists(config):
            self.findings.append({"id": "SSH-000", "severity": "INFO", "title": "SSH config not found", "status": "SKIP"})
            return
        with open(config, "r") as f:
            content = f.read()
        checks = [
            ("SSH-001", "HIGH", "Root login disabled", r"PermitRootLogin\s+no"),
            ("SSH-002", "HIGH", "Password auth disabled", r"PasswordAuthentication\s+no"),
            ("SSH-003", "MEDIUM", "X11 forwarding disabled", r"X11Forwarding\s+no"),
            ("SSH-004", "MEDIUM", "Max auth tries limited", r"MaxAuthTries\s+[1-4]"),
            ("SSH-005", "MEDIUM", "SSH protocol version 2", r"Protocol\s+2"),
            ("SSH-006", "LOW", "Login grace time limited", r"LoginGraceTime\s+\d+"),
        ]
        for cid, sev, title, pattern in checks:
            status = "PASS" if re.search(pattern, content) else "FAIL"
            self.findings.append({"id": cid, "severity": sev, "title": title, "status": status})

    def check_firewall(self) -> None:
        for fw_cmd in ["ufw status", "iptables -L -n", "nft list ruleset"]:
            cmd = fw_cmd.split()[0]
            if os.path.exists(f"/usr/sbin/{cmd}") or os.path.exists(f"/sbin/{cmd}"):
                try:
                    result = subprocess.run(fw_cmd.split(), capture_output=True, text=True, timeout=5)
                    active = "inactive" not in result.stdout.lower() and result.stdout.strip()
                    self.findings.append({"id": "FW-001", "severity": "HIGH", "title": f"Firewall active ({cmd})", "status": "PASS" if active else "FAIL"})
                    return
                except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
                    pass
        self.findings.append({"id": "FW-001", "severity": "HIGH", "title": "Firewall status", "status": "SKIP"})

    def check_filesystem(self) -> None:
        suid_count = 0
        for root, dirs, files in os.walk("/usr"):
            for f in files:
                path = os.path.join(root, f)
                try:
                    if os.path.isfile(path) and os.stat(path).st_mode & 0o4000:
                        suid_count += 1
                except (OSError, PermissionError):
                    pass
            if suid_count > 50:
                break
        self.findings.append({"id": "FS-001", "severity": "MEDIUM", "title": f"SUID binaries count: {suid_count}",
                             "status": "PASS" if suid_count < 30 else "WARN"})
        world_writable = os.path.exists("/tmp") and os.stat("/tmp").st_mode & 0o0002
        self.findings.append({"id": "FS-002", "severity": "LOW", "title": "/tmp world-writable check",
                             "status": "INFO" if world_writable else "PASS"})

    def check_services(self) -> None:
        unnecessary = ["telnet", "rsh", "rlogin", "tftp", "vsftpd"]
        for svc in unnecessary:
            try:
                result = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True, timeout=3)
                active = result.stdout.strip() == "active"
                self.findings.append({"id": f"SVC-{svc}", "severity": "MEDIUM",
                                     "title": f"Unnecessary service: {svc}", "status": "FAIL" if active else "PASS"})
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

    def check_audit(self) -> None:
        auditd_running = False
        try:
            result = subprocess.run(["systemctl", "is-active", "auditd"], capture_output=True, text=True, timeout=3)
            auditd_running = result.stdout.strip() == "active"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        self.findings.append({"id": "AUD-001", "severity": "HIGH", "title": "Audit daemon (auditd) running",
                             "status": "PASS" if auditd_running else "FAIL"})

    def run(self) -> Dict[str, Any]:
        logger.info("=" * 50)
        logger.info("Linux Hardening Check")
        logger.info("=" * 50)
        self.check_ssh_config()
        self.check_firewall()
        self.check_filesystem()
        self.check_services()
        self.check_audit()
        passed = sum(1 for f in self.findings if f["status"] == "PASS")
        failed = sum(1 for f in self.findings if f["status"] == "FAIL")
        return {
            "os": "Linux", "hostname": platform.node(),
            "total_checks": len(self.findings), "passed": passed, "failed": failed,
            "score_pct": round(passed / max(len(self.findings), 1) * 100, 1),
            "findings": self.findings,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }


def main():
    parser = argparse.ArgumentParser(description="System Hardening Checker",
                                     epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill")
    parser.add_argument("--os", choices=["ubuntu", "centos", "windows", "auto"], default="auto")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    checker = LinuxHardeningChecker()
    results = checker.run()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("Report saved to %s", args.output)
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
