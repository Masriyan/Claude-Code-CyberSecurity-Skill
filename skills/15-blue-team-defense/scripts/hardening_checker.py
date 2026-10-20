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

    SSH_CHECKS = [
        ("SSH-001", "HIGH", "Root login disabled", r"PermitRootLogin\s+(no|prohibit-password)"),
        ("SSH-002", "HIGH", "Password auth disabled", r"PasswordAuthentication\s+no"),
        ("SSH-003", "MEDIUM", "X11 forwarding disabled", r"X11Forwarding\s+no"),
        ("SSH-004", "MEDIUM", "Max auth tries limited", r"MaxAuthTries\s+[1-4]"),
        ("SSH-005", "MEDIUM", "SSH protocol version 2", r"Protocol\s+2"),
        ("SSH-006", "LOW", "Login grace time limited", r"LoginGraceTime\s+\d+"),
        ("SSH-007", "MEDIUM", "Strong ciphers only (no CBC/arcfour)", r"Ciphers\s+(?!.*(cbc|arcfour|3des)).+"),
        ("SSH-008", "MEDIUM", "Modern KEX algorithms set", r"KexAlgorithms\s+.*(curve25519|sntrup|ecdh-sha2)"),
        ("SSH-009", "LOW", "ClientAlive idle timeout set", r"ClientAliveInterval\s+[1-9]\d*"),
    ]

    @classmethod
    def evaluate_ssh_config(cls, content: str) -> List[Dict]:
        """Evaluate sshd_config text, ignoring commented-out directives.

        A commented default like ``#PermitRootLogin no`` does NOT harden the
        server, so comment lines are stripped before matching — otherwise the
        check would report a false PASS on a stock config.
        """
        active = "\n".join(line for line in content.splitlines()
                           if not line.lstrip().startswith("#"))
        findings = []
        for cid, sev, title, pattern in cls.SSH_CHECKS:
            status = "PASS" if re.search(pattern, active) else "FAIL"
            findings.append({"id": cid, "severity": sev, "title": title, "status": status})
        return findings

    def check_ssh_config(self) -> None:
        config = "/etc/ssh/sshd_config"
        if not os.path.exists(config):
            self.findings.append({"id": "SSH-000", "severity": "INFO", "title": "SSH config not found", "status": "SKIP"})
            return
        try:
            with open(config, "r") as f:
                content = f.read()
        except PermissionError:
            self.findings.append({"id": "SSH-000", "severity": "INFO",
                                  "title": "SSH config unreadable (run as root for SSH checks)", "status": "SKIP"})
            return
        self.findings.extend(self.evaluate_ssh_config(content))

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

    def check_sysctl(self) -> None:
        """Validate kernel network/exec hardening sysctls (CIS-aligned)."""
        expected = {
            "SYS-001": ("HIGH", "ASLR fully enabled", "kernel.randomize_va_space", "2"),
            "SYS-002": ("MEDIUM", "IP forwarding disabled", "net.ipv4.ip_forward", "0"),
            "SYS-003": ("MEDIUM", "Reverse-path filtering on", "net.ipv4.conf.all.rp_filter", "1"),
            "SYS-004": ("MEDIUM", "ICMP redirects not accepted", "net.ipv4.conf.all.accept_redirects", "0"),
            "SYS-005": ("MEDIUM", "Source routing disabled", "net.ipv4.conf.all.accept_source_route", "0"),
            "SYS-006": ("LOW", "TCP SYN cookies enabled", "net.ipv4.tcp_syncookies", "1"),
            "SYS-007": ("MEDIUM", "ptrace scope restricted", "kernel.yama.ptrace_scope", "1"),
        }
        for cid, (sev, title, key, want) in expected.items():
            try:
                result = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True, timeout=3)
                val = result.stdout.strip()
                status = "PASS" if val == want else ("FAIL" if val else "SKIP")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                status = "SKIP"
            self.findings.append({"id": cid, "severity": sev, "title": title, "status": status})

    def check_kernel_modules(self) -> None:
        """Flag risky/legacy filesystem & network modules that should be disabled."""
        risky = ["cramfs", "freevxfs", "hfs", "hfsplus", "squashfs", "udf", "usb-storage", "dccp", "sctp"]
        try:
            loaded = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=3).stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            loaded = ""
        for mod in risky:
            present = bool(re.search(rf"^{re.escape(mod)}\b", loaded, re.MULTILINE))
            self.findings.append({"id": f"MOD-{mod}", "severity": "LOW",
                                  "title": f"Legacy/risky module not loaded: {mod}",
                                  "status": "FAIL" if present else "PASS"})

    REMEDIATION = {
        "SSH-001": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd.",
        "SSH-002": "Set 'PasswordAuthentication no' and use key/cert auth.",
        "SSH-007": "Set 'Ciphers' to AEAD/CTR only (e.g. chacha20-poly1305, aes256-gcm).",
        "SSH-008": "Set 'KexAlgorithms' to curve25519-sha256 (or sntrup761x25519 for PQC hybrid).",
        "FW-001": "Enable a host firewall (ufw enable / nft default-deny inbound).",
        "AUD-001": "Install and enable auditd; deploy a CIS/Neo23x0 audit ruleset.",
        "SYS-001": "echo 'kernel.randomize_va_space=2' >> /etc/sysctl.d/99-hardening.conf; sysctl --system",
        "SYS-007": "Set kernel.yama.ptrace_scope=1 to restrict process tracing.",
    }

    def _annotate_remediation(self) -> None:
        for f in self.findings:
            if f["status"] in ("FAIL", "WARN"):
                hint = self.REMEDIATION.get(f["id"])
                if not hint and f["id"].startswith("MOD-"):
                    mod = f["id"].split("-", 1)[1]
                    hint = f"Blacklist module: echo 'install {mod} /bin/true' >> /etc/modprobe.d/hardening.conf"
                if not hint and f["id"].startswith("SVC-"):
                    hint = "Disable & mask the service: systemctl disable --now <svc>; systemctl mask <svc>"
                if hint:
                    f["remediation"] = hint

    def run(self) -> Dict[str, Any]:
        logger.info("=" * 50)
        logger.info("Linux Hardening Check")
        logger.info("=" * 50)
        self.check_ssh_config()
        self.check_firewall()
        self.check_filesystem()
        self.check_services()
        self.check_audit()
        self.check_sysctl()
        self.check_kernel_modules()
        self._annotate_remediation()
        passed = sum(1 for f in self.findings if f["status"] == "PASS")
        failed = sum(1 for f in self.findings if f["status"] == "FAIL")
        return {
            "os": "Linux", "hostname": platform.node(),
            "total_checks": len(self.findings), "passed": passed, "failed": failed,
            "score_pct": round(passed / max(len(self.findings), 1) * 100, 1),
            "findings": self.findings,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }


def _run_demo() -> int:
    """Offline self-test: SSH evaluator must ignore commented directives."""
    hardened = ("PermitRootLogin no\nPasswordAuthentication no\nX11Forwarding no\n"
                "MaxAuthTries 3\nProtocol 2\n")
    commented = ("#PermitRootLogin no\n#PasswordAuthentication no\n"
                 "PermitRootLogin yes\n")
    h = {f["id"]: f["status"] for f in LinuxHardeningChecker.evaluate_ssh_config(hardened)}
    c = {f["id"]: f["status"] for f in LinuxHardeningChecker.evaluate_ssh_config(commented)}
    checks = [
        ("hardened: root login PASS", h["SSH-001"] == "PASS"),
        ("hardened: password auth PASS", h["SSH-002"] == "PASS"),
        ("commented default NOT a false PASS", c["SSH-001"] == "FAIL"),
        ("prohibit-password accepted", LinuxHardeningChecker.evaluate_ssh_config(
            "PermitRootLogin prohibit-password\n")[0]["status"] == "PASS"),
    ]
    ok = all(p for _, p in checks)
    for label, p in checks:
        print(f"  [{'OK' if p else 'FAIL'}] {label}")
    print("[+] demo passed" if ok else "[!] demo FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description="System Hardening Checker",
                                     epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill")
    parser.add_argument("--os", choices=["ubuntu", "centos", "windows", "auto"], default="auto")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--demo", action="store_true", help="Run an offline self-test and exit")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.demo:
        sys.exit(_run_demo())

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
