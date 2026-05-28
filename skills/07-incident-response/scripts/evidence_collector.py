#!/usr/bin/env python3
"""
Forensic Evidence Collector
Collects and documents digital evidence from systems during incident response.
Follows order-of-volatility and generates chain of custody documentation.

IMPORTANT: Run with root/administrator privileges for complete collection.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import hashlib
import json
import logging
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def sha256_file(path: str) -> Optional[str]:
    """Calculate SHA-256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, OSError):
        return None


def run_cmd(cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
    """Run a command and return structured result."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace"
        )
        return {
            "command": " ".join(cmd),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except subprocess.TimeoutExpired:
        return {"command": " ".join(cmd), "error": "timeout", "timestamp": datetime.now(timezone.utc).isoformat()}
    except FileNotFoundError:
        return {"command": " ".join(cmd), "error": "command not found", "timestamp": datetime.now(timezone.utc).isoformat()}


class EvidenceCollector:
    """Collect volatile and non-volatile evidence from live systems."""

    def __init__(self, output_dir: str, collection_type: str = "full"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.collection_type = collection_type
        self.is_linux = platform.system().lower() == "linux"
        self.is_windows = platform.system().lower() == "windows"
        self.evidence_manifest: List[Dict] = []
        self.collection_time = datetime.now(timezone.utc).isoformat()

    def collect_volatile(self) -> Dict[str, Any]:
        """Collect most volatile data first (processes, connections, users)."""
        logger.info("Collecting volatile evidence (order of volatility)...")
        volatile = {}

        if self.is_linux:
            volatile["running_processes"] = run_cmd(["ps", "auxf"])
            volatile["network_connections"] = run_cmd(["ss", "-tulnap"])
            volatile["open_files"] = run_cmd(["lsof", "-n"])
            volatile["logged_in_users"] = run_cmd(["who", "-a"])
            volatile["last_logins"] = run_cmd(["last", "-25"])
            volatile["listening_ports"] = run_cmd(["ss", "-tlnp"])
            volatile["arp_cache"] = run_cmd(["arp", "-n"])
            volatile["routing_table"] = run_cmd(["ip", "route"])
            volatile["kernel_modules"] = run_cmd(["lsmod"])
            volatile["environment_vars"] = run_cmd(["env"])
            volatile["crontabs"] = run_cmd(["crontab", "-l"])
            volatile["scheduled_jobs"] = {"command": "ls /etc/cron*", "stdout": self._read_cron_dirs()}
            volatile["sudoers"] = self._safe_read("/etc/sudoers")
            volatile["passwd"] = self._safe_read("/etc/passwd")
            volatile["shadow_hashes"] = run_cmd(["cat", "/etc/shadow"])  # requires root
            volatile["bash_history"] = self._collect_bash_histories()
            volatile["syslog_tail"] = run_cmd(["tail", "-n", "500", "/var/log/syslog"])
            volatile["auth_log_tail"] = run_cmd(["tail", "-n", "500", "/var/log/auth.log"])
        elif self.is_windows:
            volatile["running_processes"] = run_cmd(["tasklist", "/v", "/fo", "csv"])
            volatile["network_connections"] = run_cmd(["netstat", "-ano"])
            volatile["logged_in_users"] = run_cmd(["query", "user"])
            volatile["services"] = run_cmd(["sc", "query", "type=", "all"])
            volatile["scheduled_tasks"] = run_cmd(["schtasks", "/query", "/fo", "csv", "/v"])
            volatile["startup_items"] = run_cmd(["wmic", "startup", "get", "caption,command"])
            volatile["arp_cache"] = run_cmd(["arp", "-a"])
        else:
            volatile["note"] = "Platform not fully supported. Run manually on target system."

        return volatile

    def collect_filesystem(self) -> Dict[str, Any]:
        """Collect filesystem evidence (recently modified files, suspicious paths)."""
        logger.info("Collecting filesystem evidence...")
        fs = {}

        if self.is_linux:
            # Files modified in the last 7 days in common attack paths
            for path in ["/tmp", "/var/tmp", "/dev/shm", "/root", "/home"]:
                if os.path.exists(path):
                    result = run_cmd(["find", path, "-mtime", "-7", "-type", "f", "-ls"])
                    fs[f"recent_files_{path.strip('/').replace('/', '_')}"] = result

            # Check for SUID/SGID binaries
            fs["suid_binaries"] = run_cmd(["find", "/", "-perm", "/4000", "-type", "f", "-ls"])
            fs["sgid_binaries"] = run_cmd(["find", "/", "-perm", "/2000", "-type", "f", "-ls"])

            # Startup scripts and persistence locations
            for persist_path in [
                "/etc/rc.local", "/etc/cron.d", "/etc/cron.hourly",
                "/etc/cron.daily", "/etc/init.d", "/etc/systemd/system",
            ]:
                if os.path.exists(persist_path):
                    fs[f"persistence_{persist_path.strip('/').replace('/', '_')}"] = run_cmd(["ls", "-la", persist_path])

        return fs

    def collect_network_info(self) -> Dict[str, Any]:
        """Collect network configuration and active connections."""
        logger.info("Collecting network evidence...")
        net = {}

        if self.is_linux:
            net["interfaces"] = run_cmd(["ip", "addr"])
            net["connections_with_pids"] = run_cmd(["ss", "-tulnap"])
            net["dns_config"] = self._safe_read("/etc/resolv.conf")
            net["hosts_file"] = self._safe_read("/etc/hosts")
            net["network_history"] = run_cmd(["journalctl", "-u", "NetworkManager", "-n", "100", "--no-pager"])
        elif self.is_windows:
            net["interfaces"] = run_cmd(["ipconfig", "/all"])
            net["connections"] = run_cmd(["netstat", "-bano"])
            net["dns_cache"] = run_cmd(["ipconfig", "/displaydns"])
            net["hosts_file"] = self._safe_read("C:\\Windows\\System32\\drivers\\etc\\hosts")

        return net

    def collect_logs(self) -> Dict[str, Any]:
        """Collect key log files."""
        logger.info("Collecting log evidence...")
        logs = {}

        if self.is_linux:
            log_files = [
                "/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log",
                "/var/log/secure", "/var/log/messages", "/var/log/wtmp",
                "/var/log/btmp", "/var/log/lastlog",
            ]
            for log_path in log_files:
                if os.path.exists(log_path):
                    # Collect last 1000 lines of text logs
                    if log_path.endswith(".log") or log_path in ["/var/log/syslog", "/var/log/messages", "/var/log/secure"]:
                        logs[os.path.basename(log_path)] = run_cmd(["tail", "-n", "1000", log_path])
                    else:
                        # Binary logs (wtmp, btmp) — use last/lastb to read
                        if "wtmp" in log_path:
                            logs["wtmp_last50"] = run_cmd(["last", "-50", "-F"])
                        elif "btmp" in log_path:
                            logs["btmp_lastb50"] = run_cmd(["lastb", "-50"])

        return logs

    def _safe_read(self, path: str) -> Dict[str, Any]:
        try:
            with open(path) as f:
                return {"command": f"cat {path}", "stdout": f.read(), "timestamp": datetime.now(timezone.utc).isoformat()}
        except (IOError, OSError, PermissionError) as e:
            return {"command": f"cat {path}", "error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()}

    def _read_cron_dirs(self) -> str:
        output = []
        for path in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly"]:
            if os.path.isdir(path):
                try:
                    files = os.listdir(path)
                    output.append(f"\n{path}/: {files}")
                except PermissionError:
                    output.append(f"\n{path}/: [permission denied]")
        return "\n".join(output)

    def _collect_bash_histories(self) -> Dict[str, str]:
        histories = {}
        for home_dir in Path("/home").iterdir() if Path("/home").exists() else []:
            hist = home_dir / ".bash_history"
            if hist.exists():
                try:
                    histories[str(hist)] = hist.read_text(errors="replace")[-10000:]  # Last 10KB
                except (IOError, PermissionError):
                    histories[str(hist)] = "[permission denied]"
        root_hist = Path("/root/.bash_history")
        if root_hist.exists():
            try:
                histories[str(root_hist)] = root_hist.read_text(errors="replace")[-10000:]
            except (IOError, PermissionError):
                histories[str(root_hist)] = "[permission denied]"
        return histories

    def generate_custody_chain(self, evidence_file: str) -> Dict[str, Any]:
        """Generate chain of custody entry for an evidence file."""
        path = Path(evidence_file)
        return {
            "evidence_id": f"EV-{int(time.time())}",
            "file_name": path.name,
            "file_path": str(path.resolve()),
            "file_size_bytes": path.stat().st_size if path.exists() else 0,
            "sha256": sha256_file(str(path)) if path.exists() else None,
            "collection_time": self.collection_time,
            "collected_by": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
            "collection_method": "evidence_collector.py",
            "platform": platform.platform(),
        }

    def save_evidence(self, category: str, data: Dict[str, Any]) -> str:
        """Save evidence data to file and return the path."""
        filename = f"{category}_{int(time.time())}.json"
        filepath = self.output_dir / filename
        with open(filepath, "w", errors="replace") as f:
            json.dump(data, f, indent=2, default=str)
        custody = self.generate_custody_chain(str(filepath))
        self.evidence_manifest.append(custody)
        logger.info("Saved: %s (%d bytes)", filename, filepath.stat().st_size)
        return str(filepath)

    def run(self) -> None:
        logger.info("Starting evidence collection — output: %s", self.output_dir)
        logger.info("Collection type: %s", self.collection_type)
        logger.info("Platform: %s", platform.platform())

        # Always collect volatile data first
        volatile = self.collect_volatile()
        self.save_evidence("01_volatile", volatile)

        if self.collection_type in ("full", "network"):
            net = self.collect_network_info()
            self.save_evidence("02_network", net)

        if self.collection_type in ("full", "filesystem"):
            fs = self.collect_filesystem()
            self.save_evidence("03_filesystem", fs)

        if self.collection_type in ("full", "logs"):
            logs = self.collect_logs()
            self.save_evidence("04_logs", logs)

        # Write manifest with chain of custody
        manifest_path = self.output_dir / "EVIDENCE_MANIFEST.json"
        manifest = {
            "collection_start": self.collection_time,
            "collection_end": datetime.now(timezone.utc).isoformat(),
            "platform": platform.platform(),
            "hostname": platform.node(),
            "collection_type": self.collection_type,
            "total_evidence_items": len(self.evidence_manifest),
            "evidence_items": self.evidence_manifest,
        }
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        logger.info("Collection complete. Evidence manifest: %s", manifest_path)
        logger.info("Total evidence items collected: %d", len(self.evidence_manifest))


def main():
    parser = argparse.ArgumentParser(
        description="Forensic Evidence Collector — IR Tool",
        epilog="IMPORTANT: Run with root/admin privileges for complete collection."
    )
    parser.add_argument("--output", "-o", required=True, help="Output directory for evidence")
    parser.add_argument(
        "--type", "-t",
        choices=["full", "volatile", "network", "filesystem", "logs"],
        default="full",
        help="Collection type (default: full)"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    collector = EvidenceCollector(args.output, args.type)
    collector.run()


if __name__ == "__main__":
    main()
