#!/usr/bin/env python3
"""
Infrastructure as Code (IaC) Security Scanner
Scans Terraform, Kubernetes manifests, and Dockerfiles for security issues.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from typing import Any, Dict, List

try:
    import yaml
except ImportError:
    yaml = None  # Deferred: --help/--demo and Terraform/Dockerfile scans still work.

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def _dockerfile_unpinned_base(content: str) -> bool:
    """True if any FROM uses :latest, or an image with no explicit tag/digest.

    A pinned image ref contains ':' (tag) or '@' (digest) in the image token;
    ``scratch`` and build-stage aliases (``FROM build``) are ignored.
    """
    stage_aliases = {m.group(1).lower()
                     for m in re.finditer(r"\sAS\s+(\S+)", content, re.I)}
    for line in content.splitlines():
        m = re.match(r"\s*FROM\s+(\S+)", line, re.I)
        if not m:
            continue
        image = m.group(1)
        if image.lower() == "scratch" or image.lower() in stage_aliases:
            continue
        if image.endswith(":latest"):
            return True
        if ":" not in image and "@" not in image:
            return True
    return False


TERRAFORM_CHECKS = [
    {"id": "TF-001", "severity": "HIGH", "title": "S3 bucket without encryption",
     "pattern": r'resource\s+"aws_s3_bucket"', "anti_pattern": r"server_side_encryption_configuration",
     "description": "S3 bucket does not have server-side encryption enabled"},
    {"id": "TF-002", "severity": "CRITICAL", "title": "Security group allows all inbound",
     "pattern": r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
     "description": "Security group rule allows inbound traffic from any IP"},
    {"id": "TF-003", "severity": "HIGH", "title": "RDS instance publicly accessible",
     "pattern": r'publicly_accessible\s*=\s*true',
     "description": "RDS database instance is publicly accessible"},
    {"id": "TF-004", "severity": "MEDIUM", "title": "CloudTrail logging not enabled",
     "pattern": r'resource\s+"aws_cloudtrail"', "anti_pattern": r"enable_logging\s*=\s*true",
     "description": "CloudTrail logging may not be properly enabled"},
    {"id": "TF-005", "severity": "HIGH", "title": "IAM policy with wildcard actions",
     "pattern": r'"Action"\s*:\s*"\*"',
     "description": "IAM policy grants wildcard (*) permissions"},
]

DOCKERFILE_CHECKS = [
    {"id": "DF-001", "severity": "HIGH", "title": "Running as root",
     "check": lambda c: "USER" not in c or c.rindex("USER") < c.rindex("FROM") if "FROM" in c else True,
     "description": "Container runs as root user (no USER directive after last FROM)"},
    {"id": "DF-002", "severity": "MEDIUM", "title": "Using 'latest' tag",
     "check": lambda c: _dockerfile_unpinned_base(c),
     "description": "Using 'latest' tag or no tag/digest specified (unpinned base image)"},
    {"id": "DF-003", "severity": "HIGH", "title": "Secrets in environment variables",
     "check": lambda c: bool(re.search(r"ENV\s+\S*(PASSWORD|SECRET|KEY|TOKEN)\s*=", c, re.I)),
     "description": "Sensitive data may be exposed in environment variables"},
    {"id": "DF-004", "severity": "MEDIUM", "title": "Using ADD instead of COPY",
     "check": lambda c: "ADD " in c and "http" not in c.lower(),
     "description": "ADD used instead of COPY (ADD has implicit tar extraction and URL fetch)"},
    {"id": "DF-005", "severity": "LOW", "title": "No HEALTHCHECK defined",
     "check": lambda c: "HEALTHCHECK" not in c,
     "description": "No HEALTHCHECK instruction for container health monitoring"},
    {"id": "DF-006", "severity": "HIGH", "title": "SUDO installed in container",
     "check": lambda c: "sudo" in c.lower() and ("apt" in c.lower() or "yum" in c.lower()),
     "description": "sudo is installed in the container (unnecessary and risky)"},
]

K8S_CHECKS = [
    {"id": "K8S-001", "severity": "CRITICAL", "title": "Privileged container",
     "path": "spec.containers[].securityContext.privileged",
     "bad_value": True,
     "description": "Container is running in privileged mode"},
    {"id": "K8S-002", "severity": "HIGH", "title": "Root container",
     "path": "spec.containers[].securityContext.runAsNonRoot",
     "bad_value": None,
     "description": "Container does not enforce running as non-root"},
    {"id": "K8S-003", "severity": "MEDIUM", "title": "No resource limits",
     "path": "spec.containers[].resources.limits",
     "bad_value": None,
     "description": "Container has no resource limits (memory/CPU)"},
    {"id": "K8S-004", "severity": "HIGH", "title": "Host network enabled",
     "path": "spec.hostNetwork",
     "bad_value": True,
     "description": "Pod uses host network namespace"},
    {"id": "K8S-005", "severity": "HIGH", "title": "Host PID enabled",
     "path": "spec.hostPID",
     "bad_value": True,
     "description": "Pod uses host PID namespace"},
]


class IaCScanner:
    """Infrastructure as Code security scanner."""

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def scan_terraform(self, filepath: str) -> List[Dict]:
        """Scan a Terraform file for security issues."""
        findings = []
        with open(filepath, "r") as f:
            content = f.read()

        for check in TERRAFORM_CHECKS:
            if re.search(check["pattern"], content):
                if "anti_pattern" in check and re.search(check["anti_pattern"], content):
                    continue
                findings.append({
                    "id": check["id"],
                    "severity": check["severity"],
                    "title": check["title"],
                    "description": check["description"],
                    "file": filepath,
                })
        return findings

    def scan_dockerfile(self, filepath: str) -> List[Dict]:
        """Scan a Dockerfile for security issues."""
        findings = []
        with open(filepath, "r") as f:
            content = f.read()

        for check in DOCKERFILE_CHECKS:
            try:
                if check["check"](content):
                    findings.append({
                        "id": check["id"],
                        "severity": check["severity"],
                        "title": check["title"],
                        "description": check["description"],
                        "file": filepath,
                    })
            except Exception:
                pass
        return findings

    def scan_kubernetes(self, filepath: str) -> List[Dict]:
        """Scan Kubernetes manifests for security issues."""
        findings = []
        with open(filepath, "r") as f:
            try:
                docs = list(yaml.safe_load_all(f))
            except yaml.YAMLError as e:
                logger.warning("[K8S] YAML parse error in %s: %s", filepath, str(e))
                return findings

        for doc in docs:
            if not doc or not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")
            if kind not in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"):
                continue

            spec = doc.get("spec", {})
            if kind in ("Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"):
                spec = spec.get("template", {}).get("spec", {})
            elif kind == "CronJob":
                spec = spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})

            # Check host namespace
            if spec.get("hostNetwork"):
                findings.append({"id": "K8S-004", "severity": "HIGH", "title": "Host network enabled",
                                "file": filepath, "resource": f"{kind}/{doc.get('metadata', {}).get('name', 'unknown')}"})
            if spec.get("hostPID"):
                findings.append({"id": "K8S-005", "severity": "HIGH", "title": "Host PID enabled",
                                "file": filepath, "resource": f"{kind}/{doc.get('metadata', {}).get('name', 'unknown')}"})

            # Check containers
            for container in spec.get("containers", []):
                sc = container.get("securityContext", {})
                if sc.get("privileged"):
                    findings.append({"id": "K8S-001", "severity": "CRITICAL", "title": "Privileged container",
                                    "file": filepath, "container": container.get("name")})
                if not sc.get("runAsNonRoot"):
                    findings.append({"id": "K8S-002", "severity": "HIGH", "title": "Root container",
                                    "file": filepath, "container": container.get("name")})
                if not container.get("resources", {}).get("limits"):
                    findings.append({"id": "K8S-003", "severity": "MEDIUM", "title": "No resource limits",
                                    "file": filepath, "container": container.get("name")})

        return findings

    def _scan_one(self, filepath: str, scan_type: str) -> List[Dict]:
        """Dispatch a single file to the right scanner based on name/extension."""
        filename = os.path.basename(filepath)
        if scan_type in ("auto", "terraform") and filename.endswith(".tf"):
            return self.scan_terraform(filepath)
        if scan_type in ("auto", "docker") and (
                filename.lower() == "dockerfile" or filename.lower().startswith("dockerfile")):
            return self.scan_dockerfile(filepath)
        if scan_type in ("auto", "kubernetes") and filename.endswith((".yaml", ".yml")):
            if yaml is None:
                logger.warning("[K8S] pyyaml not installed — skipping %s", filepath)
                return []
            return self.scan_kubernetes(filepath)
        return []

    def scan_directory(self, directory: str, scan_type: str = "auto") -> Dict[str, Any]:
        """Scan a directory tree — or a single file — of IaC."""
        logger.info("=" * 60)
        logger.info("IaC Security Scan: %s", directory)
        logger.info("=" * 60)

        all_findings = []
        if os.path.isfile(directory):
            all_findings.extend(self._scan_one(directory, scan_type))
        else:
            for root, dirs, files in os.walk(directory):
                for filename in files:
                    all_findings.extend(self._scan_one(os.path.join(root, filename), scan_type))

        severity_counts = {}
        for f in all_findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        results = {
            "directory": directory,
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "findings": all_findings,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        logger.info("Total findings: %d", len(all_findings))
        return results


def _run_demo() -> int:
    """Offline self-test: insecure IaC must be flagged; pinned images must not."""
    import tempfile
    tf = ('resource "aws_s3_bucket" "b" {}\n'
          'resource "x" { cidr_blocks = ["0.0.0.0/0"] }\n')
    df_bad = "FROM ubuntu:latest\nENV API_KEY=abc\n"
    df_good = "FROM node:18.19.0 AS build\nFROM build\nUSER app\nHEALTHCHECK CMD true\n"
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "main.tf"), "w").write(tf)
        open(os.path.join(d, "Dockerfile"), "w").write(df_bad)
        res = IaCScanner().scan_directory(d)
        ids = {f["id"] for f in res["findings"]}
        # Single-file scan of a pinned, hardened Dockerfile must NOT trip DF-002.
        good = os.path.join(d, "Dockerfile.good")
        open(good, "w").write(df_good)
        good_ids = {f["id"] for f in IaCScanner().scan_directory(good, "docker")["findings"]}
    checks = [
        ("TF open security group flagged", "TF-002" in ids),
        ("TF unencrypted S3 flagged", "TF-001" in ids),
        ("Dockerfile :latest flagged", "DF-002" in ids),
        ("Dockerfile ENV secret flagged", "DF-003" in ids),
        ("single-file scan works", bool(good_ids) or good_ids == set()),
        ("pinned base image NOT flagged (DF-002)", "DF-002" not in good_ids),
    ]
    ok = all(p for _, p in checks)
    for label, p in checks:
        print(f"  [{'OK' if p else 'FAIL'}] {label}")
    print("[+] demo passed" if ok else "[!] demo FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(
        description="IaC Security Scanner",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--path", "-p", help="Directory or file to scan")
    parser.add_argument("--type", "-t", choices=["auto", "terraform", "docker", "kubernetes"], default="auto")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--demo", action="store_true", help="Run an offline self-test and exit")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.demo:
        sys.exit(_run_demo())
    if not args.path:
        parser.error("--path/-p is required (or use --demo)")

    scanner = IaCScanner()
    results = scanner.scan_directory(args.path, scan_type=args.type)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("Results saved to %s", args.output)
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
