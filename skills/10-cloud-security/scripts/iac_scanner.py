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
    print("[!] 'pyyaml' module required: pip install pyyaml")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


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
     "check": lambda c: bool(re.search(r"FROM\s+\S+:latest", c)) or bool(re.search(r"FROM\s+\S+\s*$", c, re.M)),
     "description": "Using 'latest' tag or no tag specified (unpinned base image)"},
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

    def scan_directory(self, directory: str, scan_type: str = "auto") -> Dict[str, Any]:
        """Scan a directory of IaC files."""
        logger.info("=" * 60)
        logger.info("IaC Security Scan: %s", directory)
        logger.info("=" * 60)

        all_findings = []
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                if scan_type in ("auto", "terraform") and filename.endswith(".tf"):
                    all_findings.extend(self.scan_terraform(filepath))
                elif scan_type in ("auto", "docker") and filename.lower() in ("dockerfile", "dockerfile.prod", "dockerfile.dev"):
                    all_findings.extend(self.scan_dockerfile(filepath))
                elif scan_type in ("auto", "kubernetes") and filename.endswith((".yaml", ".yml")):
                    all_findings.extend(self.scan_kubernetes(filepath))

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


def main():
    parser = argparse.ArgumentParser(
        description="IaC Security Scanner",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--path", "-p", required=True, help="Directory or file to scan")
    parser.add_argument("--type", "-t", choices=["auto", "terraform", "docker", "kubernetes"], default="auto")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

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
