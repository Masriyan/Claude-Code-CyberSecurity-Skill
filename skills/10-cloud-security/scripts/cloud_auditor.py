#!/usr/bin/env python3
"""
Cloud Security Auditor
Audits AWS, Azure, and GCP environments for common security misconfigurations.
Uses native CLIs — AWS CLI, Azure CLI, gcloud — so no cloud SDK install needed.

Requires:
  AWS:   pip install boto3  OR  aws-cli configured (aws configure)
  Azure: az login  (Azure CLI)
  GCP:   gcloud auth login  (Google Cloud SDK)

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DISCLAIMER = """
[!] DISCLAIMER: This tool is for AUTHORIZED security auditing only.
[!] Ensure you have permission to audit the target cloud environment.
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_cli(cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
    """Run a CLI command and return parsed JSON output or raw text."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace"
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip(), "command": " ".join(cmd)}
        try:
            return {"data": json.loads(result.stdout), "command": " ".join(cmd)}
        except json.JSONDecodeError:
            return {"data": result.stdout.strip(), "command": " ".join(cmd)}
    except FileNotFoundError:
        return {"error": f"Command not found: {cmd[0]}", "command": " ".join(cmd)}
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "command": " ".join(cmd)}


# ---------------------------------------------------------------------------
# AWS Auditor
# ---------------------------------------------------------------------------

class AWSAuditor:
    """Audit AWS account for common misconfigurations using boto3 or AWS CLI."""

    def __init__(self, profile: Optional[str] = None, region: str = "us-east-1"):
        self.profile = profile
        self.region = region
        self.findings: List[Dict] = []
        self._cli_base = ["aws", "--output", "json"]
        if profile:
            self._cli_base += ["--profile", profile]
        if region:
            self._cli_base += ["--region", region]

    def _aws(self, *args) -> Dict:
        return run_cli(self._cli_base + list(args))

    def add_finding(self, check: str, severity: str, resource: str,
                    description: str, remediation: str) -> None:
        self.findings.append({
            "provider": "AWS",
            "check": check,
            "severity": severity,
            "resource": resource,
            "description": description,
            "remediation": remediation,
        })
        logger.warning("[AWS][%s] %s — %s", severity, check, resource)

    def audit_iam(self) -> None:
        logger.info("Auditing IAM...")

        # Root account usage / MFA
        result = self._aws("iam", "get-account-summary")
        if "data" in result:
            summary = result["data"].get("SummaryMap", {})
            if summary.get("AccountMFAEnabled", 0) == 0:
                self.add_finding(
                    "IAM-ROOT-NO-MFA", "CRITICAL", "Root Account",
                    "Root account does not have MFA enabled.",
                    "Enable MFA on the root account immediately (IAM > Security credentials)."
                )
            if summary.get("AccountAccessKeysPresent", 0) > 0:
                self.add_finding(
                    "IAM-ROOT-ACCESS-KEYS", "HIGH", "Root Account",
                    "Root account has active access keys — should be deleted.",
                    "Delete root access keys. Use IAM roles/users instead."
                )

        # Password policy
        result = self._aws("iam", "get-account-password-policy")
        if "error" in result:
            self.add_finding(
                "IAM-NO-PASSWORD-POLICY", "HIGH", "IAM Password Policy",
                "No IAM password policy is configured.",
                "Set a strong password policy: min 14 chars, uppercase, numbers, symbols, 90-day rotation."
            )
        else:
            policy = result.get("data", {}).get("PasswordPolicy", {})
            if policy.get("MinimumPasswordLength", 0) < 14:
                self.add_finding(
                    "IAM-WEAK-PASSWORD-POLICY", "MEDIUM", "IAM Password Policy",
                    f"Password minimum length is {policy.get('MinimumPasswordLength', 0)} (should be ≥ 14).",
                    "Update password policy to require at least 14 characters."
                )

        # Users without MFA
        result = self._aws("iam", "list-users")
        if "data" in result:
            users = result["data"].get("Users", [])
            for user in users[:20]:  # Limit to avoid rate limiting
                uname = user["UserName"]
                mfa_result = self._aws("iam", "list-mfa-devices", "--user-name", uname)
                if "data" in mfa_result:
                    devices = mfa_result["data"].get("MFADevices", [])
                    if not devices:
                        self.add_finding(
                            "IAM-USER-NO-MFA", "HIGH", f"IAM User: {uname}",
                            f"IAM user '{uname}' has no MFA device configured.",
                            "Enforce MFA for all IAM users via an IAM policy condition (aws:MultiFactorAuthPresent)."
                        )

    def audit_s3(self) -> None:
        logger.info("Auditing S3 buckets...")
        result = self._aws("s3api", "list-buckets")
        if "error" in result or "data" not in result:
            logger.warning("Cannot list S3 buckets: %s", result.get("error", "unknown"))
            return

        buckets = result["data"].get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]

            # Public access block
            pub_result = self._aws("s3api", "get-public-access-block", "--bucket", name)
            if "error" in pub_result:
                self.add_finding(
                    "S3-PUBLIC-ACCESS-ENABLED", "HIGH", f"S3: {name}",
                    f"Bucket '{name}' has no public access block configured.",
                    "Enable S3 Block Public Access at bucket and account level."
                )
            else:
                block = pub_result["data"].get("PublicAccessBlockConfiguration", {})
                if not all([
                    block.get("BlockPublicAcls"),
                    block.get("BlockPublicPolicy"),
                    block.get("IgnorePublicAcls"),
                    block.get("RestrictPublicBuckets"),
                ]):
                    self.add_finding(
                        "S3-PARTIAL-PUBLIC-BLOCK", "HIGH", f"S3: {name}",
                        f"Bucket '{name}' has partial public access block — some settings disabled.",
                        "Enable all four S3 Block Public Access settings."
                    )

            # Encryption
            enc_result = self._aws("s3api", "get-bucket-encryption", "--bucket", name)
            if "error" in enc_result:
                self.add_finding(
                    "S3-NO-ENCRYPTION", "MEDIUM", f"S3: {name}",
                    f"Bucket '{name}' does not have server-side encryption enabled.",
                    "Enable SSE-S3 or SSE-KMS encryption on the bucket."
                )

            # Versioning
            ver_result = self._aws("s3api", "get-bucket-versioning", "--bucket", name)
            if "data" in ver_result:
                status = ver_result["data"].get("Status", "")
                if status != "Enabled":
                    self.add_finding(
                        "S3-NO-VERSIONING", "LOW", f"S3: {name}",
                        f"Bucket '{name}' does not have versioning enabled.",
                        "Enable versioning to protect against accidental deletion and ransomware."
                    )

    def audit_ec2_security_groups(self) -> None:
        logger.info("Auditing EC2 security groups...")
        result = self._aws("ec2", "describe-security-groups")
        if "error" in result or "data" not in result:
            return

        groups = result["data"].get("SecurityGroups", [])
        for sg in groups:
            sg_id = sg.get("GroupId", "unknown")
            sg_name = sg.get("GroupName", "unknown")

            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 65535)
                proto = perm.get("IpProtocol", "all")

                for ip_range in perm.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr == "0.0.0.0/0":
                        if from_port == 22 or (from_port <= 22 <= to_port):
                            self.add_finding(
                                "SG-SSH-OPEN", "HIGH", f"SG: {sg_id} ({sg_name})",
                                f"Security group allows SSH (port 22) from 0.0.0.0/0.",
                                "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager."
                            )
                        if from_port == 3389 or (from_port <= 3389 <= to_port):
                            self.add_finding(
                                "SG-RDP-OPEN", "HIGH", f"SG: {sg_id} ({sg_name})",
                                f"Security group allows RDP (port 3389) from 0.0.0.0/0.",
                                "Restrict RDP access to specific IP ranges or use a VPN."
                            )
                        if proto == "-1":
                            self.add_finding(
                                "SG-ALL-TRAFFIC-OPEN", "HIGH", f"SG: {sg_id} ({sg_name})",
                                f"Security group allows ALL traffic from 0.0.0.0/0.",
                                "Restrict inbound rules to only required ports and protocols."
                            )

    def audit_cloudtrail(self) -> None:
        logger.info("Auditing CloudTrail...")
        result = self._aws("cloudtrail", "describe-trails")
        if "error" in result or "data" not in result:
            self.add_finding(
                "CLOUDTRAIL-NO-ACCESS", "INFO", "CloudTrail",
                "Unable to describe CloudTrail trails (may be permissions issue).",
                "Ensure CloudTrail is enabled in all regions."
            )
            return

        trails = result["data"].get("trailList", [])
        if not trails:
            self.add_finding(
                "CLOUDTRAIL-DISABLED", "CRITICAL", "CloudTrail",
                "No CloudTrail trails are configured in this region.",
                "Enable CloudTrail with multi-region logging and log file validation."
            )
            return

        for trail in trails:
            name = trail.get("Name", "unknown")
            if not trail.get("IsMultiRegionTrail"):
                self.add_finding(
                    "CLOUDTRAIL-SINGLE-REGION", "MEDIUM", f"CloudTrail: {name}",
                    f"Trail '{name}' is not multi-region.",
                    "Enable multi-region CloudTrail to capture all API activity."
                )
            if not trail.get("LogFileValidationEnabled"):
                self.add_finding(
                    "CLOUDTRAIL-NO-VALIDATION", "MEDIUM", f"CloudTrail: {name}",
                    f"Trail '{name}' does not have log file validation enabled.",
                    "Enable log file validation to detect tampering."
                )

    def run(self) -> List[Dict]:
        print(DISCLAIMER)
        logger.info("Starting AWS audit (profile=%s, region=%s)", self.profile, self.region)
        self.audit_iam()
        self.audit_s3()
        self.audit_ec2_security_groups()
        self.audit_cloudtrail()
        return self.findings


# ---------------------------------------------------------------------------
# GCP Auditor (stub using gcloud CLI)
# ---------------------------------------------------------------------------

class GCPAuditor:
    """Audit GCP project for common misconfigurations using gcloud CLI."""

    def __init__(self, project: Optional[str] = None):
        self.project = project
        self.findings: List[Dict] = []
        self._cli_base = ["gcloud", "--format=json"]
        if project:
            self._cli_base += ["--project", project]

    def _gcloud(self, *args) -> Dict:
        return run_cli(self._cli_base + list(args))

    def add_finding(self, check: str, severity: str, resource: str,
                    description: str, remediation: str) -> None:
        self.findings.append({
            "provider": "GCP",
            "check": check,
            "severity": severity,
            "resource": resource,
            "description": description,
            "remediation": remediation,
        })
        logger.warning("[GCP][%s] %s — %s", severity, check, resource)

    def audit_iam_bindings(self) -> None:
        logger.info("Auditing GCP IAM bindings...")
        result = self._gcloud("projects", "get-iam-policy", self.project or "")
        if "data" not in result:
            logger.warning("Cannot retrieve IAM policy: %s", result.get("error", ""))
            return

        bindings = result["data"].get("bindings", [])
        for binding in bindings:
            role = binding.get("role", "")
            members = binding.get("members", [])
            for member in members:
                if member == "allUsers" or member == "allAuthenticatedUsers":
                    self.add_finding(
                        "GCP-IAM-PUBLIC-BINDING", "CRITICAL", f"Role: {role}",
                        f"Role '{role}' grants access to '{member}' (public).",
                        "Remove public IAM bindings. Grant access only to specific identities."
                    )
                if role in ("roles/owner", "roles/editor") and member.startswith("user:"):
                    self.add_finding(
                        "GCP-IAM-PRIMITIVE-ROLE", "HIGH", f"Member: {member}",
                        f"User '{member}' has primitive role '{role}' — too broad.",
                        "Replace primitive roles (owner/editor/viewer) with predefined or custom roles."
                    )

    def audit_storage_buckets(self) -> None:
        logger.info("Auditing GCS buckets...")
        result = self._gcloud("storage", "buckets", "list")
        if "data" not in result:
            return

        buckets = result["data"] if isinstance(result["data"], list) else []
        for bucket in buckets:
            name = bucket.get("name", "unknown")
            iam_result = self._gcloud("storage", "buckets", "get-iam-policy", f"gs://{name}")
            if "data" in iam_result:
                for binding in iam_result["data"].get("bindings", []):
                    members = binding.get("members", [])
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        self.add_finding(
                            "GCS-PUBLIC-BUCKET", "HIGH", f"GCS: {name}",
                            f"Bucket '{name}' is publicly accessible.",
                            "Remove allUsers/allAuthenticatedUsers from bucket IAM policy."
                        )

    def run(self) -> List[Dict]:
        print(DISCLAIMER)
        logger.info("Starting GCP audit (project=%s)", self.project)
        self.audit_iam_bindings()
        self.audit_storage_buckets()
        return self.findings


# ---------------------------------------------------------------------------
# Azure Auditor (stub using az CLI)
# ---------------------------------------------------------------------------

class AzureAuditor:
    """Audit Azure subscription for common misconfigurations using az CLI."""

    def __init__(self, subscription: Optional[str] = None):
        self.subscription = subscription
        self.findings: List[Dict] = []

    def _az(self, *args) -> Dict:
        cmd = ["az"] + list(args) + ["--output", "json"]
        if self.subscription:
            cmd += ["--subscription", self.subscription]
        return run_cli(cmd)

    def add_finding(self, check: str, severity: str, resource: str,
                    description: str, remediation: str) -> None:
        self.findings.append({
            "provider": "Azure",
            "check": check,
            "severity": severity,
            "resource": resource,
            "description": description,
            "remediation": remediation,
        })
        logger.warning("[Azure][%s] %s — %s", severity, check, resource)

    def audit_security_center(self) -> None:
        logger.info("Auditing Azure Security Center recommendations...")
        result = self._az("security", "assessment", "list")
        if "data" not in result:
            logger.warning("Cannot list security assessments: %s", result.get("error", ""))
            return

        assessments = result["data"] if isinstance(result["data"], list) else []
        for assessment in assessments:
            status = assessment.get("status", {})
            if status.get("code") == "Unhealthy":
                name = assessment.get("displayName", assessment.get("name", "unknown"))
                severity_map = {"High": "HIGH", "Medium": "MEDIUM", "Low": "LOW"}
                severity = severity_map.get(
                    assessment.get("metadata", {}).get("severity", "Medium"), "MEDIUM"
                )
                self.add_finding(
                    "AZURE-SC-UNHEALTHY", severity, name,
                    f"Azure Security Center: '{name}' is Unhealthy.",
                    assessment.get("metadata", {}).get("remediationDescription", "Follow Azure Security Center recommendation.")
                )

    def audit_network_security_groups(self) -> None:
        logger.info("Auditing Azure NSGs...")
        result = self._az("network", "nsg", "list")
        if "data" not in result:
            return

        nsgs = result["data"] if isinstance(result["data"], list) else []
        for nsg in nsgs:
            nsg_name = nsg.get("name", "unknown")
            for rule in nsg.get("securityRules", []):
                if (rule.get("direction") == "Inbound" and
                        rule.get("access") == "Allow" and
                        rule.get("sourceAddressPrefix") in ("*", "Internet", "0.0.0.0/0")):
                    port = rule.get("destinationPortRange", "")
                    if port in ("22", "3389", "*"):
                        self.add_finding(
                            "NSG-UNRESTRICTED-INBOUND", "HIGH", f"NSG: {nsg_name} / Rule: {rule.get('name')}",
                            f"NSG rule allows unrestricted inbound access to port {port} from Internet.",
                            "Restrict source address to specific IP ranges or use Azure Bastion."
                        )

    def run(self) -> List[Dict]:
        print(DISCLAIMER)
        logger.info("Starting Azure audit (subscription=%s)", self.subscription)
        self.audit_security_center()
        self.audit_network_security_groups()
        return self.findings


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------

def print_summary(provider: str, findings: List[Dict]) -> None:
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    by_sev: Dict[str, int] = {}
    for f in findings:
        sev = f["severity"]
        by_sev[sev] = by_sev.get(sev, 0) + 1

    print(f"\n{'=' * 60}")
    print(f"Cloud Security Audit — {provider}")
    print(f"{'=' * 60}")
    print(f"Total findings: {len(findings)}")
    for sev in severity_order:
        if by_sev.get(sev):
            print(f"  {sev:<10}: {by_sev[sev]}")
    print()
    for sev in severity_order:
        for f in findings:
            if f["severity"] == sev:
                print(f"  [{f['severity']}] {f['check']}")
                print(f"    Resource:    {f['resource']}")
                print(f"    Description: {f['description']}")
                print(f"    Fix:         {f['remediation'][:80]}")
                print()


def main():
    parser = argparse.ArgumentParser(
        description="Cloud Security Auditor — AWS / Azure / GCP",
        epilog=(
            "Examples:\n"
            "  cloud_auditor.py --provider aws --profile default --region us-east-1\n"
            "  cloud_auditor.py --provider gcp --project my-project-id\n"
            "  cloud_auditor.py --provider azure --subscription xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"],
                        help="Cloud provider to audit")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--project", help="GCP project ID")
    parser.add_argument("--subscription", help="Azure subscription ID")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    args = parser.parse_args()

    findings: List[Dict] = []

    if args.provider == "aws":
        auditor = AWSAuditor(profile=args.profile, region=args.region)
        findings = auditor.run()
    elif args.provider == "gcp":
        auditor = GCPAuditor(project=args.project)
        findings = auditor.run()
    elif args.provider == "azure":
        auditor = AzureAuditor(subscription=args.subscription)
        findings = auditor.run()

    print_summary(args.provider.upper(), findings)

    if args.output:
        report = {
            "provider": args.provider,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_findings": len(findings),
            "findings": findings,
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
