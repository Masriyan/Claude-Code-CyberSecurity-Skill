---
name: Cloud Security & Container Hardening
description: AWS/Azure/GCP security auditing, container hardening, IaC scanning, and Kubernetes security
version: 1.0.0
author: Masriyan
tags:
  [cybersecurity, cloud, aws, azure, gcp, kubernetes, docker, container, iac]
---

# ☁️ Cloud Security & Container Hardening

## Overview

This skill enables Claude to assist with cloud security assessments across AWS, Azure, and GCP, container security hardening, Infrastructure as Code (IaC) scanning, and Kubernetes cluster security evaluation.

---

## Prerequisites

### Required

- Python 3.8+
- `pyyaml`, `requests`

### Optional

- **AWS CLI** + credentials — AWS auditing
- **Azure CLI** — Azure auditing
- **gcloud CLI** — GCP auditing
- **Docker** — Container analysis
- **kubectl** — Kubernetes management
- **Terraform** — IaC scanning

```bash
pip install pyyaml boto3 requests
```

---

## Core Capabilities

### 1. Cloud Configuration Auditing (AWS/Azure/GCP)

**When the user asks to audit cloud security:**

**AWS:**

1. Audit IAM policies for over-permissive access
2. Check S3 bucket policies and public access
3. Review security group rules for overly permissive entries
4. Audit CloudTrail and GuardDuty configurations
5. Check for unencrypted EBS volumes and RDS instances
6. Review VPC flow logs and network ACLs
7. Audit Lambda function permissions and environment variables
8. Check for root account usage and MFA enforcement

**Azure:**

1. Audit Azure AD roles and RBAC assignments
2. Check Storage Account access and public blob containers
3. Review Network Security Groups (NSGs)
4. Audit Azure Monitor and Security Center configurations
5. Check Key Vault access policies
6. Review App Service configurations

**GCP:**

1. Audit IAM bindings and service account keys
2. Check Cloud Storage bucket ACLs and public access
3. Review VPC firewall rules
4. Audit Cloud Audit Logs configuration
5. Check GKE cluster security settings

### 2. Container Security

**When the user asks about container security:**

1. Analyze Dockerfiles for security best practices:
   - Running as non-root user
   - Using specific image tags (not `latest`)
   - Minimizing layers and installed packages
   - Not storing secrets in images
   - Using multi-stage builds
   - Setting proper health checks
2. Scan container images for vulnerabilities
3. Audit Docker daemon configuration
4. Review docker-compose security settings
5. Check container runtime configurations
6. Audit container network policies

### 3. Infrastructure as Code (IaC) Scanning

**When the user asks to scan IaC:**

1. Parse Terraform files for security misconfigurations
2. Analyze CloudFormation templates
3. Review Kubernetes manifests (YAML)
4. Check Ansible playbooks for insecure patterns
5. Map findings to CIS Benchmarks
6. Generate remediation recommendations
7. Produce compliance reports

### 4. Kubernetes Security

**When the user asks about K8s security:**

1. Audit RBAC configurations
2. Check pod security contexts and policies
3. Review network policies
4. Audit service account permissions
5. Check for privileged containers
6. Review secrets management
7. Audit admission controllers
8. Check for exposed dashboards and APIs

### 5. Cloud Compliance Assessment

**When the user asks about cloud compliance:**

1. Map findings to compliance frameworks (CIS, SOC2, PCI-DSS, HIPAA)
2. Generate gap analysis reports
3. Provide remediation guidance prioritized by risk
4. Track compliance posture over time

---

## Usage Instructions

### Example Prompts

```
> Audit my AWS account for security misconfigurations
> Scan this Dockerfile for security best practices
> Review these Terraform files for security issues
> Check my Kubernetes cluster RBAC for over-permissive policies
> Assess this S3 bucket policy for public access risks
> Harden this docker-compose.yml configuration
```

---

## Script Reference

### `cloud_auditor.py`

```bash
python scripts/cloud_auditor.py --provider aws --profile default --output report.json
```

### `iac_scanner.py`

```bash
python scripts/iac_scanner.py --path ./terraform/ --output findings.json
python scripts/iac_scanner.py --path ./k8s-manifests/ --type kubernetes --output k8s_audit.json
```

---

## Integration Guide

- **← Recon & OSINT (01)**: Identify cloud-hosted assets for auditing
- **→ CSOC Automation (11)**: Automate cloud security monitoring alerts
- **→ Blue Team Defense (15)**: Implement cloud hardening recommendations

---

## References

- [CIS Benchmarks for Cloud](https://www.cisecurity.org/cis-benchmarks)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [Azure Security Benchmark](https://docs.microsoft.com/en-us/security/benchmark/azure/)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
