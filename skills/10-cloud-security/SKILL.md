---
name: Cloud Security & Container Hardening
description: AWS/Azure/GCP security auditing, container and Kubernetes hardening, Infrastructure as Code scanning, and cloud compliance assessment
version: 2.0.0
author: Masriyan
tags: [cybersecurity, cloud, aws, azure, gcp, kubernetes, docker, container, iac, terraform]
---

# Cloud Security & Container Hardening

## Purpose

Enable Claude to assist with cloud security assessments across AWS, Azure, and GCP, container and Kubernetes security hardening, Infrastructure as Code (Terraform, CloudFormation, Kubernetes manifests) scanning, and cloud compliance reporting against CIS Benchmarks and major frameworks.

---

## Activation Triggers

This skill activates when the user asks about:
- Auditing AWS IAM, S3, security groups, or cloud services
- Reviewing Azure RBAC, storage, NSGs, or Key Vault configuration
- Assessing GCP IAM, Cloud Storage, or GKE security
- Scanning Terraform files, CloudFormation templates, or Kubernetes manifests
- Hardening Docker containers or reviewing Dockerfiles
- Kubernetes RBAC, pod security, or network policies
- Cloud compliance (CIS, SOC2, PCI-DSS, HIPAA)
- Container image vulnerability scanning
- Cloud architecture security review
- IaC security scanning (tfsec, Checkov, Terrascan)

---

## Prerequisites

```bash
pip install pyyaml boto3 requests
```

**Recommended cloud security tools:**
- `AWS CLI` — AWS auditing and management
- `ScoutSuite` — Multi-cloud security audit
- `Prowler` — AWS/Azure/GCP security assessment
- `Checkov` — IaC static analysis
- `tfsec` — Terraform security scanner
- `Trivy` — Container and IaC vulnerability scanner
- `kube-bench` — CIS Kubernetes Benchmark
- `Falco` — Container runtime security

---

## Core Capabilities

### 1. AWS Security Auditing

**When the user asks to audit AWS security:**

**Quick AWS security checks using CLI:**
```bash
# IAM: Find users without MFA
aws iam get-account-summary
aws iam list-users | jq '.Users[].UserName' | xargs -I{} aws iam list-mfa-devices --user-name {}

# Find overly permissive policies
aws iam list-policies --scope Local --only-attached | jq '.Policies[].PolicyName'

# S3: Find public buckets
aws s3api list-buckets --query 'Buckets[].Name' | xargs -I{} aws s3api get-bucket-acl --bucket {}
aws s3api list-buckets --query 'Buckets[].Name' | xargs -I{} aws s3api get-bucket-policy-status --bucket {}

# Security groups: Find wide-open rules
aws ec2 describe-security-groups --filters "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName,Rules:IpPermissions}'

# CloudTrail: Verify logging
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name [trail-name]

# Root account check
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'
```

**AWS IAM Security Checklist:**
```
Identity & Access Management:
[ ] Root account has MFA enabled
[ ] Root account has no access keys
[ ] All IAM users have MFA enabled
[ ] No IAM users with AdministratorAccess unless necessary
[ ] All IAM users have individual credentials (no shared)
[ ] Password policy: min 14 chars, complexity, rotation ≤90 days
[ ] Access keys rotated every 90 days
[ ] Unused credentials disabled (>90 days no use)
[ ] No inline policies; use managed policies

S3 Security:
[ ] Block Public Access enabled at account level
[ ] No buckets with public READ ACL
[ ] Server-side encryption enabled (SSE-S3 or SSE-KMS)
[ ] Versioning enabled for critical buckets
[ ] MFA Delete enabled for critical buckets
[ ] Access logging enabled
[ ] Bucket policies use HTTPS-only conditions

Networking:
[ ] No security groups with 0.0.0.0/0 → port 22 (SSH)
[ ] No security groups with 0.0.0.0/0 → port 3389 (RDP)
[ ] VPC Flow Logs enabled
[ ] No default VPC in use for production workloads
[ ] Private subnets for database and application tiers

Monitoring & Detection:
[ ] CloudTrail enabled in all regions
[ ] CloudTrail log file integrity validation enabled
[ ] GuardDuty enabled
[ ] Security Hub enabled and findings reviewed
[ ] Config rules configured for compliance
[ ] CloudWatch alarms for: root login, failed auth, security group changes
```

**Critical AWS Finding Templates:**
```markdown
**CRITICAL: S3 Bucket Publicly Readable**
Bucket: example-data-prod
Finding: GetBucketAcl returns AllUsers:READ
Risk: All objects publicly readable — potential data breach
Fix: aws s3api put-bucket-acl --bucket example-data-prod --acl private
     Enable: aws s3api put-public-access-block --bucket example-data-prod \
       --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

**HIGH: Security Group Allows SSH from Internet**
Group: sg-0abc123 (web-servers)
Rule: Inbound TCP 22 from 0.0.0.0/0
Risk: SSH brute-force, CVE exploitation
Fix: Change source from 0.0.0.0/0 to your VPN/bastion host IP
```

### 2. Azure Security Auditing

**When the user asks to audit Azure:**

```bash
# Login and set subscription
az login
az account set --subscription [subscription-id]

# Check RBAC assignments
az role assignment list --all --include-inherited \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor'].{Name:principalName,Role:roleDefinitionName}"

# Storage account public access
az storage account list --query "[?allowBlobPublicAccess==true].name"

# NSG rules allowing any source
az network nsg list --query "[*].{NSG:name}" | jq '.[].NSG' | xargs -I{} \
  az network nsg rule list --nsg-name {} --resource-group [rg] \
  --query "[?sourceAddressPrefix=='*'].{Rule:name,Port:destinationPortRange}"

# Key Vault access policies
az keyvault list --query "[*].name" | xargs -I{} az keyvault show --name {} \
  --query 'properties.accessPolicies'
```

**Azure Security Checklist:**
```
Identity:
[ ] Global Administrator role has MFA
[ ] No more than 3-5 Global Administrators
[ ] Privileged Identity Management (PIM) for elevated roles
[ ] Guest accounts reviewed quarterly
[ ] Legacy authentication blocked (Conditional Access)

Storage:
[ ] No public blob containers (allowBlobPublicAccess = false)
[ ] Secure transfer required (HTTPS only)
[ ] Storage accounts use private endpoints
[ ] Storage logs enabled (read/write/delete)
[ ] Customer-managed keys for sensitive data

Networking:
[ ] NSGs restrict management ports (22, 3389) from internet
[ ] Azure DDoS Protection enabled
[ ] Network Watcher flow logs enabled

Monitoring:
[ ] Azure Monitor Diagnostic Settings for all resources
[ ] Security Center (Defender for Cloud) enabled
[ ] Log Analytics Workspace connected
[ ] Alerts for privileged role assignments
```

### 3. Container Security (Docker)

**When the user asks to review a Dockerfile or container security:**

Claude reads and analyzes the Dockerfile directly:

**Dockerfile Security Review:**
```dockerfile
# BEFORE (insecure)
FROM ubuntu:latest           # ← Never use latest
RUN apt-get install -y curl  # ← Install what you need during build
COPY . .                     # ← Copies everything including .env files
RUN chmod 777 /app           # ← World-writable is dangerous
CMD ["./app"]                # ← Runs as root by default
EXPOSE 0-65535               # ← Never expose all ports

# AFTER (secure)
FROM ubuntu:24.04 AS builder            # Pin specific version
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*      # Clean up after install
WORKDIR /app

FROM ubuntu:24.04 AS runtime           # Multi-stage: minimal runtime image
WORKDIR /app
COPY --from=builder /app/bin/myapp ./  # Only copy what's needed
RUN groupadd -r appgroup && useradd -r -g appgroup appuser
RUN chown -R appuser:appgroup /app
USER appuser                           # Non-root user
EXPOSE 8080                            # Only expose necessary port
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8080/health || exit 1
CMD ["./myapp"]
```

**Dockerfile Audit Checklist:**
```
[ ] Base image version pinned (not latest)
[ ] Multi-stage build used to minimize final image
[ ] Runs as non-root user (USER instruction)
[ ] No COPY . . (copies .env, secrets)
[ ] .dockerignore exists and excludes .env, *.key, secrets/
[ ] Package caches cleaned after installation (rm -rf /var/lib/apt/lists/*)
[ ] No RUN commands with passwords, tokens, or secrets
[ ] HEALTHCHECK defined
[ ] Only necessary ports EXPOSE'd
[ ] Read-only filesystem where possible
[ ] No setuid/setgid binaries in final image
```

**Container image scanning:**
```bash
# Scan with Trivy
trivy image myapp:latest --severity HIGH,CRITICAL
trivy image myapp:latest --format json --output scan-results.json

# Docker bench security (runtime checks)
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -v /etc:/etc:ro -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /usr/bin/runc:/usr/bin/runc:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker/docker-bench-security
```

### 4. Kubernetes Security

**When the user asks to audit Kubernetes security:**

```bash
# Run CIS Kubernetes Benchmark
docker run --pid=host -v /etc:/etc:ro -v /var/lib:/var/lib:ro \
  -v /usr/bin/kubelet:/usr/bin/kubelet:ro \
  aquasec/kube-bench:latest

# Check for privileged pods
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | 
      .metadata.name + " in " + .metadata.namespace'

# Check RBAC for overly permissive ClusterRoles
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[]?'

# Check for pods running as root
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.securityContext.runAsUser==0 or 
      .spec.containers[].securityContext.runAsUser==0) | .metadata.name'
```

**Secure Pod Spec Template:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  
  automountServiceAccountToken: false  # Disable unless needed
  
  containers:
  - name: app
    image: myapp:v1.2.3@sha256:abc123  # Pin by digest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      capabilities:
        drop:
          - ALL              # Drop ALL capabilities
        add:
          - NET_BIND_SERVICE  # Add back only what's needed
    
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"      # Always set limits
        cpu: "500m"
    
    volumeMounts:
    - name: tmp
      mountPath: /tmp        # Writable volume for /tmp if needed
  
  volumes:
  - name: tmp
    emptyDir: {}
```

**Kubernetes Security Checklist:**
```
RBAC:
[ ] No wildcards (*) in ClusterRole rules
[ ] cluster-admin role not assigned to service accounts
[ ] Each workload uses a dedicated service account
[ ] ServiceAccount token auto-mount disabled by default

Pod Security:
[ ] All pods have securityContext defined
[ ] runAsNonRoot: true for all containers
[ ] allowPrivilegeEscalation: false
[ ] readOnlyRootFilesystem: true where possible
[ ] capabilities: drop: [ALL]
[ ] No hostPID, hostIPC, hostNetwork
[ ] No privileged: true

Networking:
[ ] Default deny NetworkPolicy in all namespaces
[ ] Only required pod-to-pod communication allowed
[ ] Egress restricted (not just ingress)

Secrets Management:
[ ] No secrets in environment variables (use mounted secrets or vault)
[ ] No secrets in ConfigMaps
[ ] External secrets management (Vault, AWS SSM, Azure Key Vault)
[ ] ETCD encryption at rest enabled

Image Security:
[ ] All images from private registry (not Docker Hub public)
[ ] Image digest pinning (not mutable tags)
[ ] Admission controller (OPA, Kyverno) enforcing policy
[ ] Image scanning in CI/CD pipeline
```

### 5. IaC Security Scanning

**When the user asks to scan Terraform or CloudFormation:**

Claude reads the IaC files directly and identifies issues:

**Common Terraform Misconfigurations:**
```hcl
# INSECURE: S3 bucket with public access
resource "aws_s3_bucket" "bad" {
  bucket = "my-bucket"
  acl    = "public-read"          # ← PUBLIC READ!
}

# SECURE: S3 bucket with all public access blocked
resource "aws_s3_bucket" "good" {
  bucket = "my-bucket"
}
resource "aws_s3_bucket_public_access_block" "good" {
  bucket                  = aws_s3_bucket.good.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# INSECURE: Security group allows all inbound
resource "aws_security_group_rule" "bad" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]    # ← OPEN TO INTERNET!
}
```

**Automated IaC scanning:**
```bash
# Checkov (Terraform, CloudFormation, K8s, Dockerfile)
checkov -d ./terraform/ --framework terraform --output json > checkov-results.json
checkov -d ./k8s-manifests/ --framework kubernetes

# tfsec (Terraform focused)
tfsec ./terraform/ --format json --out tfsec-results.json

# Trivy (IaC, container, filesystem)
trivy config ./terraform/
trivy config ./k8s-manifests/

# Use iac_scanner.py
python scripts/iac_scanner.py --path ./terraform/ --output findings.json
python scripts/iac_scanner.py --path ./k8s-manifests/ --type kubernetes --output k8s_audit.json
```

---

## Compliance Framework Mapping

| Finding | CIS AWS | SOC2 | PCI-DSS | HIPAA |
|---------|---------|------|---------|-------|
| MFA not enforced | 1.10, 1.14 | CC6.1 | 8.3.2 | 164.312(d) |
| Public S3 bucket | 2.1.5 | CC6.7 | 3.4 | 164.312(a)(2)(iv) |
| CloudTrail disabled | 3.1, 3.2 | CC7.2 | 10.2 | 164.312(b) |
| SSH open to internet | 5.2 | CC6.6 | 1.2.1 | 164.312(e)(1) |
| Root account used | 1.7 | CC6.1 | 7.1.1 | 164.308(a)(1) |

---

## Script Reference

### `iac_scanner.py`
```bash
python scripts/iac_scanner.py --path ./terraform/ --output findings.json
python scripts/iac_scanner.py --path ./k8s-manifests/ --type kubernetes --output k8s_audit.json
```

---

## Skill Integration

| Condition | Adjacent Skill |
|-----------|---------------|
| Cloud assets discovered via recon | ← Skill 01 (Recon & OSINT) |
| Cloud vulnerabilities for CSOC alerts | → Skill 11 (CSOC Automation) |
| Implement cloud hardening recommendations | → Skill 15 (Blue Team Defense) |

---

## References

- [CIS Benchmarks for Cloud](https://www.cisecurity.org/cis-benchmarks)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [Azure Security Benchmark v3](https://learn.microsoft.com/en-us/security/benchmark/azure/)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [Checkov Documentation](https://www.checkov.io/1.Welcome/What%20is%20Checkov.html)
- [Prowler Documentation](https://docs.prowler.cloud/)
