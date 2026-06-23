---
name: GRC & Compliance
description: Governance, risk, and compliance — risk assessment and scoring, control mapping across NIST CSF 2.0 / ISO 27001:2022 / SOC 2 / CIS Controls v8, gap analysis, audit evidence preparation, and security policy generation
version: 3.0.0
author: Masriyan
tags: [cybersecurity, grc, compliance, risk-management, nist-csf, iso27001, soc2, cis-controls, audit, policy]
---

# GRC & Compliance

## Purpose

Enable Claude to operate as a governance, risk, and compliance partner: quantify and prioritize risk, map controls across the major frameworks, run gap analyses, prepare audit evidence, and draft clear, tailored security policies. Claude turns scattered control requirements into a single cross-framework view so one piece of evidence can satisfy many obligations.

> **Advisory scope**: This skill produces risk analysis, control mappings, and policy drafts to support a security/compliance program. It is decision-support, not legal advice or a certification. A qualified auditor or counsel should validate before formal attestation.

---

## Activation Triggers

This skill activates when the user asks about:
- Risk assessment, risk register, risk scoring, or treatment plans
- NIST CSF 2.0, NIST SP 800-53, ISO/IEC 27001:2022, SOC 2, PCI DSS 4.0, HIPAA, GDPR, CIS Controls v8
- Control mapping or crosswalk between frameworks
- Gap analysis against a standard or readiness for an audit/certification
- Audit evidence collection, control narratives, or an SoA (Statement of Applicability)
- Security policy, standard, or procedure drafting
- Third-party / vendor risk assessment
- Compliance posture reporting to leadership or a board

---

## Prerequisites

```bash
pip install pyyaml
```

No external tools required — this skill is primarily analytical and document-generation focused. Claude reads existing policies, configs, and evidence directly.

---

## Core Capabilities

### 1. Risk Assessment & Scoring

When asked to assess risk, run a structured, repeatable method:
1. **Asset & context** — identify assets, owners, data classification, and business impact (CIA).
2. **Threats & vulnerabilities** — enumerate relevant threat sources (map to MITRE ATT&CK where useful) and existing weaknesses.
3. **Likelihood × Impact** — score on a defined scale (e.g., 1–5 each) → inherent risk. Apply control effectiveness → residual risk. Support qualitative (heat map) and, where data exists, quantitative (single-loss/annualized-loss, or FAIR-style ranges) views.
4. **Risk treatment** — choose Mitigate / Transfer / Avoid / Accept; assign owner, due date, and the controls that move residual risk to within appetite.
5. Produce a **risk register** (see Output Standards) and a treatment plan ranked by residual risk.

Use `scripts/risk_register.py` to score and rank a YAML/CSV risk list and emit a heat-map summary.

### 2. Cross-Framework Control Mapping

Maintain one control statement mapped to many frameworks so evidence is reused, not duplicated. Anchor on **NIST CSF 2.0 functions** (GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER) and crosswalk outward:

| Need | Framework | Anchor |
|------|-----------|--------|
| Program governance | NIST CSF 2.0 | GV / ID / PR / DE / RS / RC |
| Certifiable ISMS | ISO/IEC 27001:2022 | Annex A (93 controls, 4 themes) |
| Service-org attestation | SOC 2 | Trust Services Criteria (CC1–CC9, A/C/PI/P) |
| Federal / detailed controls | NIST SP 800-53 Rev.5 | 20 control families |
| Cardholder data | PCI DSS 4.0 | 12 requirements |
| Prioritized baseline | CIS Controls v8 | 18 controls / IG1–IG3 |

Use `scripts/control_mapper.py` to crosswalk a control or to show, for a chosen framework, which related-framework requirements a single control satisfies.

### 3. Gap Analysis & Audit Readiness

When asked for a gap analysis:
1. Select the target framework and scope (systems, locations, data).
2. Assess each control: **Implemented / Partial / Not Implemented / Not Applicable**, with evidence reference.
3. Compute coverage % per domain/function and overall.
4. For each gap: required action, owner, effort, and target date → remediation roadmap.
5. For ISO 27001, produce a **Statement of Applicability** (control, applicable Y/N, justification, status).

### 4. Audit Evidence & Control Narratives

- Build an **evidence index**: control → required artifact → location/owner → cadence (e.g., quarterly access review export, change tickets, training records, scan reports).
- Draft **control narratives** auditors expect: what the control is, who operates it, frequency, and how it's evidenced.
- Flag common audit failures: stale access reviews, missing change-management tickets, untested IR/BCP plans, no log retention proof, unowned exceptions.

### 5. Security Policy & Standard Generation

Draft tailored, plain-language policy documents with a consistent structure (Purpose, Scope, Policy Statements, Roles & Responsibilities, Enforcement, Exceptions, Review cadence, Mapped controls). Common set: Information Security Policy, Access Control, Acceptable Use, Data Classification & Handling, Incident Response, Business Continuity/DR, Change Management, Vendor/Third-Party Risk, Cryptography, Secure SDLC, and an AI Use policy. Map each policy back to the controls it satisfies.

### 6. Third-Party / Vendor Risk

Tier vendors by data access and criticality; drive assessment via SIG/CAIQ-style questionnaires or review of the vendor's SOC 2 / ISO cert; track findings, residual risk, and re-assessment cadence in the register.

---

## Output Standards

**Risk register row:**
```
ID | Risk | Asset | Threat | Likelihood(1-5) | Impact(1-5) | Inherent | Controls | Residual | Treatment | Owner | Due
R-001 | Ransomware encrypts file servers | File svc | Crime group | 4 | 5 | 20 (Critical) | Backups, EDR, MFA | 8 (Medium) | Mitigate | IT Ops | 2026-09-30
```

**Gap analysis / SoA:**
```markdown
# [Framework] Gap Analysis — [Org]
Date: [Date] | Scope: [...] | Overall coverage: 72%

## By Domain
| Domain | Implemented | Partial | Not Impl | N/A | Coverage |
| Access Control | 8 | 2 | 1 | 0 | 80% |

## Gaps & Remediation
| Control | Status | Gap | Action | Owner | Effort | Target |
```

**Compliance posture (leadership):**
```markdown
# Compliance Posture — [Period]
Overall: [score] | Trend: [▲/▼] | Frameworks: [...]
Top risks: [3] | Overdue remediations: [n] | Upcoming audits: [...]
```

---

## Script Reference

### `risk_register.py`
```bash
# Score & rank a risk list (YAML or CSV), emit ranked register + heat-map summary
python scripts/risk_register.py --input risks.yaml --output risk_register.json

# Quantitative ALE view where SLE/ARO provided
python scripts/risk_register.py --input risks.csv --quant --output register.json
```

### `control_mapper.py`
```bash
# Crosswalk a control concept across frameworks
python scripts/control_mapper.py --control "access control" --frameworks all

# Show NIST CSF 2.0 -> ISO 27001 / SOC 2 mapping for a function
python scripts/control_mapper.py --csf PR.AA --output crosswalk.json
```

---

## Skill Integration

| Next Step | Condition | Target Skill |
|-----------|-----------|--------------|
| Technical validation of a control | Need to prove a control works | → Skill 02 / 09 / 10 |
| Cloud compliance scanning | Cloud controls in scope | → Skill 10 |
| Detection coverage evidence | DE function controls | → Skill 12 / 15 |
| IR plan testing evidence | RESPOND/RECOVER controls | → Skill 07 |
| AI governance controls | AI systems in scope | → Skill 16 |

---

## References

- [NIST Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [AICPA SOC 2 — Trust Services Criteria](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- [PCI DSS 4.0](https://www.pcisecuritystandards.org/)
- [FAIR — Factor Analysis of Information Risk](https://www.fairinstitute.org/)
