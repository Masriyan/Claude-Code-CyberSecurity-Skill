# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Skill 20 — Supply Chain Security** — SBOM generation/analysis (CycloneDX/SPDX), dependency confusion & typosquatting detection, malicious package lifecycle-script indicators, CI/CD (GitHub Actions) pipeline hardening, and artifact provenance/signing guidance (SLSA, Sigstore/cosign, in-toto, npm provenance), with `supply_chain_auditor.py` for the automatable static checks

### Fixed
- **Skill 12** — `log_parser.py`/`anomaly_detector.py`: chaining these two tools exactly as this module's own docstring instructs ("Works on JSON output from log_parser.py") silently found zero anomalies on real auth_log input, no matter how anomalous. `log_parser.py`'s syslog/auth_log regex only captured timestamp/hostname/process/pid/message and never populated `src_ip`/`user`/`status`, which `anomaly_detector.py`'s brute-force/after-hours/lateral-movement detectors default to and require. Added auth_log message sub-parsing in `log_parser.py` to extract those three fields for common SSH/PAM message shapes (Failed/Accepted password, Invalid user).
- **Skill 13** — `tls_auditor.py`: the expired-certificate detail path was dead code for real expired certificates. `ssl.create_default_context()` raises `SSLCertVerificationError` at `wrap_socket()` *before* the expiry computation runs, so `cert_info["expired"]` never got set for a genuinely expired cert -- only the generic "Certificate validation failed" HIGH finding fired, and the dedicated CRITICAL "Certificate expired" branch in `_assess_vulnerabilities`/`_calculate_grade` was unreachable. Now re-checks expiry via an unverified connection (using the optional `cryptography` package, with a graceful skip if it's not installed) after a verification failure, so both findings fire correctly.
- **Skill 02** — `cvss_calculator.py`: `round_up()` used ordinary round-half-up instead of the CVSS spec's mandatory ceiling rounding, systematically under-scoring vulnerabilities whose raw score wasn't an exact tenth (verified wrong on CVE-2021-3156: computed 7.7 instead of the correct 7.8)
- **Skill 02** — `dependency_auditor.py`: OSV/GHSA `database_specific.severity` value `"MODERATE"` was never mapped to this tool's `MEDIUM` bucket, so those findings silently vanished from `severity_counts` and any `--severity` filtering

---

## [3.0.0] — 2026-06-23

### Major Expansion — Four New Domains + Full Refresh of the Original 15

Adds four new skill domains and brings every existing skill up to current (2025–2026) tradecraft and standards. Stronger automation, sharper methodology, more precise output.

#### Added
- **Skill 16 — AI & LLM Security** — OWASP Top 10 for LLM Applications (2025) + MITRE ATLAS threat modeling, prompt-injection/jailbreak test harness (`prompt_injection_tester.py`), RAG & agent/tool-use (function-calling/MCP) security review, and a model supply-chain scanner for unsafe `pickle` deserialization (`model_supply_chain.py`)
- **Skill 17 — Mobile Application Security** — OWASP MASVS/MASTG coverage for Android & iOS, automated APK static triage (`apk_analyzer.py`: manifest flags, permissions, exported components, secret scanning), and Frida/objection dynamic-analysis workflows
- **Skill 18 — OT / ICS / SCADA Security** — Purdue/ISA-95 model review, passive industrial-protocol analysis and exposure-dork generation (`ics_protocol_analyzer.py`: Modbus/DNP3/S7/EtherNet-IP/BACnet), MITRE ATT&CK for ICS, IEC 62443 zone/SL alignment, and a safety-first authorization gate
- **Skill 19 — GRC & Compliance** — risk register scoring with heat map and quantitative ALE (`risk_register.py`), cross-framework control crosswalk (`control_mapper.py`: NIST CSF 2.0 ↔ ISO 27001:2022 ↔ SOC 2 ↔ 800-53r5 ↔ CIS v8 ↔ PCI DSS 4.0), gap analysis, audit evidence, and policy generation
- **"v3.0 Enhancements (2026 Update)"** section in all 15 original skills with current techniques and standards

#### Changed
- **All SKILL.md versions** — bumped from 2.0.0 to 3.0.0
- **Skill 02** — risk-based prioritization with CVSS 4.0, EPSS, CISA KEV, SBOM/VEX, and OSV.dev
- **Skill 08** — JA4+ fingerprinting, QUIC/HTTP3, encrypted-DNS detection, Zeek-first pipeline
- **Skill 09** — OWASP API Security Top 10 (2023), SSRF→cloud metadata, request smuggling, JWT/OAuth/OIDC, GraphQL
- **Skill 10** — attack-path / CNAPP thinking, IMDSv2, Kubernetes Pod Security & workload identity, CI/CD supply chain, eBPF runtime
- **Skill 13** — finalized NIST PQC standards (FIPS 203 ML-KEM / 204 ML-DSA / 205 SLH-DSA), hybrid TLS, crypto-agility
- **Skill 14** — AD CS abuse (ESC1–ESC14), EDR evasion, identity/cloud red teaming; `engagement_planner.py` rewritten ATT&CK-aligned with Markdown export and RoE/OPSEC sections
- **Skill 15** — detection-as-code, modern OS baselines, Zero Trust maturity; `hardening_checker.py` expanded (sysctl, SSH crypto, kernel modules) with remediation hints
- **README / USAGE / INSTALL / CONTRIBUTING / SECURITY** — updated for 19 skills and v3.0

#### Fixed
- `hardening_checker.py` — crashed with `PermissionError` reading `/etc/ssh/sshd_config` as a non-root user; now degrades gracefully

---

## [2.0.0] — 2025-05-28

### Major Overhaul — Complete Rebuild for Claude Code

Ground-up rebuild of all 15 skills, optimized specifically for how Claude Code reads and executes skill instructions.

#### Added
- **Activation Triggers** section in every SKILL.md — explicit phrases/contexts that activate each skill
- **Authorization Gates** in Skills 03 and 14 — mandatory authorization verification before any operational assistance
- **Output Templates** — exact formats Claude uses for reports, rules, and artifacts
- **SIEM Query Library** — ready-to-run Splunk SPL, Sentinel KQL, Elastic EQL queries in Skills 06, 11, 12
- **Sigma Rule Templates** — complete, deployable Sigma rules in Skills 06, 12, 15
- **Suricata/Snort Rule Templates** — complete IDS rules in Skills 08, 15
- **YARA Rule Templates** — three-tier YARA structure (hash/family/network) in Skills 05, 15
- **Post-Quantum Cryptography** — NIST PQC 2024 finalized standards (ML-KEM, ML-DSA) in Skill 13
- **Kubernetes Security** — complete K8s RBAC, pod security, network policy guidance in Skill 10
- **AD Attack Methodology** — BloodHound workflow and Kerberoasting guide in Skill 14
- **Linux Hardening Commands** — SSH, sysctl, iptables, auditd, AIDE commands in Skill 15
- **Windows Hardening Commands** — CIS Level 1 PowerShell, Sysmon deployment, audit policy in Skill 15
- **Detection Engineering Workflow** — end-to-end detection rule development in Skill 15
- **Zero Trust Assessment Checklist** — architecture review framework in Skill 15
- **`.gitignore`** — excludes `__pycache__`, `.env`, keys, and generated output files

#### Changed
- **Skill 15 (Blue Team Defense)** — complete rewrite from 1-page stub to 400+ line hardening reference
- **All SKILL.md versions** — bumped from 1.0.0 to 2.0.0
- **README.md** — rewritten with accurate Claude Code skill information and v2.0 feature list
- **Skills 03 and 14** — authorization gate is now the first workflow step, not a footer warning
- **Python version requirement** — updated from 3.8+ to 3.10+

#### Fixed
- Removed misleading claim that skills are "automatically discovered"
- Skill integration tables standardized across all 15 skills
- Consistent authorization language across all offensive skills

---

## [1.0.0] — 2024-12-01

### 🎉 Initial Release

#### Added

- **01-recon-osint** — Reconnaissance & OSINT automation skill with subdomain enumeration, port scanning, DNS recon, and technology fingerprinting
- **02-vulnerability-scanner** — Vulnerability scanning with CVE detection, dependency auditing, and CVSS scoring
- **03-exploit-development** — Exploit development skill with PoC generation, payload crafting, and shellcode development
- **04-reverse-engineering** — Binary analysis, disassembly, decompilation, and firmware reverse engineering
- **05-malware-analysis** — Static/dynamic malware analysis, YARA rule generation, and sandbox configuration
- **06-threat-hunting** — IOC extraction, MITRE ATT&CK mapping, and threat hunting hypothesis generation
- **07-incident-response** — IR playbook execution, evidence collection, timeline analysis, and memory forensics
- **08-network-security** — Network traffic analysis, PCAP parsing, IDS rule creation, and firewall hardening
- **09-web-security** — OWASP Top 10 testing, XSS/SQLi detection, API security, and authentication testing
- **10-cloud-security** — AWS/Azure/GCP auditing, container hardening, IaC scanning, and Kubernetes security
- **11-csoc-automation** — SOC alert triage, playbook automation, escalation workflows, and shift reporting
- **12-log-analysis** — Log parsing, anomaly detection, SIEM query building, and correlation rules
- **13-crypto-analysis** — Cipher identification, SSL/TLS auditing, hash analysis, and key strength assessment
- **14-red-team-ops** — Red team engagement planning, C2 setup, lateral movement, and persistence techniques
- **15-blue-team-defense** — System hardening, detection engineering, baseline monitoring, and patch management
- Complete documentation: README, INSTALL, USAGE, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT

---

[3.0.0]: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/releases/tag/v3.0.0
[2.0.0]: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/releases/tag/v2.0.0
[1.0.0]: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/releases/tag/v1.0.0
