---
name: Supply Chain Security
description: Software supply chain security — SBOM generation and analysis, dependency confusion and typosquatting detection, malicious package indicators, CI/CD pipeline hardening, and artifact provenance/signing (SLSA, Sigstore)
version: 1.0.0
author: Masriyan
tags: [cybersecurity, supply-chain, sbom, sca, typosquatting, dependency-confusion, slsa, sigstore, ci-cd-security, provenance]
---

# Supply Chain Security

## Purpose

Enable Claude to assess and harden the software supply chain end-to-end: what a project depends on, how those dependencies got in, how they were built, and how anyone downstream can trust the result. This complements Skill 02 (Vulnerability Scanner) — Skill 02 asks "is this known-vulnerable version?"; this skill asks "is this dependency, build, or pipeline something to trust at all?"

---

## Activation Triggers

This skill activates when the user asks about:
- SBOM (Software Bill of Materials) generation, validation, or analysis (CycloneDX, SPDX)
- Dependency confusion, typosquatting, or malicious/compromised packages (npm, PyPI, RubyGems, crates.io, Maven, Go modules)
- Suspicious `postinstall`/`preinstall` scripts or other package lifecycle hooks
- CI/CD pipeline security — GitHub Actions, GitLab CI, Jenkins hardening
- Artifact signing, provenance, or attestation — SLSA levels, in-toto, Sigstore/cosign, npm provenance
- Build reproducibility or "does this build match what's published" questions
- Vendor/open-source component risk as part of onboarding a new dependency
- Incidents referencing a compromised upstream package, maintainer account takeover, or a poisoned build pipeline

---

## Prerequisites

```bash
pip install pyyaml requests
```

**Optional enhanced tools:**
- `syft` / `cyclonedx-py` / `cdxgen` — SBOM generation (CycloneDX/SPDX)
- `grype` / `osv-scanner` — SBOM-driven vulnerability matching (pairs with Skill 02)
- `cosign` — artifact/image signing and verification (Sigstore)
- `slsa-verifier` — verify SLSA provenance attestations
- `scorecard` (OpenSSF) — automated supply-chain risk scoring for a GitHub repo

---

## Core Capabilities

### 1. SBOM Generation & Analysis

**When the user asks to generate or review an SBOM:**

1. Identify the ecosystem(s) in the project (see manifest map below) and generate a CycloneDX or SPDX SBOM with the appropriate tool (`syft dir:. -o cyclonedx-json`, `cyclonedx-py`, or language-native equivalents) — or, without tooling, build a manual component list directly from lockfiles.
2. For each component, capture: name, version, ecosystem/PURL, declared license, and (if available) known vulnerabilities.
3. Cross-reference against Skill 02's vulnerability scanning for a combined SBOM+VEX view: which components are affected, and which affected components are actually reachable in the code.
4. Flag components with no discoverable source repository, an unusually recent first-publish date paired with a sudden high download count, or a license that conflicts with project policy (e.g., copyleft in a proprietary product).

### 2. Dependency Confusion & Typosquatting Detection

**When the user asks to audit dependencies for malicious/confusable packages:**

1. **Typosquatting** — compare declared package names against well-known popular packages in the same ecosystem for near-miss names (edit distance, added/dropped hyphen, swapped separator, homoglyphs).
2. **Dependency confusion** — for any internal/private package name, confirm it is actually scoped (npm `@org/pkg`) or otherwise cannot be shadowed by a same-named public package; flag any internal package referenced without a scope or private-registry pin.
3. **Registry existence & metadata** — verify a package still exists at its declared registry, and treat a sudden maintainer change, drastically inflated version jump, or an empty/near-empty README on a long-lived package as a signal worth flagging.
4. Use `scripts/supply_chain_auditor.py` for the automatable parts (typosquat distance, floating versions, missing lockfile, lifecycle-script red flags); apply human judgment for anything the script surfaces as a near-miss rather than treating a hit as proof of compromise.

### 3. Malicious Package Indicators

**When reviewing a specific package (new dependency, or a flagged one) for compromise:**

Look for, in order of severity:
- **Lifecycle script abuse** — `preinstall`/`install`/`postinstall`/`prepare` hooks that fetch and execute remote code, decode base64 blobs, or read CI/registry credentials from the environment (`NPM_TOKEN`, `GITHUB_TOKEN`, cloud secrets).
- **Obfuscation** — minified/packed code in a package that has no legitimate reason to ship obfuscated source (most libraries don't need this).
- **Network exfiltration** — outbound calls to raw IP literals, unfamiliar domains, or DNS-based exfiltration patterns embedded in otherwise unrelated code.
- **Version/behavior mismatch** — a patch-level version bump that changes dependencies, adds install scripts, or touches unrelated files (compare the diff between versions, not just the changelog).

### 4. CI/CD Pipeline Hardening

**When the user asks to review a build/deploy pipeline:**

#### GitHub Actions Checklist
```
[ ] Third-party actions pinned to a full commit SHA, not a mutable tag/branch
[ ] Workflow declares explicit top-level `permissions:` (default is broad without it)
[ ] pull_request_target is never combined with checkout of PR head + code execution
[ ] Secrets are scoped to the job/environment that needs them, not global
[ ] Self-hosted runners are not used for public-repo PR workflows (arbitrary code execution risk)
[ ] Reusable/composite actions from third parties are reviewed like any other dependency
[ ] Build artifacts are published with provenance (see below), not just uploaded raw
```

#### General CI/CD Checklist (any platform)
```
[ ] Build environment is ephemeral / reproducible, not a long-lived hand-configured box
[ ] Dependency resolution uses lockfiles, not floating ranges, at build time
[ ] Credentials for package publishing require MFA / short-lived tokens, not long-lived static secrets
[ ] Branch protection requires review before merge to the branch that triggers release builds
[ ] Release/publish step is a distinct, auditable job — not implicit in every merge to main
```

Use `scripts/supply_chain_auditor.py --project-dir .` to automatically flag unpinned GitHub Actions and missing `permissions:` blocks across `.github/workflows/`.

### 5. Artifact Provenance & Signing

**When the user asks about proving where an artifact came from:**

1. **SLSA** — assess or target a SLSA Build Level (L1: provenance exists; L2: provenance is authenticated and generated by a hosted build service; L3: hardened, isolated build platform preventing tampering even by the build script itself). State current level and what's needed for the next.
2. **Sigstore/cosign** — recommend keyless signing (OIDC-bound, no long-lived private key to leak) for container images and release artifacts: `cosign sign` at publish, `cosign verify` at consume/deploy time.
3. **in-toto** — for multi-step build pipelines, recommend attestations per step so the full chain-of-custody can be verified, not just the final artifact.
4. **npm provenance** (`npm publish --provenance`) — recommend for any npm package published from CI, so consumers can verify it was built from the claimed source commit/workflow.

### 6. Third-Party & Vendor Component Risk

Treat a new dependency the way Skill 19 treats a new vendor: check maintenance signal (recent commits, responsive issue triage, more than one maintainer — a single-maintainer package is a bus-factor risk), license compatibility, and whether it pulls in a large, rarely-audited transitive tree for a small amount of functionality used.

---

## Output Template

```markdown
# Supply Chain Security Assessment
**Target:** [Repository/Project]
**Date:** [Date]
**Scope:** [Dependencies / CI-CD pipeline / Build artifacts / All]

---

## Executive Summary
[2-3 sentences: SBOM component count, findings by severity, top risk]

## Finding Summary
| Severity | Count | Examples |
|----------|-------|----------|
| Critical | 1 | Postinstall script executes remote payload |
| High     | 3 | Typosquatted package `lodahs`, unpinned Action `actions/checkout@v4` |
| Medium   | 5 | Floating version ranges, missing workflow `permissions:` |
| Low      | 2 | Range-pinned (`^`/`~`) dependency versions |

## Findings Detail

### CRITICAL-01: [Finding Title]
**Component:** [package@version] | **Ecosystem:** [npm/PyPI/...]
**Evidence:** [exact script/pattern/diff observed]
**Risk:** [what an attacker gains if this is exploited]
**Remediation:** [pin version / remove script / replace dependency / etc.]

---

## SBOM Summary
| Component | Version | Ecosystem | License | Known CVEs |
|-----------|---------|-----------|---------|------------|

## Provenance Status
| Artifact | SLSA Level | Signed (cosign) | Attestation |
|----------|-----------|------------------|-------------|

## Remediation Roadmap
| Priority | Action | Effort | Risk Reduction |
|----------|--------|--------|-----------------|
```

---

## Script Reference

### `supply_chain_auditor.py`
```bash
# Static scan: typosquatting, floating versions, risky lifecycle scripts, unpinned Actions
python scripts/supply_chain_auditor.py --project-dir . --output audit.json

# Also verify each dependency exists on its public registry (adds network calls)
python scripts/supply_chain_auditor.py --project-dir . --check-registry --output audit.json
```

Covers `package.json` (npm), `requirements.txt` (PyPI), `Cargo.toml` (crates.io), and `go.mod` (Go) manifests — lockfile presence, typosquatting, floating versions (npm/PyPI), and risky lifecycle scripts (npm) — plus every workflow under `.github/workflows/`. Findings are heuristic near-misses and configuration gaps, not proof of compromise — always verify a flagged package by hand before treating it as malicious.

---

## Skill Integration

| Condition | Next Skill |
|-----------|------------|
| SBOM shows a known-vulnerable version | → Skill 02 (Vulnerability Scanner) for CVSS/EPSS/KEV scoring |
| Malicious package confirmed | → Skill 05 (Malware Analysis) for static/behavioral analysis of the payload |
| Compromised pipeline suspected in production | → Skill 07 (Incident Response) |
| Pipeline runs in a cloud/K8s environment | → Skill 10 (Cloud Security) for CI/CD runner and workload identity review |
| Compliance mapping needed (e.g., SSDF, NIST 800-218) | → Skill 19 (GRC & Compliance) |
| Discovered during a red team engagement | ← Skill 14 (Red Team Operations) |

---

## References

- [SLSA — Supply-chain Levels for Software Artifacts](https://slsa.dev/)
- [Sigstore](https://www.sigstore.dev/) · [cosign](https://github.com/sigstore/cosign)
- [in-toto](https://in-toto.io/)
- [CycloneDX](https://cyclonedx.org/) · [SPDX](https://spdx.dev/)
- [OpenSSF Scorecard](https://github.com/ossf/scorecard)
- [NIST SP 800-218 — Secure Software Development Framework (SSDF)](https://csrc.nist.gov/pubs/sp/800/218/final)
- [OWASP Software Component Verification Standard (SCVS)](https://owasp.org/www-project-software-component-verification-standard/)
- [npm provenance](https://docs.npmjs.com/generating-provenance-statements)
