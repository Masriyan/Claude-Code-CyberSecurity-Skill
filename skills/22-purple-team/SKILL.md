---
name: Purple Team & Adversary Emulation
description: Collaborative purple-team operations — threat-informed adversary emulation planning (ATT&CK, CTID, Atomic Red Team, CALDERA), the detect-tune-validate loop, detection coverage measurement (DeTT&CT/Navigator), safe execution and deconfliction, and MTTD/coverage reporting
version: 3.1.0
author: Masriyan
tags: [cybersecurity, purple-team, adversary-emulation, attack, atomic-red-team, caldera, detection-engineering, detection-coverage, mttd, breach-attack-simulation]
---

# Purple Team & Adversary Emulation

## Purpose

Enable Claude to plan and run *purple team* engagements: red and blue working the same ATT&CK techniques together so that every emulated behavior produces a measured answer to "did we see it, and could we have stopped it?" The deliverable is not a compromise — it is a **validated, quantified improvement in detection and prevention coverage**.

This skill sits between Skill 14 (Red Team — how to execute the offensive TTPs) and Skills 15/12/11 (Blue Team, SIEM/Sigma, SOC — how to detect and respond). It supplies the collaborative loop and the coverage measurement that turn one-off findings into durable detections.

---

## ⚠️ Authorization Gate — Read First

Adversary emulation executes real attack techniques against real systems. Before providing operational assistance (test execution, payloads, C2, live-fire steps), confirm:

```
[ ] Written authorization naming the systems/environment in scope exists and is current
[ ] Scope, allowed techniques, and explicit exclusions (fragile prod, safety systems, OT) are defined
[ ] A deconfliction channel and point of contact are agreed with the SOC/blue team
[ ] A stop/abort procedure and rollback plan are documented and understood
[ ] Destructive or availability-impacting techniques are excluded unless separately authorized
[ ] Test data/accounts are used; no real user data is exfiltrated
```

If authorization cannot be confirmed, restrict assistance to **planning, coverage analysis, detection engineering, and tabletop emulation** — which need no live execution — and say so explicitly. Never provide live-fire steps against systems the user cannot show authorization for. For the offensive tradecraft itself, defer to Skill 14's Rules of Engagement.

---

## Activation Triggers

This skill activates when the user asks about:
- Planning a purple team engagement, adversary emulation plan, or breach-and-attack-simulation exercise
- Choosing and emulating a specific threat actor's TTPs (from CTI / ATT&CK groups)
- Atomic Red Team, MITRE CALDERA, CTID Adversary Emulation Library, or MITRE Engenuity ATT&CK Evaluations
- The detect → tune → re-test validation loop for a technique
- Measuring or visualizing detection coverage (ATT&CK Navigator layer, DeTT&CT, heatmap)
- Detection maturity per technique (none / telemetry / detection / prevention)
- Deconfliction between red and blue, or safe execution of attack techniques
- Purple-team metrics — MTTD/MTTR, detection rate, per-technique time-to-detect, gap backlog

---

## Prerequisites

```bash
python3 --version          # 3.10+; standard library only for the core script
pip install pyyaml         # optional — only to load emulation plans written in YAML
```

**Optional enhanced tooling:**
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — library of small, ATT&CK-mapped tests
- [MITRE CALDERA](https://github.com/mitre/caldera) — automated adversary emulation platform
- [CTID Adversary Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) — full actor emulation plans
- [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) — data-source and detection coverage scoring
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — coverage heatmaps
- [VECTR](https://github.com/SecurityRiskAdvisors/VECTR) — purple-team assessment tracking

---

## Core Capabilities

### 1. Engagement Model Selection

Pick the collaboration model that fits the maturity and goal:

- **Tabletop emulation** — walk the actor's kill chain on paper; verify each step *would* generate telemetry and *should* fire a detection. No execution; safe anywhere, ideal first pass.
- **Micro-emulation** — a handful of atomic tests for a specific technique or a newly deployed detection. Fast feedback, small blast radius.
- **Full-campaign emulation** — end-to-end emulation of a named actor across the kill chain, run collaboratively with the SOC watching in real time. Highest fidelity, highest coordination cost.
- **Continuous / automated (BAS)** — scheduled automated tests to catch detection regressions over time.

Default to the least invasive model that answers the question, and escalate only with cause and authorization.

### 2. Threat-Informed Emulation Planning

**When the user asks to plan an emulation:**

1. **Choose the adversary from intelligence, not convenience.** Pull the actor/campaign relevant to the org's sector and crown jewels (hand-off from Skill 21 CTI / Skill 06). Prefer an actor the org actually faces.
2. **Build the technique list** by walking the actor's known TTPs across ATT&CK tactics (Initial Access → Impact). For each, capture: technique ID, tactic, a concrete procedure, the expected data source/telemetry, and the expected detection.
3. **Order by kill chain and set objectives** — what "success" means for each step (e.g., "Kerberoast a service account" → objective: SOC alerts within N minutes).
4. **Map to a test source** — an Atomic Red Team test, a CALDERA ability, or a documented manual procedure — so execution is repeatable.
5. **Record the plan** as structured data (`scripts/detection_validator.py` reads a JSON/YAML plan) so results are trackable across re-tests.

### 3. The Detect–Tune–Validate Loop

For every technique, run the collaborative loop and record the outcome:

```
Execute technique (red, announced to blue)
        ↓
Confirm telemetry exists  ──no──▶ GAP: missing data source  → Skill 15 (onboard log source)
        ↓ yes
Confirm a detection fires  ──no──▶ GAP: no detection         → Skill 12 (write Sigma) / Skill 15
        ↓ yes
Was it prevented?          ──no──▶ note: detect-only          → hardening backlog → Skill 15
        ↓
Measure time-to-detect, tune false positives, re-test to confirm the fix
```

Classify each technique's outcome on this ladder: **none** (no telemetry) → **telemetry** (data exists, no alert) → **detection** (alert fires) → **prevention** (blocked). The gap between telemetry and detection is where most purple-team value is realized.

### 4. Coverage Measurement & Visualization

1. **Score every in-scope technique** on the none/telemetry/detection/prevention ladder and compute coverage per tactic and overall.
2. **Produce an ATT&CK Navigator layer** (technique IDs colored by coverage) so the heatmap is shareable and diff-able across engagements.
3. **Track drift** — compare this engagement's layer to the last one; a technique that regressed from detection→telemetry is a finding.
4. **Avoid the coverage-theater trap** — a technique "covered" by one brittle, high-false-positive rule is not covered. Weight robustness and note single-signature dependencies.
5. Use `scripts/detection_validator.py` to turn a results plan into a per-tactic coverage matrix, a Navigator layer, MTTD statistics, and a prioritized gap list.

### 5. Safe Execution & Deconfliction

- **Announce every action** to the blue team in the agreed channel with a timestamp, so a real intrusion during the exercise is not mistaken for the test (and vice versa).
- **Bound the blast radius** — test accounts, test data, non-production or clearly-scoped hosts; never destructive/availability-impacting techniques without separate sign-off (see Skill 18 for OT/ICS where impact can be physical).
- **Have an abort** — a single agreed signal that stops all offensive activity, plus a rollback for any change made.
- **Log everything** — command, time, operator, target, expected vs. observed — so results are attributable and repeatable.

### 6. Metrics & Reporting

Report outcomes, not activity:

- **Detection rate** — % of executed techniques that fired a detection; **prevention rate** — % blocked.
- **MTTD / MTTR** — mean time to detect / respond, per technique and overall; call out the slowest.
- **Coverage delta** — improvement vs. the previous engagement.
- **Remediation backlog** — each gap as an actionable item (missing log source, new detection to write, hardening change) with an owner and priority, handed to Skills 15/12/11.

---

## Output Template

```markdown
# Purple Team Engagement Report
**Engagement:** [Name]  |  **Date:** [YYYY-MM-DD]
**Emulated adversary:** [Actor / campaign]  |  **Model:** [Tabletop / Micro / Full-campaign / BAS]
**Authorization:** [reference]  |  **Deconfliction POC:** [name/channel]

---

## Executive Summary
[2–3 sentences: techniques run, detection rate, prevention rate, top gap, coverage delta.]

## Coverage Scorecard
| Metric | Result |
|--------|--------|
| Techniques executed | N |
| Detected | N (xx%) |
| Prevented | N (xx%) |
| Mean time-to-detect | mm:ss |
| Coverage delta vs. prior | +/- x techniques |

## Per-Technique Results
| Tactic | Technique (ID) | Executed | Data source | Outcome | TTD | Detection / Gap |
|--------|----------------|----------|-------------|---------|-----|-----------------|
| Credential Access | Kerberoasting (T1558.003) | ✅ | Security 4769 | detection | 04:12 | Sigma: rc4 TGS request |
| Defense Evasion | Clear Windows Event Logs (T1070.001) | ✅ | Security 1102 | telemetry | — | GAP: no alert on 1102 |

## Coverage Heatmap
[ATT&CK Navigator layer attached: `navigator_layer.json`]

## Prioritized Remediation Backlog
| Priority | Gap | Action | Owner | Handoff |
|----------|-----|--------|-------|---------|
| High | No alert on log clearing | Write Sigma for EID 1102 | Detection Eng | → Skill 12 |
| Med | RDP lateral movement detect-only | Add prevention control | Blue Team | → Skill 15 |
```

---

## Script Reference

### `detection_validator.py`
```bash
# Score an emulation results plan: coverage matrix, MTTD, gaps
python scripts/detection_validator.py --plan results.json

# Also emit an ATT&CK Navigator layer and a JSON report
python scripts/detection_validator.py --plan results.json \
    --navigator navigator_layer.json --output report.json

# Compare against a previous engagement to compute coverage drift
python scripts/detection_validator.py --plan results.json --baseline prior.json

# Self-contained demo with a built-in sample emulation plan
python scripts/detection_validator.py --demo
```

A plan is a JSON (or YAML with `pyyaml`) list of test entries — `technique_id`, `technique`, `tactic`, `executed`, `data_source`, `outcome` (`none`/`telemetry`/`detection`/`prevention`), and optional `time_to_detect_seconds`. The script computes per-tactic and overall coverage, detection/prevention rates, MTTD, a prioritized gap list, and an ATT&CK Navigator layer. Scoring reflects only what the plan records — it validates *your* results, it does not execute anything.

---

## Skill Integration

| Condition | Next Skill |
|-----------|------------|
| Which adversary/TTPs to emulate | ← Skill 21 (CTI) and Skill 06 (Threat Hunting) |
| Executing the offensive techniques | → Skill 14 (Red Team Operations) — under its RoE |
| A gap needs a detection written | → Skill 12 (Log Analysis / Sigma) |
| A gap needs a hardening/prevention control | → Skill 15 (Blue Team Defense) |
| Validating SOC alerting/triage in the loop | → Skill 11 (CSOC Operations) |
| Emulation touches OT/ICS environments | → Skill 18 (OT/ICS) — safety-first, non-disruptive only |
| A real incident is discovered mid-exercise | → Skill 07 (Incident Response) — declare and deconflict |

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/) · [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Center for Threat-Informed Defense — Adversary Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library)
- [Atomic Red Team (Red Canary)](https://github.com/redcanaryco/atomic-red-team)
- [MITRE CALDERA](https://github.com/mitre/caldera)
- [DeTT&CT — Detect Tactics, Techniques & Combat Threats](https://github.com/rabobank-cdc/DeTTECT)
- [MITRE Engenuity ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/)
- [VECTR (Security Risk Advisors)](https://github.com/SecurityRiskAdvisors/VECTR)
- [Sigma — Generic Detection Rule Format](https://github.com/SigmaHQ/sigma)
- [Scott Roberts / Robert M. Lee — Intelligence-Driven Defense](https://www.first.org/)
