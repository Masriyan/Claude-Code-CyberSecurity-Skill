# Purple Team & Adversary Emulation — Example Usage

> **Authorization first.** Adversary emulation runs real attack techniques. Confirm written scope,
> a deconfliction channel with the SOC, and an abort procedure before any live execution
> (see the Authorization Gate in `SKILL.md`). Planning, coverage analysis, and tabletop
> emulation need no execution and are always safe.

## Score an Emulation Plan

```bash
# Score a results plan: coverage matrix, detection/prevention rate, MTTD, gaps
python scripts/detection_validator.py --plan results.json

# Emit an ATT&CK Navigator layer + a full JSON report
python scripts/detection_validator.py --plan results.json \
    --navigator navigator_layer.json --output report.json

# Compare against the previous engagement to measure coverage drift
python scripts/detection_validator.py --plan results.json --baseline prior.json

# Self-contained demo with a built-in sample plan
python scripts/detection_validator.py --demo
```

## Plan Format

A plan is a JSON (or YAML) list of technique-result entries:

```json
[
  {
    "technique_id": "T1558.003",
    "technique": "Kerberoasting",
    "tactic": "Credential Access",
    "executed": true,
    "data_source": "Security 4769",
    "outcome": "detection",
    "time_to_detect_seconds": 252
  },
  {
    "technique_id": "T1070.001",
    "technique": "Clear Windows Event Logs",
    "tactic": "Defense Evasion",
    "executed": true,
    "data_source": "Security 1102",
    "outcome": "telemetry"
  }
]
```

`outcome` is the coverage ladder: `none` (no telemetry) → `telemetry` (data exists, no alert)
→ `detection` (alert fires) → `prevention` (blocked). A bare list, or an object with a
`tests` / `techniques` / `results` key, are both accepted.

## Example Prompts

```
> Build an emulation plan for FIN7 targeting our retail POS environment, mapped to ATT&CK
> We ran these atomic tests — score our detection coverage and rank the gaps
> Turn this results plan into a Navigator layer so I can show the coverage heatmap
> Which techniques regressed since last quarter's purple-team engagement?
> The SOC detected Kerberoasting in 4 minutes — is that good, and how do we cut MTTD?
> Write the deconfliction plan and abort procedure for a live-fire lateral-movement test
```

## Typical Handoffs

| Gap or need | Go to |
|-------------|-------|
| Which adversary/TTPs to emulate | Skill 21 (CTI) / Skill 06 (Threat Hunting) |
| Executing the offensive techniques | Skill 14 (Red Team) — under its RoE |
| No detection for a technique with telemetry | Skill 12 (Sigma) |
| Detect-only technique needs prevention | Skill 15 (Blue Team) |
| Validate SOC triage in the loop | Skill 11 (CSOC Operations) |
