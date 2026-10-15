# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

This is a **content repository**, not an application. It publishes a Claude Code plugin — a collection of 22 `SKILL.md` files (in `skills/<NN-skill-name>/`) that teach Claude domain-specific cybersecurity methodology (recon, vuln scanning, exploit dev, RE, malware analysis, threat hunting, IR, network/web/cloud security, SOC automation, log analysis, crypto, red/blue team ops, AI/LLM security, mobile, OT/ICS, GRC, supply chain security, threat intelligence/CTI, purple team/adversary emulation). Each skill directory optionally ships standalone Python automation scripts and example usage docs that the SKILL.md references.

Quality gates run through `make check`: pytest, frontmatter/packaging checks, all-script CLI smoke tests, STIX validation, Ruff correctness checks, and Bandit on shared infrastructure. GitHub Actions runs the checks on Python 3.10 and 3.12.

## Commands

Keep the full plugin checkout: IOC scripts import the root `cyberskill` shared package. Install development dependencies with `python -m pip install -r requirements-dev.txt`.

```bash
# Syntax-check a script after editing it
python3 -m py_compile skills/<NN-skill-name>/scripts/<tool>.py

# Confirm --help works (argparse is required for every script)
python3 skills/<NN-skill-name>/scripts/<tool>.py --help

# If the script has a --demo flag, run it as a smoke test
python3 skills/<NN-skill-name>/scripts/<tool>.py --demo

# If a script writes --output <file>.json, validate the JSON
python3 -c "import json; json.load(open('/tmp/test.json'))"
```

Run `make check` before submitting changes. Legacy-script Bandit findings are uploaded for review; they are not a claim of a clean full-repository security audit.

## Repository structure

```
skills/<NN-skill-name>/
├── SKILL.md              # required — the instructions Claude reads; drives activation
├── scripts/<tool>.py      # optional — automation the SKILL.md's Script Integration section calls
└── examples/, resources/  # optional — only when they add value beyond SKILL.md itself
```

`.claude-plugin/marketplace.json` is the plugin manifest — it lists every skill path and must stay in sync with `skills/`. If you add, remove, or renumber a skill directory, update this file too.

## Editing skills — required SKILL.md shape

Every `SKILL.md` uses this structure (see CONTRIBUTING.md for the full template):

```yaml
---
name: 23-your-skill-name
description: One-line description (Claude uses this for activation matching)
license: MIT
metadata:
  version: "3.2.0"
  author: Masriyan
  tags: cybersecurity
---
```
followed by: **Activation Triggers** → **Prerequisites** → **Core Capabilities** (numbered methodology) → **Script Integration** (table of scripts + args) → **Output Template** (exact report/finding format Claude must reproduce) → **Skill Integration** (cross-links to other numbered skills, e.g. "Vulnerabilities confirmed → develop PoC → Skill 03") → **References**.

New skills are added sequentially — the collection currently ends at 22, so the next one is 23.

Rules enforced by CONTRIBUTING.md that matter when editing:
- **Never remove the authorization/legal-scope gates** from Skill 03 (Exploit Development), Skill 14 (Red Team Operations), and Skill 22 (Purple Team & Adversary Emulation), or the safety gates on Skill 16 (AI/LLM Security) and Skill 18 (OT/ICS Security) — these are load-bearing, not boilerplate.
- Don't add speculative features outside a skill's domain; don't introduce external dependencies without a graceful fallback.
- If you change a script's behavior, update the SKILL.md's Script Integration section (and `USAGE.md` if a script is added/renamed) in the same change.
- Any Unreleased-worthy change should be logged under `CHANGELOG.md`'s `[Unreleased]` section.

## Python script conventions (from CONTRIBUTING.md)

- Python 3.10+, `#!/usr/bin/env python3` shebang.
- `argparse` for all CLI args; every script must support `--help`.
- `logging` for diagnostics; `print()` only for actual report/finding content.
- Optional dependencies must degrade gracefully:
  ```python
  try:
      import optional_package
  except ImportError:
      optional_package = None
      logger.warning("optional_package not installed — feature X disabled")
  ```
- No hardcoded credentials/IPs/secrets. No `shell=True` in `subprocess` (use list form).
- PEP 8, type hints on all signatures, 120-char line limit, one short docstring per class/function.

## PR conventions

Title format: `[skill-name] Brief description` (e.g. `[threat-hunting] Add Sigma rule generation for lateral movement detection`).

## Note on AV false positives

Some scripts contain payload/exploit *string templates* for authorized testing (Skills 03, 14). This is intentional and documented in `SECURITY.md` — don't "fix" these by removing or obfuscating the content.
