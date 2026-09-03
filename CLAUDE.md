# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

This is a **content repository**, not an application. It publishes a Claude Code plugin — a collection of 20 `SKILL.md` files (in `skills/<NN-skill-name>/`) that teach Claude domain-specific cybersecurity methodology (recon, vuln scanning, exploit dev, RE, malware analysis, threat hunting, IR, network/web/cloud security, SOC automation, log analysis, crypto, red/blue team ops, AI/LLM security, mobile, OT/ICS, GRC, supply chain security). Each skill directory optionally ships standalone Python automation scripts and example usage docs that the SKILL.md references.

There is no app to build, no test suite, and no CI pipeline defined in this repo — "development" here means writing/editing Markdown skill files and the Python scripts they call out to.

## Commands

Scripts are standalone (no shared package, no `requirements.txt` at repo root — each script declares its own imports and degrades gracefully if optional deps are missing).

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

There is no linter or test runner configured — `py_compile` + `--help` + manual JSON validation (above) is the full verification loop used in this repo (see CONTRIBUTING.md).

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
name: Skill Name
description: One-line description (Claude uses this for activation matching)
version: 3.0.0
author: Masriyan
tags: [cybersecurity, ...]
---
```
followed by: **Activation Triggers** → **Prerequisites** → **Core Capabilities** (numbered methodology) → **Script Integration** (table of scripts + args) → **Output Template** (exact report/finding format Claude must reproduce) → **Skill Integration** (cross-links to other numbered skills, e.g. "Vulnerabilities confirmed → develop PoC → Skill 03") → **References**.

New skills are added sequentially — the collection currently ends at 20, so the next one is 21.

Rules enforced by CONTRIBUTING.md that matter when editing:
- **Never remove the authorization/legal-scope gates** from Skill 03 (Exploit Development) and Skill 14 (Red Team Operations), or the safety gates on Skill 16 (AI/LLM Security) and Skill 18 (OT/ICS Security) — these are load-bearing, not boilerplate.
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
