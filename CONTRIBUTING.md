# Contributing Guide

Thank you for your interest in contributing to the **Claude Code CyberSecurity Skill Collection**.

---

## Table of Contents

- [How to Contribute](#how-to-contribute)
- [Adding a New Skill](#adding-a-new-skill)
- [Improving Existing Skills](#improving-existing-skills)
- [Script Standards](#script-standards)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

---

## How to Contribute

1. **Fork** the repository at [https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill)
2. **Clone** your fork locally
3. **Create a branch** (`git checkout -b feature/my-improvement`)
4. **Make your changes** following the standards below
5. **Test** your changes (scripts run without errors, SKILL.md is valid YAML)
6. **Submit a Pull Request**

---

## Adding a New Skill

### Directory Structure

```
skills/<NN-skill-name>/
├── SKILL.md              # Required — instructions Claude reads
└── scripts/
    └── <tool>.py         # Supporting automation scripts
```

Only create `examples/` or `resources/` directories when the content genuinely adds value beyond what is in SKILL.md.

### SKILL.md Template (v2.0 Format)

Every SKILL.md must follow the v2.0 structure. The key difference from v1.0 is:
- **Activation Triggers** — explicit phrases that cause Claude to load the skill
- **Authorization Gates** — mandatory for any offensive capability
- **Output Templates** — exact formats Claude uses for reports and artifacts
- **Script Integration** — named scripts with argument examples

```yaml
---
name: Your Skill Name
description: One-line description (Claude uses this for matching)
version: 2.0.0
tags: [cybersecurity, relevant, tags]
---

# Your Skill Name

## Activation Triggers

Claude activates this skill when the user mentions:
- [keyword 1], [keyword 2], [keyword 3]
- Phrases like "help me with X" or "analyze Y"

## Overview

Brief description of the skill and its purpose.

## Prerequisites

| Tool | Installation | Required? |
|------|-------------|-----------|
| tool-name | `pip install tool` | Required |
| other-tool | `apt install other` | Optional |

## Core Capabilities

What this skill enables Claude to do, as a bullet list.

## Methodology

Step-by-step procedure Claude follows. Use numbered steps.

1. Step one
2. Step two
3. Step three

## Script Integration

| Script | Purpose | Key Arguments |
|--------|---------|---------------|
| `scripts/tool.py` | What it does | `--arg value` |

Example:
```bash
python skills/<NN>/scripts/tool.py --arg value --output results.json
```

## Output Template

The exact format Claude uses when reporting results:

```
[FINDING] Title
  Severity:    HIGH
  Description: What was found
  Evidence:    Specific evidence
  Fix:         Remediation steps
```

## References

- [Standard or spec name](https://link)
- [Tool documentation](https://link)
```

---

## Improving Existing Skills

Focus areas where contributions are most valuable:

- **Detection content** — new SIEM queries, Sigma rules, YARA rules
- **Script enhancements** — new checks, better output, additional platforms
- **Methodology updates** — incorporating new ATT&CK techniques or OWASP items
- **Bug fixes** — broken script arguments, outdated command syntax
- **Documentation** — clearer examples, better explanations

Do NOT:
- Remove authorization gates from Skills 03 and 14
- Add speculative features that don't align with the skill's domain
- Introduce external dependencies without a graceful fallback

---

## Script Standards

### Python Requirements

- Python **3.10+** minimum
- Shebang: `#!/usr/bin/env python3`
- Use `argparse` for all CLI arguments, always include `--help`
- Use `logging` for diagnostic output; `print()` only for report content
- Graceful degradation when optional dependencies are missing:

```python
try:
    import optional_package
except ImportError:
    optional_package = None
    logger.warning("optional_package not installed — feature X disabled")
```

- No hardcoded credentials, IPs, or sensitive values
- No `shell=True` in `subprocess` calls (use list form)

### Style

- Follow PEP 8
- Type hints on all function signatures
- Maximum line length: 120 characters
- One short docstring per class/function (what it does, not how)
- No emoji in output unless explicitly part of a report template

### Testing a Script

```bash
# Syntax check
python3 -m py_compile skills/<NN>/scripts/<tool>.py

# Help works
python3 skills/<NN>/scripts/<tool>.py --help

# Demo/dry-run (if --demo flag exists)
python3 skills/<NN>/scripts/<tool>.py --demo

# JSON output is valid
python3 skills/<NN>/scripts/<tool>.py [args] --output /tmp/test.json
python3 -c "import json; json.load(open('/tmp/test.json'))"
```

### Markdown Standards

- Proper heading hierarchy (`#`, `##`, `###`)
- Code fences with language tags (` ```python `, ` ```bash `)
- Tables aligned and consistent
- No broken links

---

## Pull Request Process

1. Ensure all scripts pass syntax check (`python3 -m py_compile`)
2. Update the relevant `SKILL.md` if you change script behavior
3. Update `USAGE.md` if you add or rename a script
4. Update `CHANGELOG.md` under the `[Unreleased]` section
5. Write a clear PR description:
   - What changed and why
   - How to test it
   - Any breaking changes

### PR Title Format

```
[skill-name] Brief description
```

Examples:

```
[threat-hunting] Add Sigma rule generation for lateral movement detection
[12-log-analysis] Fix anomaly detector z-score calculation for small datasets
[docs] Update INSTALL.md with Fedora-specific notes
```

---

## Reporting Issues

Open an issue at [https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/issues](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/issues) with:

1. **Description** — What happened?
2. **Expected behavior** — What should have happened?
3. **Steps to reproduce** — Exact commands that trigger the issue
4. **Environment** — OS, Python version (`python3 --version`), Claude Code version (`claude --version`)
5. **Output** — Paste the error or unexpected output

---

## Code of Conduct

Please read our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

---

[Back to Main Repository](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill)
