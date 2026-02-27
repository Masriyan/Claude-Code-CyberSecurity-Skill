# 🤝 Contributing Guide

Thank you for your interest in contributing to the **Claude Code CyberSecurity Skill Collection**!

---

## Table of Contents

- [How to Contribute](#how-to-contribute)
- [Adding a New Skill](#adding-a-new-skill)
- [Improving Existing Skills](#improving-existing-skills)
- [Coding Standards](#coding-standards)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

---

## How to Contribute

1. **Fork** the repository at [https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill)
2. **Clone** your fork locally
3. **Create a branch** for your changes (`git checkout -b feature/my-new-skill`)
4. **Make your changes** following the standards below
5. **Test** your changes thoroughly
6. **Submit a Pull Request**

---

## Adding a New Skill

### Directory Structure

Every skill must follow this structure:

```
skills/<NN-skill-name>/
├── SKILL.md              # Required: Main instructions
├── scripts/
│   ├── <tool>.py         # Automation scripts
│   └── utils.py          # Shared utilities
├── examples/
│   └── example_usage.md  # Usage examples
└── resources/
    └── templates/        # Templates, configs, reference data
```

### SKILL.md Template

```yaml
---
name: Your Skill Name
description: One-line description of what this skill does
version: 1.0.0
author: Your Name
tags: [cybersecurity, relevant, tags]
---

# Your Skill Name

## Overview
Brief description of the skill and its purpose.

## Prerequisites
Tools and packages required.

## Core Capabilities
What this skill enables Claude to do.

## Usage Instructions
Step-by-step instructions for using the skill.

## Integration Guide
How this skill integrates with other skills and tools.

## Examples
Real-world usage examples.

## References
Links to relevant documentation, standards, and tools.
```

### Script Standards

- All Python scripts must be **Python 3.8+ compatible**
- Include a `#!/usr/bin/env python3` shebang
- Use `argparse` for command-line arguments
- Include `--help` documentation
- Handle errors gracefully with meaningful messages
- Use `logging` instead of `print` for diagnostic output

---

## Improving Existing Skills

- **Fix bugs** in scripts
- **Add new capabilities** to existing skills
- **Improve documentation** and examples
- **Add test cases**
- **Update for new tool versions**

---

## Coding Standards

### Python

- Follow **PEP 8** style guidelines
- Use **type hints** where practical
- Write **docstrings** for all functions and classes
- Maximum line length: **120 characters**

### Markdown

- Use proper heading hierarchy (`#`, `##`, `###`)
- Include a table of contents for files > 100 lines
- Use code fences with language tags (` ```python `, ` ```bash `)
- Test that all links work

### Shell Scripts

- Use `#!/usr/bin/env bash` shebang
- Use `set -euo pipefail` for safety
- Quote all variables
- Include usage/help output

---

## Pull Request Process

1. Ensure your code follows the coding standards above
2. Update relevant documentation (SKILL.md, examples)
3. Test all scripts for syntax errors
4. Write a clear PR description explaining:
   - What you changed
   - Why you changed it
   - How to test it
5. Reference any related issues

### PR Title Format

```
[skill-name] Brief description of change
```

Examples:

- `[threat-hunting] Add Sigma rule generation support`
- `[new-skill] Add wireless security assessment skill`
- `[docs] Fix installation instructions for macOS`

---

## Reporting Issues

Open an issue at [https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/issues](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/issues) with:

1. **Description** — What happened?
2. **Expected behavior** — What should have happened?
3. **Steps to reproduce** — How can we replicate the issue?
4. **Environment** — OS, Python version, Claude Code version
5. **Logs/Screenshots** — Any relevant output

---

## Code of Conduct

Please read our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

---

<p align="center">
  <a href="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill">← Back to Main Repository</a>
</p>
