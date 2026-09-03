# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 3.0.x   | Yes       |
| 2.0.x   | Security fixes only — upgrade to v3.0 |
| 1.0.x   | No — end of life, upgrade to v3.0 |

---

## ⚠️ Antivirus & VirusTotal False Positives

This repository is a **cybersecurity skills collection** containing security testing tools, payload templates, and exploit development references for **authorized penetration testing and education**. Antivirus engines may flag certain files — this is **expected behavior** and represents a **false positive**.

### Why This Happens

The file `skills/03-exploit-development/scripts/payload_generator.py` contains reverse shell, web shell, and injection payload **templates stored as Python string constants**. AV engines use signature and heuristic matching against these exact patterns because they resemble actual malware payloads. However:

- ❌ No code in this repository executes malicious actions autonomously
- ❌ No hidden backdoors, C2 communication, or data exfiltration exists
- ❌ No obfuscated or hidden malicious payloads exist
- ✅ All payloads are inert string templates requiring explicit user action with authorized targets
- ✅ Every offensive tool includes legal disclaimers requiring written authorization
- ✅ Offensive skills enforce authorization gates before Claude provides assistance

### Affected Files

| File | Why It's Flagged | Actual Purpose |
|---|---|---|
| `skills/03-exploit-development/scripts/payload_generator.py` | Contains reverse shell & web shell string templates | Generates payloads for authorized pentesting |
| `skills/16-ai-llm-security/scripts/prompt_injection_tester.py` | Contains zero-width characters & obfuscated strings | Tests AI model resilience against prompt injection |

### This Is Standard for Security Repositories

Every major cybersecurity toolkit on GitHub triggers the same AV heuristic detections:

- [SecLists](https://github.com/danielmiessler/SecLists) — routinely flagged by AV engines
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — triggers dozens of AV signatures
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) — flagged by nearly every AV engine
- [GTFOBins](https://github.com/GTFOBins/GTFOBins.github.io) — contains shell escape references

### What Users Should Do

If your antivirus quarantines files from this repository:

1. **Whitelist the directory** — Add the skills directory to your AV exclusion list
2. **Review the source code** — Verify the flagged file contains only string templates
3. **Use in isolated environments** — Offensive skills should be used in authorized lab/test environments

#### Windows Defender

On Windows, real-time protection can silently delete flagged files on write or on every OneDrive sync cycle — for example, `payload_generator.py` being re-deleted each time it was restored or re-synced, with no on-screen warning (only visible via `Get-MpThreatDetection`). If files in this repo keep disappearing after `git restore`/`git pull`/OneDrive sync, add an exclusion **before** restoring them, in an elevated PowerShell prompt:

```powershell
Add-MpPreference -ExclusionPath "C:\path\to\Claude-Code-CyberSecurity-Skill"
```

Then re-run `git restore <file>` (or re-sync) to bring the quarantined file back.

---

## Reporting a Vulnerability

If you discover a security vulnerability in this project's code or scripts, **do NOT open a public issue**.

Report it privately via one of:

1. **GitHub Security Advisories** — [Submit a private report](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/security/advisories/new)
2. **GitHub private message** — Contact the repository maintainer directly

### What to Include

- Description of the vulnerability
- Affected file(s) and line numbers if applicable
- Steps to reproduce
- Potential impact (what an attacker could do)
- Suggested fix or mitigation (if you have one)

### Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix release (critical) | Within 30 days |
| Fix release (medium/low) | Within 90 days |

---

## Responsible Use

This skill collection is designed for **authorized security testing, research, and education only**.

Before using any tool or script in this collection, you must:

1. Have **written authorization** from the system owner before testing any system you do not personally own
2. Comply with all **applicable laws** (Computer Fraud and Abuse Act, Computer Misuse Act, GDPR, etc.)
3. Operate only within **explicitly defined scope** (IP ranges, domains, environments)
4. Use offensive tools only in **isolated, controlled environments** when testing your own systems
5. **Report vulnerabilities** discovered during authorized testing to the affected parties through responsible disclosure

Skills with offensive capabilities (03-exploit-development, 14-red-team-ops) require authorization verification before Claude provides operational assistance. This is enforced in the SKILL.md authorization gates.

### Authorized Use Cases

- Penetration testing with a signed Statement of Work
- Bug bounty programs (in-scope targets only)
- CTF competitions
- Security research in isolated lab environments
- Defensive security — hardening, detection engineering, incident response

### Prohibited Use Cases

- Unauthorized access to any computer system
- Targeting systems outside your authorized scope
- Distributing discovered vulnerabilities without coordinated disclosure
- Using scripts to harm, disrupt, or spy on individuals or organizations

---

## Scope of This Security Policy

This policy covers:

- The skill collection scripts and code
- The SKILL.md instruction files
- Documentation and configuration templates

This policy does NOT cover:

- Third-party tools referenced by the skills (Nmap, Volatility, etc.)
- Systems or networks tested using these skills
- User modifications to the scripts or SKILL.md files

---

## Vulnerability Disclosure Credits

Responsible reporters will be credited in the release notes (unless they prefer anonymity).

---

[Back to Main Repository](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill)
