---
name: Mobile Application Security
description: Android and iOS application security testing — static and dynamic analysis, APK/IPA inspection, OWASP MASVS/MASTG verification, secure-storage and transport review, and mobile malware triage for authorized assessments
version: 3.0.0
author: Masriyan
tags: [cybersecurity, mobile-security, android, ios, masvs, mastg, apk, ipa, frida, reverse-engineering]
---

# Mobile Application Security

## Purpose

Enable Claude to assess Android and iOS application security against the **OWASP MASVS** (Mobile Application Security Verification Standard) and execute tests from the **OWASP MASTG** (Mobile Application Security Testing Guide). Claude performs static analysis on APK/IPA artifacts, guides dynamic instrumentation (Frida/objection), reviews secure storage, transport, and platform-interaction controls, and triages potentially malicious mobile apps.

> **Authorization Required**: Only test applications you own or are explicitly authorized to assess. Decompiling and modifying third-party apps may violate licenses and law. Confirm written scope before proceeding.

---

## Activation Triggers

This skill activates when the user asks about:
- Android (APK/AAB) or iOS (IPA) application security testing
- OWASP MASVS / MASTG verification or a mobile pentest checklist
- Decompiling, reversing, or static analysis of a mobile app
- Insecure data storage, hardcoded secrets, or keystore/keychain review
- Certificate pinning, SSL bypass, or mobile TLS/transport security
- Frida / objection dynamic instrumentation or runtime hooking
- `AndroidManifest.xml`, exported components, deep links, or `Info.plist` review
- Mobile malware analysis or suspicious APK triage
- Root/jailbreak detection, tampering, or anti-RE controls

---

## Prerequisites

```bash
pip install requests pyaxmlparser
```

**Optional enhanced capabilities:**
- `apktool` — APK decode/rebuild
- `jadx` — Dalvik → Java decompiler
- `apkid` — packer/obfuscator/compiler fingerprinting
- `frida` / `objection` — dynamic instrumentation
- `mobsf` (MobSF) — automated static+dynamic analysis platform
- Android SDK platform-tools (`adb`), `unzip`, `openssl`

---

## Core Capabilities

### 1. APK Static Analysis

When asked to analyze an APK:
1. **Unpack & decode** — `apktool d app.apk`; extract `AndroidManifest.xml`, `classes*.dex`, `resources.arsc`, native libs (`lib/`), and assets.
2. **Manifest review** — flag:
   - `android:debuggable="true"`, `android:allowBackup="true"`
   - Exported components (`activity`/`service`/`receiver`/`provider` with `exported="true"` or implicit via intent-filter) lacking permissions
   - `usesCleartextTraffic="true"` / permissive `network_security_config`
   - Dangerous/excessive permissions; custom permissions with weak `protectionLevel`
   - Deep links / `android:autoVerify` (app-link hijack), exported `ContentProvider` paths
3. **Secret hunting** — scan decompiled sources/resources/assets for API keys, tokens, private keys, cloud creds, hardcoded crypto keys/IVs, and backend URLs.
4. **Decompile** — `jadx` to Java; review auth, crypto, WebView (`addJavascriptInterface`, `setJavaScriptEnabled`, `loadUrl` with untrusted input), and SQL.
5. **Native & packing** — `apkid` for packers/obfuscators; inspect `lib/*/*.so` for JNI entry points and hardcoded data.
6. **Signature** — verify signing scheme (v1/v2/v3), debug-cert use, and integrity.

Use `scripts/apk_analyzer.py` for an automated first pass.

### 2. iOS (IPA) Static Analysis

When asked to analyze an IPA:
1. Unzip the IPA; locate `Payload/<App>.app/`.
2. **`Info.plist`** — `NSAppTransportSecurity` exceptions (`NSAllowsArbitraryLoads`), URL schemes, `UIFileSharingEnabled`, permission usage strings.
3. **Binary checks** — encryption (`cryptid`), PIE, stack canaries, ARC; detect missing hardening via `otool`/`class-dump`.
4. **Secret hunting** — `strings` and resource scan for keys, endpoints, tokens.
5. **Data storage** — `NSUserDefaults`, Core Data, Keychain accessibility classes (avoid `kSecAttrAccessibleAlways`), plist data at rest.
6. **Embedded provisioning profile** — entitlements, ad-hoc vs. enterprise distribution.

### 3. Insecure Data Storage (MASVS-STORAGE)

Review where sensitive data lands at rest:
- Android: SharedPreferences, SQLite, internal/external files, logs, WebView cache, clipboard. Verify Keystore-backed keys for sensitive material.
- iOS: Keychain (correct accessibility), no secrets in NSUserDefaults/plists, no sensitive data in app snapshots/backups.
- Flag any PII, tokens, or credentials stored plaintext or with app-derived keys.

### 4. Network & Transport (MASVS-NETWORK)

- Confirm TLS everywhere; no cleartext fallback.
- **Certificate/public-key pinning** present and validated; document bypass via objection/Frida for testing.
- Inspect API traffic with an intercepting proxy (Burp/mitmproxy); test for the same API flaws as web (→ Skill 09): IDOR, broken auth, mass assignment.

### 5. Dynamic Analysis & Instrumentation

Guide runtime testing on a rooted/jailbroken test device or emulator:
- **objection** quick wins: `android sslpinning disable`, `android root disable`, keystore/keychain dump, list activities, start exported components.
- **Frida** hooks for crypto APIs, auth checks, root/jailbreak detection bypass, and tracing sensitive method calls.
- Observe filesystem and logcat for data leakage during use.

### 6. Platform Interaction & Anti-Tampering (MASVS-PLATFORM / RESILIENCE)

- IPC: validate exported components, intent handling, `ContentProvider` permissions, custom URL schemes / deep-link validation.
- WebView: disable JS where not needed; never expose privileged JS interfaces to untrusted content.
- Resilience (defense-in-depth, not a vuln by itself): root/jailbreak detection, anti-debug, anti-hook, code obfuscation, integrity checks.

### 7. Mobile Malware Triage

For suspicious APKs: `apkid` packing, requested permissions vs. stated function, accessibility-service abuse, SMS/dialer/overlay permissions (banking-trojan markers), C2 URLs in strings, dynamic code loading (`DexClassLoader`). Hand confirmed IOCs to → Skill 06, deeper RE to → Skill 04/05.

---

## Output Standards

```markdown
# Mobile App Security Assessment — [App / Package]
Date: [Date] | Platform: [Android/iOS] | Version: [x.y.z] | Analyst: [Name]

## Executive Summary
[Posture, count by severity, top risks]

## MASVS Coverage
| Category | Result | Notes |
|----------|--------|-------|
| STORAGE | Fail | Token in SharedPreferences plaintext |
| CRYPTO  | Pass  | ... |
| NETWORK | Partial | No pinning |
| PLATFORM | ... |
| CODE / RESILIENCE | ... |

## Findings
### [M-01] Hardcoded API Key in resources  (High)
- MASTG-TEST ref / MASVS-STORAGE
- Evidence: res/values/strings.xml:api_key=...
- Impact / Remediation: [rotate, move to backend, ...]

## Recommendations (Prioritized)
```

---

## Script Reference

### `apk_analyzer.py`
```bash
# Static triage of an APK: manifest flags, permissions, exported components, secrets
python scripts/apk_analyzer.py --apk app.apk --output apk_report.json

# Secret-scan the decoded sources too (point at an apktool/jadx output dir)
python scripts/apk_analyzer.py --apk app.apk --sources ./jadx_out --output apk_report.json
```

---

## Skill Integration

| Next Step | Condition | Target Skill |
|-----------|-----------|--------------|
| Backend API testing | App talks to REST/GraphQL API | → Skill 09 |
| Deeper native/binary RE | `.so` / obfuscated logic | → Skill 04 |
| Malware classification | Suspicious/packed APK | → Skill 05 |
| IOC correlation | C2 / malicious infra found | → Skill 06 |
| Crypto implementation review | Custom crypto in app | → Skill 13 |

---

## References

- [OWASP MASVS — Mobile App Security Verification Standard](https://mas.owasp.org/MASVS/)
- [OWASP MASTG — Mobile App Security Testing Guide](https://mas.owasp.org/MASTG/)
- [OWASP Mobile Top 10 (2024)](https://owasp.org/www-project-mobile-top-10/)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/)
- [objection — Runtime mobile exploration](https://github.com/sensepost/objection)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
