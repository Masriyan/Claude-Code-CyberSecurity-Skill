# Mobile Application Security — Example Usage

## Static APK Triage

### Quick first pass (manifest, permissions, exported components, secrets)

```bash
python scripts/apk_analyzer.py --apk app.apk --output apk_report.json
```

### Deeper secret scan against decompiled sources

```bash
# First decompile with jadx, then point the analyzer at the output
jadx -d ./jadx_out app.apk
python scripts/apk_analyzer.py --apk app.apk --sources ./jadx_out --output apk_report.json
```

## Manual Tooling Cheatsheet

```bash
# Decode resources + manifest
apktool d app.apk -o app_decoded

# Decompile to Java
jadx -d jadx_out app.apk

# Identify packers / obfuscators / compiler
apkid app.apk

# Verify signing scheme
apksigner verify --verbose app.apk
```

## Dynamic Analysis (rooted device / emulator)

```bash
# objection quick wins
objection -g com.target.app explore
#   android sslpinning disable
#   android root disable
#   android keystore list

# Frida trace of crypto usage
frida-trace -U -f com.target.app -i "javax.crypto.Cipher.*"
```

## iOS (IPA)

```bash
unzip -q app.ipa -d ipa_out
plutil -p ipa_out/Payload/*.app/Info.plist | grep -i -E "ATS|ArbitraryLoads|URLScheme"
otool -hv ipa_out/Payload/*.app/<binary> | grep -E "PIE|cryptid"
strings ipa_out/Payload/*.app/<binary> | grep -E "https?://|AKIA|api_key"
```

## Conversational Examples (skill activates automatically)

```
> Analyze this APK and tell me which components are exported without protection
> Review the app against OWASP MASVS storage and network requirements
> How do I bypass certificate pinning on this app for testing?
> This APK requests SMS + accessibility + overlay permissions — is it a banking trojan?
```

## Integration Workflow

```bash
# 1. Static triage
python scripts/apk_analyzer.py --apk app.apk -o apk_report.json
# 2. Intercept API traffic, then hand REST/GraphQL flaws to Skill 09
# 3. Suspicious/packed? → Skill 05 (malware) ; native .so → Skill 04 (RE)
```
