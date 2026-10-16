#!/usr/bin/env python3
"""
apk_analyzer.py — Static triage for Android APKs (authorized testing).

Parses the manifest, enumerates permissions and exported components, flags risky
manifest attributes, and scans for hardcoded secrets. Uses pyaxmlparser when
available for binary-manifest decoding; otherwise falls back to raw zip/string
heuristics so it still runs with zero optional deps.

Usage:
    python apk_analyzer.py --apk app.apk
    python apk_analyzer.py --apk app.apk --sources ./jadx_out --output report.json
"""
import argparse
import json
import os
import re
import sys
import zipfile

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_CALL_LOG",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE", "android.permission.QUERY_ALL_PACKAGES",
}

SECRET_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Private Key Block": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "Generic Bearer/JWT": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "Firebase URL": r"https://[a-z0-9\-]+\.firebaseio\.com",
    "Hardcoded secret kw": r"(?i)(api[_-]?key|secret|password|passwd|token)\s*[=:]\s*[\"'][^\"']{6,}[\"']",
}


def try_pyaxml(apk_path: str):
    try:
        from pyaxmlparser import APK  # type: ignore
    except ImportError:
        return None
    try:
        return APK(apk_path)
    except Exception:  # noqa: BLE001
        return None


def manifest_from_zip(apk_path: str) -> str:
    """Fallback: pull printable strings out of the binary manifest."""
    try:
        with zipfile.ZipFile(apk_path) as zf:
            raw = zf.read("AndroidManifest.xml")
        strings = re.findall(rb"[\x20-\x7e]{4,}", raw)
        return " ".join(s.decode("ascii", "ignore") for s in strings)
    except Exception:  # noqa: BLE001
        return ""


def scan_secrets(root: str) -> list[dict]:
    findings = []
    for dirpath, _d, files in os.walk(root):
        for fn in files:
            if not fn.endswith((".java", ".kt", ".xml", ".json", ".js", ".smali", ".properties", ".txt")):
                continue
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:  # noqa: BLE001
                continue
            for label, pat in SECRET_PATTERNS.items():
                for m in re.finditer(pat, content):
                    findings.append({"type": label, "file": os.path.relpath(fp, root),
                                     "match": m.group(0)[:80]})
    return findings


def analyze(apk_path: str, sources: str | None) -> dict:
    report = {"apk": apk_path, "package": None, "version": None,
              "permissions": [], "dangerous_permissions": [],
              "manifest_flags": [], "exported_components": [], "secrets": []}

    apk = try_pyaxml(apk_path)
    manifest_text = ""
    if apk is not None:
        report["package"] = apk.package
        report["version"] = f"{apk.version_name} ({apk.version_code})"
        report["permissions"] = sorted(apk.get_permissions() or [])
        try:
            manifest_text = apk.get_android_manifest_axml().get_xml().decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            manifest_text = manifest_from_zip(apk_path)
        # Exported components
        for comp_type, getter in (("activity", apk.get_activities),
                                   ("service", apk.get_services),
                                   ("receiver", apk.get_receivers),
                                   ("provider", apk.get_providers)):
            try:
                for name in getter() or []:
                    report["exported_components"].append({"type": comp_type, "name": name})
            except Exception:  # noqa: BLE001
                pass
    else:
        manifest_text = manifest_from_zip(apk_path)
        report["permissions"] = sorted(set(re.findall(r"android\.permission\.[A-Z_]+", manifest_text)))

    report["dangerous_permissions"] = [p for p in report["permissions"] if p in DANGEROUS_PERMISSIONS]

    flags = []
    if re.search(r'debuggable["\s=]*true', manifest_text):
        flags.append("android:debuggable=true (debug build / data exposure)")
    if re.search(r'allowBackup["\s=]*true', manifest_text):
        flags.append("android:allowBackup=true (adb backup data exfiltration)")
    if re.search(r'usesCleartextTraffic["\s=]*true', manifest_text):
        flags.append("usesCleartextTraffic=true (HTTP allowed)")
    if "exported=true" in manifest_text.replace('"', '').replace(" ", ""):
        flags.append("Exported components present — verify permission protection")
    if "autoVerify" in manifest_text:
        flags.append("App Links (autoVerify) — check deep-link hijack")
    report["manifest_flags"] = flags

    scan_root = sources if sources and os.path.isdir(sources) else None
    if scan_root:
        report["secrets"] = scan_secrets(scan_root)
    else:
        # Best-effort: scan strings inside the APK zip entries
        try:
            tmp = []
            with zipfile.ZipFile(apk_path) as zf:
                for nm in zf.namelist():
                    if nm.endswith((".xml", ".json", ".properties", ".txt")):
                        txt = zf.read(nm).decode("utf-8", "ignore")
                        for label, pat in SECRET_PATTERNS.items():
                            for m in re.finditer(pat, txt):
                                tmp.append({"type": label, "file": nm, "match": m.group(0)[:80]})
            report["secrets"] = tmp
        except Exception:  # noqa: BLE001
            pass
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Static APK triage (authorized testing)")
    ap.add_argument("--apk", required=True, help="Path to .apk")
    ap.add_argument("--sources", help="Optional decompiled sources dir (jadx/apktool output) for deeper secret scan")
    ap.add_argument("--output", help="Write JSON report")
    args = ap.parse_args()

    if not os.path.isfile(args.apk):
        print(f"[!] No such APK: {args.apk}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Analyzing {args.apk}\n")
    r = analyze(args.apk, args.sources)

    print(f"  Package : {r['package']}")
    print(f"  Version : {r['version']}")
    print(f"  Permissions: {len(r['permissions'])} ({len(r['dangerous_permissions'])} dangerous)")
    for p in r["dangerous_permissions"]:
        print(f"    [!] {p}")
    print(f"  Manifest flags: {len(r['manifest_flags'])}")
    for f in r["manifest_flags"]:
        print(f"    [!] {f}")
    print(f"  Exported components: {len(r['exported_components'])}")
    print(f"  Potential secrets: {len(r['secrets'])}")
    for s in r["secrets"][:10]:
        print(f"    [SECRET] {s['type']} in {s['file']}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(r, fh, indent=2)
        print(f"\n[+] Wrote {args.output}")


if __name__ == "__main__":
    main()
