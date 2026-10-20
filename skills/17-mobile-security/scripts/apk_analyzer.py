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
import logging
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

logger = logging.getLogger("apk_analyzer")

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

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


def parse_components(manifest_xml: str) -> list[dict]:
    """Parse components from real manifest XML and determine export status.

    A component is reachable by other apps when ``android:exported="true"`` is
    set, or (on apps targeting API < 31) when it declares an intent-filter and
    does not set ``exported="false"``. Components that are not exported are not
    an IPC attack surface and are excluded from the exported list.
    """
    try:
        root = ET.fromstring(manifest_xml)
    except ET.ParseError:
        return []
    target_sdk = None
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        raw = uses_sdk.get(ANDROID_NS + "targetSdkVersion")
        target_sdk = int(raw) if raw and raw.isdigit() else None

    components: list[dict] = []
    app = root.find("application")
    if app is None:
        return []
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for node in app.findall(tag):
            name = node.get(ANDROID_NS + "name", "?")
            exported_attr = node.get(ANDROID_NS + "exported")
            has_filter = node.find("intent-filter") is not None
            permission = node.get(ANDROID_NS + "permission")
            if exported_attr is not None:
                exported = exported_attr.lower() == "true"
                basis = f'exported="{exported_attr}"'
            elif has_filter:
                # Implicit export: true pre-31, must be explicit on 31+.
                exported = target_sdk is None or target_sdk < 31
                basis = "implicit (intent-filter, no explicit exported)"
            else:
                exported = False
                basis = "no intent-filter, not exported"
            if exported:
                components.append({
                    "type": tag, "name": name, "basis": basis,
                    "protected_by_permission": bool(permission),
                    "permission": permission,
                })
    return components


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
    manifest_xml = ""  # real XML, when available, for accurate export parsing
    if apk is not None:
        report["package"] = apk.package
        report["version"] = f"{apk.version_name} ({apk.version_code})"
        report["permissions"] = sorted(apk.get_permissions() or [])
        try:
            manifest_xml = apk.get_android_manifest_axml().get_xml().decode("utf-8", "ignore")
            manifest_text = manifest_xml
        except Exception as exc:  # noqa: BLE001 — decode failure falls back to string heuristics
            logger.debug("axml decode failed: %s", exc)
            manifest_text = manifest_from_zip(apk_path)
    else:
        manifest_text = manifest_from_zip(apk_path)
        report["permissions"] = sorted(set(re.findall(r"android\.permission\.[A-Z_]+", manifest_text)))

    if manifest_xml:
        report["exported_components"] = parse_components(manifest_xml)
    elif "exported=true" in manifest_text.replace('"', "").replace(" ", ""):
        report["exported_components"] = [{"type": "?", "name": "undetermined",
                                          "basis": "binary manifest — install pyaxmlparser for per-component export status"}]

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
        except Exception as exc:  # noqa: BLE001 — zip/decode issues are non-fatal for triage
            logger.debug("in-APK secret scan failed: %s", exc)

    # De-duplicate identical (type, file, match) secret hits.
    seen, deduped = set(), []
    for s in report["secrets"]:
        key = (s["type"], s["file"], s["match"])
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    report["secrets"] = deduped
    return report


_DEMO_MANIFEST = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo.app">
  <uses-sdk android:targetSdkVersion="33"/>
  <application>
    <activity android:name=".Public" android:exported="true"/>
    <activity android:name=".Private" android:exported="false"/>
    <activity android:name=".Legacy"><intent-filter/></activity>
    <service android:name=".Internal"/>
  </application>
</manifest>"""


def _run_demo() -> int:
    """Offline self-test of the export-status parser (no APK needed)."""
    comps = parse_components(_DEMO_MANIFEST)
    names = {c["name"] for c in comps}
    # targetSdk=33 (>=31) => .Legacy's implicit filter does NOT export it.
    expected = {".Public"}
    ok = names == expected
    print(f"  parsed exported: {sorted(names)} (expected {sorted(expected)})")
    print("[+] demo passed" if ok else "[!] demo FAILED")
    return 0 if ok else 1


def main() -> None:
    ap = argparse.ArgumentParser(description="Static APK triage (authorized testing)")
    ap.add_argument("--apk", help="Path to .apk")
    ap.add_argument("--sources", help="Optional decompiled sources dir (jadx/apktool output) for deeper secret scan")
    ap.add_argument("--output", help="Write JSON report")
    ap.add_argument("--demo", action="store_true", help="Run an offline self-test and exit")
    ap.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")

    if args.demo:
        sys.exit(_run_demo())
    if not args.apk:
        ap.error("--apk is required (or use --demo)")
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
    for c in r["exported_components"][:12]:
        prot = "" if c.get("protected_by_permission") else "  (no permission guard)"
        print(f"    [exp] {c['type']}: {c['name']} — {c.get('basis', '')}{prot}")
    print(f"  Potential secrets: {len(r['secrets'])}")
    for s in r["secrets"][:10]:
        print(f"    [SECRET] {s['type']} in {s['file']}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(r, fh, indent=2)
        print(f"\n[+] Wrote {args.output}")


if __name__ == "__main__":
    main()
