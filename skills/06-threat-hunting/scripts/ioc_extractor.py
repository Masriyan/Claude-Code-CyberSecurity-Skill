#!/usr/bin/env python3
"""
IOC Extractor
Extracts Indicators of Compromise from text, reports, and logs.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import csv
import io
import json
import logging
import re
import sys
import time
from typing import Any, Dict, List, Set
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from cyberskill.indicators import observable_bundle, refang

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Regex patterns for IOC extraction
IOC_PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|io|info|biz|xyz|top|ru|cn|uk|de|fr|jp|br|in|"
        r"au|ca|it|nl|es|se|no|fi|pl|cz|sk|hu|ro|bg|hr|si|ee|lv|lt|"
        r"me|cc|tv|ws|su|tk|ml|ga|cf|gq|onion|bit)\b"
    ),
    "url": re.compile(
        r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\-.~:/?#\[\]@!$&'()*+,;=%]*"
    ),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha512": re.compile(r"\b[a-fA-F0-9]{128}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "mitre_technique": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "registry_key": re.compile(
        r"\bHK(?:EY_LOCAL_MACHINE|EY_CURRENT_USER|LM|CU|EY_CLASSES_ROOT|CR)"
        r"\\[^\s\"',;)}\]]{5,}\b"
    ),
    "file_path_windows": re.compile(r"\b[A-Z]:\\(?:[^\s\"',;)}\]\\]+\\)*[^\s\"',;)}\]]+\b"),
    "file_path_unix": re.compile(r"\b/(?:usr|etc|var|tmp|home|opt|bin|sbin|root)/[^\s\"',;)}\]]+\b"),
    "bitcoin": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "mutex": re.compile(r"(?:Mutex|mutex|MUTEX)[:\s]+[\"\']?([^\s\"',;)}\]]+)"),
}

# Private/reserved IP ranges to filter
PRIVATE_IP_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^127\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^0\."),
    re.compile(r"^255\."),
]


class IOCExtractor:
    """Extract and categorize IOCs from text input."""

    def __init__(self, defang: bool = False, include_private_ips: bool = False):
        self.defang = defang
        self.include_private_ips = include_private_ips

    def extract(self, text: str) -> Dict[str, Any]:
        """Extract all IOC types from text."""
        logger.info("[IOC] Extracting indicators from text (%d chars)", len(text))

        results: Dict[str, List[str]] = {}
        text = refang(text)

        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = set(pattern.findall(text))

            # Filter IPs
            if ioc_type == "ipv4" and not self.include_private_ips:
                matches = {ip for ip in matches if not self._is_private_ip(ip)}

            # Filter hash false positives (exclude very common hex strings)
            if ioc_type in ("md5", "sha1", "sha256", "sha512"):
                matches = {h for h in matches if not self._is_likely_false_positive_hash(h)}

            if matches:
                results[ioc_type] = sorted(matches)

        # Defang indicators if requested
        if self.defang:
            results = self._defang_indicators(results)

        # Summary stats
        total = sum(len(v) for v in results.values())
        logger.info("[IOC] Extracted %d total indicators across %d types", total, len(results))

        return {
            "total_indicators": total,
            "indicator_types": len(results),
            "indicators": results,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in a private/reserved range."""
        return any(pattern.match(ip) for pattern in PRIVATE_IP_RANGES)

    def _is_likely_false_positive_hash(self, h: str) -> bool:
        """Filter out likely false positive hashes."""
        # All same character
        if len(set(h)) <= 2:
            return True
        # Sequential
        if h == "0" * len(h) or h == "f" * len(h):
            return True
        return False

    def _defang_indicators(self, results: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Defang network indicators for safe sharing."""
        defanged = {}
        for ioc_type, values in results.items():
            if ioc_type in ("ipv4", "ipv6"):
                defanged[ioc_type] = [ip.replace(".", "[.]") for ip in values]
            elif ioc_type == "domain":
                defanged[ioc_type] = [d.replace(".", "[.]") for d in values]
            elif ioc_type == "url":
                defanged[ioc_type] = [
                    u.replace("http://", "hxxp://")
                     .replace("https://", "hxxps://")
                     .replace(".", "[.]")
                    for u in values
                ]
            elif ioc_type == "email":
                defanged[ioc_type] = [e.replace("@", "[@]").replace(".", "[.]") for e in values]
            else:
                defanged[ioc_type] = values
        return defanged

    def to_csv(self, results: Dict[str, Any]) -> str:
        """Convert results to CSV format."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["indicator_type", "indicator_value"])
        for ioc_type, values in results.get("indicators", {}).items():
            for value in values:
                writer.writerow([ioc_type, value])
        return output.getvalue()

    def to_stix(self, results: Dict[str, Any]) -> Dict:
        """Convert results to STIX 2.1 bundle format."""
        return observable_bundle([
            {"type": kind, "value": value}
            for kind, values in results.get("indicators", {}).items() for value in values
        ])


def _run_demo() -> int:
    """Offline self-test: extraction, refang, private-IP filtering, defang, STIX."""
    text = ("Beacon to hxxps://evil[.]com/gate 8[.]8[.]8[.]8 and 10.0.0.5 "
            "hash 44d88612fea8a8f36de82e1278abb02f CVE-2024-3400 T1059.001")
    ex = IOCExtractor(defang=False)
    res = ex.extract(text)
    ind = res["indicators"]
    checks = [
        ("public IP kept", "8.8.8.8" in ind.get("ipv4", [])),
        ("private IP dropped", "10.0.0.5" not in ind.get("ipv4", [])),
        ("refanged URL extracted", any("evil.com" in u for u in ind.get("url", []))),
        ("md5 extracted", "44d88612fea8a8f36de82e1278abb02f" in ind.get("md5", [])),
        ("CVE extracted", "CVE-2024-3400" in ind.get("cve", [])),
        ("ATT&CK technique extracted", "T1059.001" in ind.get("mitre_technique", [])),
    ]
    defanged = IOCExtractor(defang=True).extract(text)["indicators"]
    checks.append(("defang hides dots", all("[.]" in u for u in defanged.get("url", []))))
    try:
        import stix2
        stix2.parse(ex.to_stix(res), allow_custom=True)
        checks.append(("STIX bundle parses", True))
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001
        checks.append((f"STIX parse ({exc})", False))
    ok = all(p for _, p in checks)
    for label, p in checks:
        print(f"  [{'OK' if p else 'FAIL'}] {label}")
    print("[+] demo passed" if ok else "[!] demo FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(
        description="IOC Extractor — Extract indicators from text",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--input", "-i", help="Input file to extract IOCs from")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--format", "-f", choices=["json", "csv", "stix"], default="json", help="Output format")
    parser.add_argument("--defang", action="store_true", help="Defang network indicators")
    parser.add_argument("--include-private", action="store_true", help="Include private IP addresses")
    parser.add_argument("--demo", action="store_true", help="Run an offline self-test and exit")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.demo:
        sys.exit(_run_demo())
    if not args.input:
        parser.error("--input/-i is required (or use --demo)")

    try:
        raw = Path(args.input).read_bytes()
        if raw.startswith(b"%PDF") or b"\x00" in raw:
            parser.error("input must be UTF-8 text; extract PDF/document text first")
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        parser.error(str(exc))

    extractor = IOCExtractor(defang=args.defang, include_private_ips=args.include_private)
    results = extractor.extract(text)

    if args.format == "csv":
        output_data = extractor.to_csv(results)
    elif args.format == "stix":
        output_data = json.dumps(extractor.to_stix(results), indent=2)
    else:
        output_data = json.dumps(results, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_data)
        logger.info("Results saved to %s", args.output)
    else:
        print(output_data)


if __name__ == "__main__":
    main()
