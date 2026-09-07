#!/usr/bin/env python3
"""
CTI Processor — extract, defang/refang, normalize, deduplicate, and score
indicators of compromise from raw threat reports, then export them as a
STIX 2.1 bundle or a MISP-style event with TLP and Admiralty source scoring.

Standard library only. Optional `requests` enables --enrich (live lookups).

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import ipaddress
import json
import logging
import re
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    requests = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

TLP_LEVELS = ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]

# Admiralty code: source reliability A-F, information credibility 1-6.
ADMIRALTY_RELIABILITY = set("ABCDEF")
ADMIRALTY_CREDIBILITY = set("123456")

# Ranges we drop as noise unless the user keeps them explicitly.
DOC_DOMAINS = {"example.com", "example.org", "example.net", "localhost", "test.com"}

# Extraction patterns. Applied after refanging, so they can assume clean text.
PATTERNS: Dict[str, re.Pattern] = {
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "url": re.compile(r"\bhttps?://[^\s<>\"'\])}]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6": re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
    "asn": re.compile(r"\bAS\d{2,7}\b", re.IGNORECASE),
    "btc": re.compile(r"\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "domain": re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
        r"(?:[A-Za-z]{2,24})\b"
    ),
}

# Kill-chain phase heuristics from surrounding keywords (best-effort).
KILL_CHAIN_HINTS = {
    "reconnaissance": ["scan", "recon", "enumerat"],
    "delivery": ["phish", "email", "attachment", "download", "dropper"],
    "exploitation": ["exploit", "cve-", "vulnerab", "rce"],
    "installation": ["persist", "install", "implant", "backdoor"],
    "command-and-control": ["c2", "c&c", "beacon", "callback", "command and control"],
    "actions-on-objectives": ["exfil", "ransom", "encrypt", "steal", "destroy"],
}


def refang(text: str) -> str:
    """Convert common defanged notations back to canonical form for parsing."""
    replacements = [
        (r"h(?:xx|XX)p", "http"),
        (r"\[\.\]", "."),
        (r"\(\.\)", "."),
        (r"\{\.\}", "."),
        (r"\[dot\]", "."),
        (r"\(dot\)", "."),
        (r"\s+dot\s+", "."),
        (r"\[@\]", "@"),
        (r"\[at\]", "@"),
        (r"\(at\)", "@"),
        (r"\[:\]", ":"),
        (r"\[//\]", "//"),
    ]
    out = text
    for pat, repl in replacements:
        out = re.sub(pat, repl, out, flags=re.IGNORECASE)
    return out


def defang(value: str, ioc_type: str) -> str:
    """Render an indicator safe to display in prose."""
    if ioc_type in ("domain", "url", "email", "ipv4"):
        value = value.replace(".", "[.]")
    if ioc_type == "url":
        value = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
    if ioc_type == "email":
        value = value.replace("@", "[@]")
    return value


def _is_noise_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True
    return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_link_local


def _valid_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def _guess_phase(text: str, span: Tuple[int, int]) -> Optional[str]:
    window = text[max(0, span[0] - 60): span[1] + 60].lower()
    for phase, hints in KILL_CHAIN_HINTS.items():
        if any(h in window for h in hints):
            return phase
    return None


def _confidence_for(ioc_type: str) -> str:
    # Hashes/CVEs are self-identifying; domains extracted by regex are noisier.
    if ioc_type in ("sha256", "sha1", "md5", "cve", "btc"):
        return "high"
    if ioc_type in ("url", "email", "ipv4", "ipv6", "asn"):
        return "medium"
    return "low"


class CTIProcessor:
    """Extracts and structures indicators from free-text threat reporting."""

    def __init__(self, keep_noise: bool = False, tlp: str = "AMBER",
                 source_score: Optional[str] = None) -> None:
        self.keep_noise = keep_noise
        self.tlp = tlp
        self.source_score = source_score
        self.indicators: List[Dict[str, Any]] = []

    def process(self, text: str) -> List[Dict[str, Any]]:
        """Run the full extract -> normalize -> dedup pipeline over `text`."""
        clean = refang(text)
        seen: Dict[Tuple[str, str], Dict[str, Any]] = {}

        # Order matters: consume hashes/urls/emails before bare ip/domain so the
        # broad patterns don't re-capture substrings of already-typed values.
        consumed_spans: List[Tuple[int, int]] = []

        def overlaps(span: Tuple[int, int]) -> bool:
            return any(span[0] < e and s < span[1] for s, e in consumed_spans)

        for ioc_type in ("url", "email", "sha256", "sha1", "md5", "cve",
                         "asn", "btc", "ipv6", "ipv4", "domain"):
            for match in PATTERNS[ioc_type].finditer(clean):
                raw = match.group(0)
                span = match.span()
                if ioc_type in ("domain", "ipv4", "ipv6") and overlaps(span):
                    continue
                normalized = self._normalize(raw, ioc_type)
                if normalized is None:
                    continue
                consumed_spans.append(span)
                key = (ioc_type, normalized)
                if key in seen:
                    seen[key]["count"] += 1
                    continue
                indicator = {
                    "type": ioc_type,
                    "value": normalized,
                    "defanged": defang(normalized, ioc_type),
                    "kill_chain_phase": _guess_phase(clean, span),
                    "confidence": _confidence_for(ioc_type),
                    "tlp": self.tlp,
                    "source_score": self.source_score,
                    "first_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "count": 1,
                }
                seen[key] = indicator

        self.indicators = list(seen.values())
        logger.info("Extracted %d unique indicator(s)", len(self.indicators))
        return self.indicators

    def _normalize(self, raw: str, ioc_type: str) -> Optional[str]:
        """Canonicalize and validate one raw match; return None to drop it."""
        value = raw.strip().strip(".,;:)")
        if ioc_type in ("md5", "sha1", "sha256"):
            return value.lower()
        if ioc_type == "cve":
            return value.upper()
        if ioc_type == "asn":
            return value.upper()
        if ioc_type == "ipv4":
            if not _valid_ipv4(value):
                return None
            if not self.keep_noise and _is_noise_ip(value):
                return None
            return value
        if ioc_type == "ipv6":
            try:
                return str(ipaddress.ip_address(value))
            except ValueError:
                return None
        if ioc_type == "email":
            local, _, dom = value.lower().rpartition("@")
            if not self.keep_noise and dom in DOC_DOMAINS:
                return None
            return f"{local}@{dom}"
        if ioc_type in ("domain", "url"):
            lowered = value.lower()
            host = lowered
            if ioc_type == "url":
                host = re.sub(r"^https?://", "", lowered).split("/")[0].split(":")[0]
            # A bare dotted-quad is an IP, not a domain — let the ip pattern own it.
            if ioc_type == "domain" and _valid_ipv4(host):
                return None
            if not self.keep_noise and host in DOC_DOMAINS:
                return None
            return lowered.rstrip("/") if ioc_type == "url" else lowered
        return value

    # ----- Exports -------------------------------------------------------

    def to_stix(self) -> Dict[str, Any]:
        """Build a minimal STIX 2.1 bundle of indicator SDOs + a TLP marking."""
        marking_id = f"marking-definition--{uuid.uuid4()}"
        objects: List[Dict[str, Any]] = [{
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": marking_id,
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "definition_type": "tlp",
            "name": f"TLP:{self.tlp}",
        }]
        stix_type_map = {
            "ipv4": "ipv4-addr", "ipv6": "ipv6-addr", "domain": "domain-name",
            "url": "url", "email": "email-addr", "md5": "file", "sha1": "file",
            "sha256": "file",
        }
        for ind in self.indicators:
            pattern = self._stix_pattern(ind, stix_type_map)
            if pattern is None:
                continue
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"{ind['type']}: {ind['value']}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ind["first_seen"],
                "confidence": {"low": 15, "medium": 50, "high": 85}[ind["confidence"]],
                "object_marking_refs": [marking_id],
                "labels": ["malicious-activity"],
            })
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}

    @staticmethod
    def _stix_pattern(ind: Dict[str, Any], type_map: Dict[str, str]) -> Optional[str]:
        stix_type = type_map.get(ind["type"])
        if stix_type is None:
            return None
        value = ind["value"]
        if ind["type"] in ("md5", "sha1", "sha256"):
            return f"[file:hashes.'{ind['type'].upper()}' = '{value}']"
        if ind["type"] == "email":
            return f"[email-addr:value = '{value}']"
        if ind["type"] == "url":
            return f"[url:value = '{value}']"
        if ind["type"] == "domain":
            return f"[domain-name:value = '{value}']"
        return f"[{stix_type}:value = '{value}']"

    def to_misp(self) -> Dict[str, Any]:
        """Build a MISP-style event dict (attributes list)."""
        misp_type = {
            "ipv4": "ip-dst", "ipv6": "ip-dst", "domain": "domain", "url": "url",
            "email": "email-src", "md5": "md5", "sha1": "sha1", "sha256": "sha256",
            "cve": "vulnerability", "asn": "AS", "btc": "btc",
        }
        attributes = [{
            "type": misp_type.get(ind["type"], "text"),
            "category": "Network activity" if ind["type"] in ("ipv4", "ipv6", "domain", "url")
            else "Payload delivery" if ind["type"] in ("md5", "sha1", "sha256")
            else "External analysis",
            "value": ind["value"],
            "to_ids": ind["confidence"] != "low",
            "comment": f"kill-chain={ind['kill_chain_phase'] or 'unknown'} "
                       f"confidence={ind['confidence']}",
        } for ind in self.indicators]
        return {
            "Event": {
                "info": "CTI Processor extracted indicators",
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "threat_level_id": "2",
                "analysis": "1",
                "distribution": "0",
                "Tag": [{"name": f'tlp:{self.tlp.lower()}'}],
                "Attribute": attributes,
            }
        }

    def enrich(self) -> None:
        """Best-effort live enrichment. No-op with a warning if requests missing."""
        if requests is None:
            logger.warning("requests not installed — skipping --enrich")
            return
        for ind in self.indicators:
            if ind["type"] != "domain":
                continue
            try:
                resp = requests.get(f"https://rdap.org/domain/{ind['value']}", timeout=8)
                if resp.ok:
                    data = resp.json()
                    ind["enrichment"] = {
                        "registrar": next(
                            (e.get("handle") for e in data.get("entities", [])), None),
                        "events": [ev.get("eventAction") for ev in data.get("events", [])],
                    }
            except Exception as exc:  # noqa: BLE001 - enrichment is best-effort
                logger.debug("Enrichment failed for %s: %s", ind["value"], exc)

    def summary(self) -> str:
        by_type: Dict[str, int] = {}
        for ind in self.indicators:
            by_type[ind["type"]] = by_type.get(ind["type"], 0) + 1
        lines = ["CTI Indicator Summary", "=" * 40,
                 f"TLP: {self.tlp}   Source score: {self.source_score or 'n/a'}",
                 f"Unique indicators: {len(self.indicators)}", ""]
        for t in sorted(by_type):
            lines.append(f"  {t:<8} {by_type[t]}")
        lines.append("")
        for ind in self.indicators:
            phase = ind["kill_chain_phase"] or "-"
            lines.append(f"  [{ind['confidence']:<6}] {ind['type']:<8} "
                         f"{ind['defanged']}  ({phase})")
        return "\n".join(lines)


SAMPLE_REPORT = """
Threat report: The actor sent a phishing email from admin[at]evil-corp[.]xyz
with an attachment that dropped a loader (SHA256:
9f2c1c4b0e5a8d3f6b7c9e1a2d4f6b8c0a1e3d5f7b9c1e3a5d7f9b1c3e5a7d9f).
On execution it beaconed to hxxps://malicious-c2[.]example-bad[.]tld/gate.php
and 185[.]220[.]101[.]45 over C2. It exploited CVE-2024-3400 for initial access.
Related infrastructure: bad-domain[.]top resolving via AS64512.
Ransom note referenced BTC address bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh.
Ignore noise like 127.0.0.1 and example.com.
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CTI Processor — extract, normalize, score, and export IOCs.",
        epilog=(
            "Examples:\n"
            "  cti_processor.py --input report.txt --stix out.json\n"
            "  cti_processor.py --input report.txt --tlp AMBER --source-score B2 --misp event.json\n"
            "  cti_processor.py --demo"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", "-i", help="Path to a text/report file to process")
    parser.add_argument("--output", "-o", help="Write the structured indicator list as JSON")
    parser.add_argument("--stix", help="Write a STIX 2.1 bundle to this path")
    parser.add_argument("--misp", help="Write a MISP-style event to this path")
    parser.add_argument("--tlp", choices=TLP_LEVELS, default="AMBER",
                        help="TLP marking applied to every indicator (default: AMBER)")
    parser.add_argument("--source-score",
                        help="Admiralty source score, e.g. B2 (reliability A-F + credibility 1-6)")
    parser.add_argument("--keep-noise", action="store_true",
                        help="Keep private/documentation indicators instead of dropping them")
    parser.add_argument("--enrich", action="store_true",
                        help="Best-effort live enrichment of domains (needs `requests`)")
    parser.add_argument("--demo", action="store_true",
                        help="Run against a bundled sample report")
    args = parser.parse_args()

    if args.source_score:
        score = args.source_score.upper()
        if (len(score) != 2 or score[0] not in ADMIRALTY_RELIABILITY
                or score[1] not in ADMIRALTY_CREDIBILITY):
            parser.error("--source-score must be a letter A-F followed by a digit 1-6, e.g. B2")

    if args.demo:
        text = SAMPLE_REPORT
    elif args.input:
        try:
            with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            logger.error("Could not read %s: %s", args.input, exc)
            return 1
    else:
        parser.error("provide --input <file> or --demo")
        return 2  # unreachable; parser.error exits

    processor = CTIProcessor(keep_noise=args.keep_noise, tlp=args.tlp,
                             source_score=args.source_score)
    processor.process(text)
    if args.enrich:
        processor.enrich()

    print(processor.summary())

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(processor.indicators, fh, indent=2)
        logger.info("Indicators written to %s", args.output)
    if args.stix:
        with open(args.stix, "w", encoding="utf-8") as fh:
            json.dump(processor.to_stix(), fh, indent=2)
        logger.info("STIX bundle written to %s", args.stix)
    if args.misp:
        with open(args.misp, "w", encoding="utf-8") as fh:
            json.dump(processor.to_misp(), fh, indent=2)
        logger.info("MISP event written to %s", args.misp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
