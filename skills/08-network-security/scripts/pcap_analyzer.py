#!/usr/bin/env python3
"""
PCAP Network Traffic Analyzer
Parses PCAP files for security-relevant network activity.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import os
import sys
import time
from collections import Counter, defaultdict
from typing import Any, Dict, List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    logger.warning("scapy not available. Install: pip install scapy")


class PCAPAnalyzer:
    """Network traffic analysis engine for PCAP files."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.packets = None
        self.results: Dict[str, Any] = {}

    def load(self) -> bool:
        """Load PCAP file."""
        if not HAS_SCAPY:
            logger.error("scapy required: pip install scapy")
            return False

        logger.info("[PCAP] Loading: %s", self.filepath)
        try:
            self.packets = rdpcap(self.filepath)
            logger.info("[PCAP] Loaded %d packets", len(self.packets))
            return True
        except Exception as e:
            logger.error("[PCAP] Load error: %s", str(e))
            return False

    def protocol_stats(self) -> Dict[str, int]:
        """Calculate protocol distribution statistics."""
        protocols = Counter()
        for pkt in self.packets:
            if pkt.haslayer(TCP):
                protocols["TCP"] += 1
            elif pkt.haslayer(UDP):
                protocols["UDP"] += 1
            if pkt.haslayer(DNS):
                protocols["DNS"] += 1
            if pkt.haslayer(HTTPRequest):
                protocols["HTTP"] += 1
            if pkt.haslayer(IP):
                protocols["IP"] += 1
        return dict(protocols)

    def top_talkers(self, n: int = 10) -> Dict[str, List]:
        """Identify top source and destination IPs by volume."""
        src_counter = Counter()
        dst_counter = Counter()
        conversations = Counter()

        for pkt in self.packets:
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                src_counter[src] += 1
                dst_counter[dst] += 1
                conversations[f"{src} -> {dst}"] += 1

        return {
            "top_sources": [{"ip": ip, "packets": count} for ip, count in src_counter.most_common(n)],
            "top_destinations": [{"ip": ip, "packets": count} for ip, count in dst_counter.most_common(n)],
            "top_conversations": [{"flow": flow, "packets": count} for flow, count in conversations.most_common(n)],
        }

    def extract_dns(self) -> Dict[str, Any]:
        """Extract DNS queries and responses."""
        queries = Counter()
        query_types = Counter()

        for pkt in self.packets:
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                queries[qname] += 1
                qtype = pkt[DNSQR].qtype
                type_map = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}
                query_types[type_map.get(qtype, str(qtype))] += 1

        # Detect suspicious DNS patterns
        suspicious = []
        for domain, count in queries.items():
            # Long domain names (potential DGA or tunneling)
            if len(domain) > 50:
                suspicious.append({"domain": domain, "reason": "Unusually long domain (possible tunneling/DGA)", "count": count})
            # High entropy subdomains
            if count > 100:
                suspicious.append({"domain": domain, "reason": "High query volume (possible beaconing)", "count": count})

        return {
            "total_queries": sum(queries.values()),
            "unique_domains": len(queries),
            "top_queried": [{"domain": d, "count": c} for d, c in queries.most_common(20)],
            "query_types": dict(query_types),
            "suspicious": suspicious,
        }

    @staticmethod
    def score_beacon(ip: str, times: List[float], threshold_count: int = 10) -> Dict:
        """Score one destination's timestamps for beaconing regularity.

        Pure function (no scapy) so the detection logic is unit-testable. Times
        are sorted first — capture order is not guaranteed monotonic, and an
        out-of-order list would otherwise yield bogus negative intervals.
        """
        if len(times) < threshold_count:
            return {}
        times = sorted(times)
        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        if not intervals:
            return {}
        avg_interval = sum(intervals) / len(intervals)
        if avg_interval <= 0:
            return {}
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        jitter = (variance ** 0.5) / avg_interval
        if jitter < 0.3 and avg_interval > 1:  # low jitter + steady cadence = beaconing
            return {
                "destination_ip": ip,
                "connection_count": len(times),
                "avg_interval_seconds": round(avg_interval, 2),
                "jitter_ratio": round(jitter, 4),
                "confidence": "HIGH" if jitter < 0.1 else "MEDIUM",
            }
        return {}

    def detect_beaconing(self, threshold_count: int = 10) -> List[Dict]:
        """Detect beaconing patterns (regular interval callbacks)."""
        ip_timestamps = defaultdict(list)
        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                ip_timestamps[pkt[IP].dst].append(float(pkt.time))

        beacons = [b for ip, times in ip_timestamps.items()
                   if (b := self.score_beacon(ip, times, threshold_count))]
        return sorted(beacons, key=lambda x: x["jitter_ratio"])

    def detect_port_scanning(self) -> List[Dict]:
        """Detect port scanning activity."""
        src_dst_ports = defaultdict(set)

        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                dport = pkt[TCP].dport
                src_dst_ports[f"{src}->{dst}"].add(dport)

        scanners = []
        for flow, ports in src_dst_ports.items():
            if len(ports) > 20:
                src, dst = flow.split("->")
                scanners.append({
                    "source": src,
                    "target": dst,
                    "unique_ports_scanned": len(ports),
                    "scan_type": "Horizontal" if len(ports) > 100 else "Targeted",
                })

        return sorted(scanners, key=lambda x: x["unique_ports_scanned"], reverse=True)

    def run(self, include_dns: bool = True, top_n: int = 10) -> Dict[str, Any]:
        """Execute full PCAP analysis."""
        if not self.load():
            return {"error": "Failed to load PCAP"}

        logger.info("=" * 60)
        logger.info("PCAP Analysis: %s", self.filepath)
        logger.info("=" * 60)

        self.results = {
            "file": os.path.basename(self.filepath),
            "file_size_bytes": os.path.getsize(self.filepath),
            "total_packets": len(self.packets),
            "protocol_stats": self.protocol_stats(),
            "top_talkers": self.top_talkers(top_n),
            "beaconing_detection": self.detect_beaconing(),
            "port_scan_detection": self.detect_port_scanning(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        if include_dns:
            self.results["dns_analysis"] = self.extract_dns()

        return self.results


def _run_demo() -> int:
    """Offline self-test of the beaconing scorer (no scapy / PCAP needed)."""
    # Perfectly periodic callbacks every 60s -> beacon; jittery/sparse -> not.
    periodic = [1000.0 + 60 * i for i in range(20)]
    # Out-of-order copy must give the same verdict (regression for the sort fix).
    shuffled = periodic[::-1]
    jittery = [1000.0, 1003.0, 1050.0, 1120.0, 1500.0, 2000.0, 2001.0, 3000.0, 3600.0, 4000.0, 9000.0]
    checks = [
        ("periodic detected as beacon", bool(PCAPAnalyzer.score_beacon("1.2.3.4", periodic))),
        ("out-of-order still detected", bool(PCAPAnalyzer.score_beacon("1.2.3.4", shuffled))),
        ("high confidence on zero jitter",
         PCAPAnalyzer.score_beacon("1.2.3.4", periodic).get("confidence") == "HIGH"),
        ("jittery not flagged", not PCAPAnalyzer.score_beacon("1.2.3.4", jittery)),
        ("too-few samples ignored", not PCAPAnalyzer.score_beacon("1.2.3.4", periodic[:5])),
    ]
    ok = all(p for _, p in checks)
    for label, p in checks:
        print(f"  [{'OK' if p else 'FAIL'}] {label}")
    print("[+] demo passed" if ok else "[!] demo FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(
        description="PCAP Network Traffic Analyzer",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--file", "-f", help="PCAP file to analyze")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--dns", action="store_true", default=True, help="Include DNS analysis")
    parser.add_argument("--top-talkers", type=int, default=10, help="Number of top talkers (default: 10)")
    parser.add_argument("--demo", action="store_true", help="Run an offline self-test and exit")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.demo:
        sys.exit(_run_demo())
    if not args.file:
        parser.error("--file/-f is required (or use --demo)")

    analyzer = PCAPAnalyzer(args.file)
    results = analyzer.run(include_dns=args.dns, top_n=args.top_talkers)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        logger.info("Results saved to %s", args.output)
    else:
        print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
