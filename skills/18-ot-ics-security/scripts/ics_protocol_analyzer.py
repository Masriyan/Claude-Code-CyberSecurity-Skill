#!/usr/bin/env python3
"""
ics_protocol_analyzer.py — Passive ICS/SCADA traffic summarizer & exposure dork generator.

Two modes:
  (1) PCAP summary: read a tshark JSON export, identify industrial protocols,
      list talkers, and FLAG control/write operations (the dangerous ones).
  (2) Dork mode: emit read-only Shodan/Censys queries to find externally
      exposed ICS devices for a given vendor/protocol.

Designed for passive, safety-first OT assessment. It never touches the network.

Usage:
    tshark -r capture.pcap -T json > capture.json
    python ics_protocol_analyzer.py --input capture.json --output report.json
    python ics_protocol_analyzer.py --dorks --vendor siemens --output dorks.txt
"""
import argparse
import json
import sys
from collections import Counter, defaultdict

# protocol -> (well-known port, default risk note)
ICS_PORTS = {
    502: "Modbus/TCP",
    20000: "DNP3",
    102: "S7comm (Siemens)",
    44818: "EtherNet/IP (CIP)",
    2222: "EtherNet/IP I/O",
    4840: "OPC-UA",
    47808: "BACnet/IP",
    2404: "IEC 60870-5-104",
    789: "Red Lion / Crimson",
    1911: "Niagara Fox",
    9600: "OMRON FINS",
}

# Modbus write/control function codes (the risky ones)
MODBUS_WRITE_FC = {5: "Write Single Coil", 6: "Write Single Register",
                   15: "Write Multiple Coils", 16: "Write Multiple Registers",
                   8: "Diagnostics", 43: "Encapsulated Interface"}

DORK_TEMPLATES = {
    "shodan": [
        'port:502', 'port:20000 source address', 'port:102',
        'port:44818', 'port:47808', 'port:4840', 'tag:ics', 'tag:scada',
    ],
    "censys": [
        'services.port=502', 'services.port=20000', 'services.port=44818',
        'services.service_name=MODBUS', 'services.service_name=S7',
    ],
}
VENDOR_DORKS = {
    "siemens": ['"Siemens"', '"SIMATIC"', 'port:102'],
    "schneider": ['"Schneider Electric"', '"Modicon"', 'port:502'],
    "rockwell": ['"Rockwell"', '"Allen-Bradley"', 'port:44818'],
    "ge": ['"General Electric"', 'port:18245'],
    "omron": ['"OMRON"', 'port:9600'],
}


def get_layers(pkt):
    # tshark -T json wraps each packet as {"_source": {"layers": {...}}}
    return pkt.get("_source", {}).get("layers", {}) if isinstance(pkt, dict) else {}


def first(d, *keys):
    for k in keys:
        if k in d:
            v = d[k]
            return v[0] if isinstance(v, list) else v
    return None


def analyze_pcap(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        packets = json.load(fh)
    if not isinstance(packets, list):
        packets = [packets]

    proto_count = Counter()
    talkers = Counter()
    flows = defaultdict(Counter)
    control_ops = []

    for pkt in packets:
        layers = get_layers(pkt)
        ip = layers.get("ip", {})
        tcp = layers.get("tcp", {})
        src = first(ip, "ip.src")
        dst = first(ip, "ip.dst")
        dport = first(tcp, "tcp.dstport")
        sport = first(tcp, "tcp.srcport")

        proto = None
        for p in (dport, sport):
            try:
                pi = int(p) if p is not None else None
            except (TypeError, ValueError):
                pi = None
            if pi in ICS_PORTS:
                proto = ICS_PORTS[pi]
                break
        if not proto:
            continue

        proto_count[proto] += 1
        if src:
            talkers[src] += 1
        if src and dst:
            flows[(src, dst)][proto] += 1

        # Modbus write detection
        mb = layers.get("modbus")
        if mb:
            fc = first(mb if isinstance(mb, dict) else {}, "modbus.func_code")
            try:
                fci = int(fc) if fc is not None else None
            except (TypeError, ValueError):
                fci = None
            if fci in MODBUS_WRITE_FC:
                control_ops.append({"proto": "Modbus", "src": src, "dst": dst,
                                    "op": MODBUS_WRITE_FC[fci], "fc": fci})
        # S7 / DNP3 presence is itself notable for control segments
        if proto.startswith("S7") and src and dst:
            control_ops.append({"proto": "S7comm", "src": src, "dst": dst,
                                "op": "S7 job/userdata (possible program op)"})

    return {
        "protocols": dict(proto_count),
        "top_talkers": talkers.most_common(15),
        "flows": [{"src": s, "dst": d, "protocols": dict(c)} for (s, d), c in flows.items()],
        "control_operations": control_ops,
    }


def emit_dorks(vendor: str | None) -> list[str]:
    out = ["# Read-only ICS exposure dorks — verify authorization before acting", ""]
    out.append("## Shodan")
    out += DORK_TEMPLATES["shodan"]
    out.append("")
    out.append("## Censys")
    out += DORK_TEMPLATES["censys"]
    if vendor and vendor.lower() in VENDOR_DORKS:
        out.append("")
        out.append(f"## Vendor: {vendor}")
        out += VENDOR_DORKS[vendor.lower()]
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Passive ICS protocol analyzer / exposure dork generator")
    ap.add_argument("--input", help="tshark JSON export of a capture")
    ap.add_argument("--dorks", action="store_true", help="Emit exposure dorks instead of analyzing a PCAP")
    ap.add_argument("--vendor", help="Vendor for dork mode (siemens, schneider, rockwell, ge, omron)")
    ap.add_argument("--output", help="Write output (JSON for analysis, text for dorks)")
    args = ap.parse_args()

    if args.dorks:
        lines = emit_dorks(args.vendor)
        print("\n".join(lines))
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            print(f"\n[+] Wrote {args.output}")
        return

    if not args.input:
        print("[!] Provide --input <tshark.json> or use --dorks", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Analyzing {args.input} (passive)\n")
    r = analyze_pcap(args.input)

    print("  Industrial protocols seen:")
    for p, c in sorted(r["protocols"].items(), key=lambda x: -x[1]):
        print(f"    {p:<22} {c} pkts")
    print(f"\n  Control/write operations flagged: {len(r['control_operations'])}")
    for op in r["control_operations"][:15]:
        print(f"    [!] {op['proto']:<8} {op.get('src')} -> {op.get('dst')}  {op['op']}")
    if not r["control_operations"]:
        print("    (none detected — confirm capture covered control traffic)")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(r, fh, indent=2)
        print(f"\n[+] Wrote {args.output}")


if __name__ == "__main__":
    main()
