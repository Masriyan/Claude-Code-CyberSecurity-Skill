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
import logging
import sys
from collections import Counter, defaultdict

logger = logging.getLogger("ics_protocol_analyzer")

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
                   8: "Diagnostics", 43: "Encapsulated Interface",
                   22: "Mask Write Register", 23: "Read/Write Multiple Registers"}

# S7comm parameter functions that change PLC state (vs. benign reads/setup).
S7_CONTROL_FUNC = {
    0x05: "Write Var", 0x1a: "Request Download", 0x1b: "Download Block",
    0x1c: "Download Ended", 0x1d: "Start Upload", 0x1e: "Upload",
    0x1f: "End Upload", 0x28: "PLC Control (e.g. start/PI service)",
    0x29: "PLC Stop",
}

# DNP3 application-layer function codes that command or restart the outstation.
DNP3_CONTROL_FUNC = {
    3: "Select", 4: "Operate", 5: "Direct Operate", 6: "Direct Operate (no ack)",
    13: "Cold Restart", 14: "Warm Restart", 18: "Stop Application",
    1: "Write", 15: "Initialize Data", 16: "Initialize Application",
}

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


def _as_int(val):
    """Coerce a tshark field (decimal or '0x..' string) to int, else None."""
    if val is None:
        return None
    try:
        return int(str(val), 0) if str(val).lower().startswith("0x") else int(val)
    except (TypeError, ValueError):
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
        if isinstance(mb, dict):
            fci = _as_int(first(mb, "modbus.func_code"))
            if fci in MODBUS_WRITE_FC:
                control_ops.append({"proto": "Modbus", "src": src, "dst": dst,
                                    "op": MODBUS_WRITE_FC[fci], "fc": fci})

        # S7comm: flag only state-changing parameter functions, not every packet.
        s7 = layers.get("s7comm")
        if isinstance(s7, dict):
            func = _as_int(first(s7, "s7comm.param.func"))
            if func in S7_CONTROL_FUNC:
                control_ops.append({"proto": "S7comm", "src": src, "dst": dst,
                                    "op": S7_CONTROL_FUNC[func], "func": func})

        # DNP3: flag application-layer control/restart functions.
        dnp3 = layers.get("dnp3")
        if isinstance(dnp3, dict):
            afunc = _as_int(first(dnp3, "dnp3.al.func"))
            if afunc in DNP3_CONTROL_FUNC:
                control_ops.append({"proto": "DNP3", "src": src, "dst": dst,
                                    "op": DNP3_CONTROL_FUNC[afunc], "func": afunc})

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


_DEMO_PACKETS = [
    {"_source": {"layers": {"ip": {"ip.src": "10.0.0.5", "ip.dst": "10.0.1.10"},
                            "tcp": {"tcp.dstport": "502"},
                            "modbus": {"modbus.func_code": "16"}}}},
    {"_source": {"layers": {"ip": {"ip.src": "10.0.0.5", "ip.dst": "10.0.1.11"},
                            "tcp": {"tcp.dstport": "102"},
                            "s7comm": {"s7comm.param.func": "0x29"}}}},
    {"_source": {"layers": {"ip": {"ip.src": "10.0.0.6", "ip.dst": "10.0.1.12"},
                            "tcp": {"tcp.dstport": "20000"},
                            "dnp3": {"dnp3.al.func": "4"}}}},
    {"_source": {"layers": {"ip": {"ip.src": "10.0.0.7", "ip.dst": "10.0.1.11"},
                            "tcp": {"tcp.dstport": "102"},
                            "s7comm": {"s7comm.param.func": "0x04"}}}},  # Read Var — benign, must NOT flag
]


def _run_demo() -> int:
    """Offline self-test using synthetic tshark-shaped packets (no capture needed)."""
    import tempfile
    import os
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(_DEMO_PACKETS, fh)
        tmp = fh.name
    try:
        r = analyze_pcap(tmp)
    finally:
        os.unlink(tmp)
    ops = {(o["proto"], o["op"]) for o in r["control_operations"]}
    expected = {("Modbus", "Write Multiple Registers"), ("S7comm", "PLC Stop"), ("DNP3", "Operate")}
    ok = ops == expected  # the benign S7 Read Var must be absent
    print(f"  control ops: {sorted(ops)}")
    print(f"  protocols:   {r['protocols']}")
    print("[+] demo passed" if ok else f"[!] demo FAILED (expected {sorted(expected)})")
    return 0 if ok else 1


def main() -> None:
    ap = argparse.ArgumentParser(description="Passive ICS protocol analyzer / exposure dork generator")
    ap.add_argument("--input", help="tshark JSON export of a capture")
    ap.add_argument("--dorks", action="store_true", help="Emit exposure dorks instead of analyzing a PCAP")
    ap.add_argument("--vendor", help="Vendor for dork mode (siemens, schneider, rockwell, ge, omron)")
    ap.add_argument("--output", help="Write output (JSON for analysis, text for dorks)")
    ap.add_argument("--demo", action="store_true", help="Run an offline self-test and exit")
    ap.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")

    if args.demo:
        sys.exit(_run_demo())

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
