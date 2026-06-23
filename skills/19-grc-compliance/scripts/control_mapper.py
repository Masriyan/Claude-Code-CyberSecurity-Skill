#!/usr/bin/env python3
"""
control_mapper.py — Cross-framework security control crosswalk.

Given a control concept (or a NIST CSF 2.0 subcategory), shows the corresponding
requirements across ISO/IEC 27001:2022 Annex A, SOC 2 Trust Services Criteria,
NIST SP 800-53 Rev.5, CIS Controls v8, and PCI DSS 4.0 — so a single piece of
evidence can be mapped to many obligations.

This is a curated starter crosswalk for the most common control domains, not an
exhaustive mapping. Validate against the authoritative standard before audit.

Usage:
    python control_mapper.py --control "access control"
    python control_mapper.py --csf PR.AA --frameworks iso27001,soc2
    python control_mapper.py --list
"""
import argparse
import json
import sys

# domain -> {csf, iso27001, soc2, nist80053, cis_v8, pci_dss}
CROSSWALK = {
    "access control": {
        "csf": ["PR.AA-01", "PR.AA-05"],
        "iso27001": ["A.5.15 Access control", "A.5.18 Access rights", "A.8.2 Privileged access"],
        "soc2": ["CC6.1", "CC6.2", "CC6.3"],
        "nist80053": ["AC-2", "AC-3", "AC-6"],
        "cis_v8": ["6 Access Control Management"],
        "pci_dss": ["7 Restrict access", "8 Identify & authenticate"],
    },
    "mfa": {
        "csf": ["PR.AA-03"],
        "iso27001": ["A.5.17 Authentication information", "A.8.5 Secure authentication"],
        "soc2": ["CC6.1"],
        "nist80053": ["IA-2(1)", "IA-2(2)"],
        "cis_v8": ["6.3 Require MFA for externally-exposed apps", "6.4 MFA for remote access"],
        "pci_dss": ["8.4 MFA", "8.5 MFA systems"],
    },
    "logging and monitoring": {
        "csf": ["DE.CM-01", "DE.AE-03"],
        "iso27001": ["A.8.15 Logging", "A.8.16 Monitoring activities"],
        "soc2": ["CC7.2", "CC7.3"],
        "nist80053": ["AU-2", "AU-6", "SI-4"],
        "cis_v8": ["8 Audit Log Management"],
        "pci_dss": ["10 Log and monitor all access"],
    },
    "vulnerability management": {
        "csf": ["ID.RA-01", "PR.PS-02"],
        "iso27001": ["A.8.8 Management of technical vulnerabilities"],
        "soc2": ["CC7.1"],
        "nist80053": ["RA-5", "SI-2"],
        "cis_v8": ["7 Continuous Vulnerability Management"],
        "pci_dss": ["6 Develop secure systems", "11 Test security regularly"],
    },
    "incident response": {
        "csf": ["RS.MA-01", "RS.AN-03", "RC.RP-01"],
        "iso27001": ["A.5.24 IR planning", "A.5.26 Response to incidents"],
        "soc2": ["CC7.4", "CC7.5"],
        "nist80053": ["IR-4", "IR-6", "IR-8"],
        "cis_v8": ["17 Incident Response Management"],
        "pci_dss": ["12.10 Incident response plan"],
    },
    "data protection": {
        "csf": ["PR.DS-01", "PR.DS-02"],
        "iso27001": ["A.8.10 Information deletion", "A.8.11 Data masking", "A.8.24 Cryptography"],
        "soc2": ["CC6.7", "C1.1", "C1.2"],
        "nist80053": ["SC-13", "SC-28", "MP-6"],
        "cis_v8": ["3 Data Protection"],
        "pci_dss": ["3 Protect stored account data", "4 Protect data in transit"],
    },
    "change management": {
        "csf": ["PR.PS-01", "ID.AM-08"],
        "iso27001": ["A.8.32 Change management"],
        "soc2": ["CC8.1"],
        "nist80053": ["CM-3", "CM-4"],
        "cis_v8": ["4 Secure Configuration"],
        "pci_dss": ["6.5 Change control"],
    },
    "risk assessment": {
        "csf": ["ID.RA-01", "GV.RM-01"],
        "iso27001": ["Clause 6.1.2 Risk assessment", "Clause 8.2"],
        "soc2": ["CC3.1", "CC3.2", "CC3.4"],
        "nist80053": ["RA-3", "PM-9"],
        "cis_v8": ["—"],
        "pci_dss": ["12.3 Risk analysis"],
    },
    "vendor risk": {
        "csf": ["GV.SC-01", "ID.RA-10"],
        "iso27001": ["A.5.19 Supplier relationships", "A.5.21 ICT supply chain"],
        "soc2": ["CC9.2"],
        "nist80053": ["SR-3", "SR-6"],
        "cis_v8": ["15 Service Provider Management"],
        "pci_dss": ["12.8 Manage TPSPs"],
    },
}

# NIST CSF 2.0 subcategory -> domain key (for --csf lookups)
CSF_INDEX = {}
for _domain, _m in CROSSWALK.items():
    for _sub in _m["csf"]:
        CSF_INDEX[_sub.upper()] = _domain

FRAMEWORK_LABELS = {
    "csf": "NIST CSF 2.0", "iso27001": "ISO/IEC 27001:2022",
    "soc2": "SOC 2 TSC", "nist80053": "NIST SP 800-53r5",
    "cis_v8": "CIS Controls v8", "pci_dss": "PCI DSS 4.0",
}


def resolve(control: str | None, csf: str | None) -> tuple[str, dict] | None:
    if csf:
        key = CSF_INDEX.get(csf.upper())
        if key:
            return key, CROSSWALK[key]
        # allow function prefix like "PR" -> first match
        for sub, dom in CSF_INDEX.items():
            if sub.startswith(csf.upper()):
                return dom, CROSSWALK[dom]
        return None
    if control:
        c = control.lower().strip()
        if c in CROSSWALK:
            return c, CROSSWALK[c]
        for k in CROSSWALK:
            if c in k or k in c:
                return k, CROSSWALK[k]
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description="Cross-framework control crosswalk")
    ap.add_argument("--control", help='Control concept, e.g. "access control", "mfa", "logging and monitoring"')
    ap.add_argument("--csf", help="NIST CSF 2.0 subcategory or function prefix, e.g. PR.AA-01 or DE")
    ap.add_argument("--frameworks", default="all", help="Comma list: csf,iso27001,soc2,nist80053,cis_v8,pci_dss or 'all'")
    ap.add_argument("--list", action="store_true", help="List available control domains")
    ap.add_argument("--output", help="Write JSON")
    args = ap.parse_args()

    if args.list:
        print("Available control domains:")
        for k in CROSSWALK:
            print(f"  - {k}")
        return

    if not (args.control or args.csf):
        print("[!] Provide --control or --csf (or --list)", file=sys.stderr)
        sys.exit(1)

    res = resolve(args.control, args.csf)
    if not res:
        print("[!] No mapping found. Try --list for available domains.", file=sys.stderr)
        sys.exit(1)
    domain, mapping = res

    wanted = list(FRAMEWORK_LABELS) if args.frameworks == "all" else \
        [f.strip() for f in args.frameworks.split(",")]

    print(f"\n=== Crosswalk: {domain.upper()} ===\n")
    out = {"domain": domain, "mapping": {}}
    for fw in wanted:
        if fw not in mapping:
            continue
        label = FRAMEWORK_LABELS.get(fw, fw)
        print(f"  {label}:")
        for item in mapping[fw]:
            print(f"    - {item}")
        out["mapping"][fw] = mapping[fw]
        print()

    print("  Note: starter crosswalk — validate against the authoritative standard before audit.")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(f"\n[+] Wrote {args.output}")


if __name__ == "__main__":
    main()
