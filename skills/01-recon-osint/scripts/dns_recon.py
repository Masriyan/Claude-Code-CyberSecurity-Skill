#!/usr/bin/env python3
"""
DNS Reconnaissance Tool
Comprehensive DNS record analysis and misconfiguration detection.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import sys
import time
from typing import Any, Dict, List, Optional

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.reversename
except ImportError:
    print("[!] 'dnspython' module required: pip install dnspython")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class DNSRecon:
    """Comprehensive DNS reconnaissance engine."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "SRV", "CNAME", "CAA", "PTR"]

    def __init__(self, domain: str, nameserver: Optional[str] = None, timeout: int = 5):
        self.domain = domain.lower().strip()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        if nameserver:
            self.resolver.nameservers = [nameserver]
        self.results: Dict[str, Any] = {"domain": self.domain, "records": {}}

    def enumerate_records(self) -> Dict[str, List[str]]:
        """Enumerate all DNS record types."""
        logger.info("[DNS] Enumerating records for %s", self.domain)
        records = {}
        for rtype in self.RECORD_TYPES:
            try:
                answers = self.resolver.resolve(self.domain, rtype)
                records[rtype] = [str(r) for r in answers]
                logger.info("[DNS] %s records: %d found", rtype, len(records[rtype]))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                records[rtype] = []
            except Exception as e:
                logger.debug("[DNS] %s lookup error: %s", rtype, str(e))
                records[rtype] = []
        self.results["records"] = records
        return records

    def check_zone_transfer(self) -> Dict[str, Any]:
        """Attempt AXFR zone transfer on all nameservers."""
        logger.info("[AXFR] Testing zone transfer for %s", self.domain)
        axfr_results = {"vulnerable": False, "nameservers": {}}
        try:
            ns_answers = self.resolver.resolve(self.domain, "NS")
            for ns in ns_answers:
                ns_host = str(ns).rstrip(".")
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_host, self.domain, timeout=5)
                    )
                    zone_records = []
                    for name, node in zone.nodes.items():
                        zone_records.append(str(name))
                    axfr_results["vulnerable"] = True
                    axfr_results["nameservers"][ns_host] = {
                        "status": "VULNERABLE",
                        "records_count": len(zone_records),
                        "records": zone_records[:50],
                    }
                    logger.warning("[AXFR] Zone transfer SUCCESSFUL on %s!", ns_host)
                except Exception:
                    axfr_results["nameservers"][ns_host] = {"status": "REFUSED"}
                    logger.info("[AXFR] Zone transfer refused on %s", ns_host)
        except Exception as e:
            logger.error("[AXFR] Error: %s", str(e))

        self.results["zone_transfer"] = axfr_results
        return axfr_results

    def analyze_email_security(self) -> Dict[str, Any]:
        """Analyze SPF, DKIM, and DMARC records."""
        logger.info("[Email] Analyzing email security for %s", self.domain)
        email_security = {"spf": None, "dmarc": None, "dkim_selector_test": None}

        # SPF
        try:
            txt_records = self.resolver.resolve(self.domain, "TXT")
            for record in txt_records:
                text = str(record).strip('"')
                if text.startswith("v=spf1"):
                    email_security["spf"] = {
                        "record": text,
                        "mechanisms": self._parse_spf(text),
                    }
                    break
        except Exception:
            pass

        # DMARC
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            dmarc_records = self.resolver.resolve(dmarc_domain, "TXT")
            for record in dmarc_records:
                text = str(record).strip('"')
                if text.startswith("v=DMARC1"):
                    email_security["dmarc"] = {
                        "record": text,
                        "policy": self._parse_dmarc(text),
                    }
                    break
        except Exception:
            pass

        # DKIM (common selectors)
        selectors = ["default", "google", "selector1", "selector2", "mail", "dkim"]
        for selector in selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{self.domain}"
                dkim_records = self.resolver.resolve(dkim_domain, "TXT")
                email_security["dkim_selector_test"] = {
                    "selector": selector,
                    "found": True,
                    "record": str(list(dkim_records)[0]).strip('"')[:200],
                }
                break
            except Exception:
                continue

        # Security assessment
        issues = []
        if not email_security["spf"]:
            issues.append("No SPF record found — domain vulnerable to email spoofing")
        if not email_security["dmarc"]:
            issues.append("No DMARC record found — no email authentication policy")
        elif email_security["dmarc"]["policy"].get("p") == "none":
            issues.append("DMARC policy set to 'none' — no enforcement")

        email_security["issues"] = issues
        self.results["email_security"] = email_security
        return email_security

    def _parse_spf(self, record: str) -> Dict[str, Any]:
        """Parse SPF record into components."""
        parts = record.split()
        return {
            "version": parts[0] if parts else "",
            "mechanisms": [p for p in parts[1:] if not p.startswith("~") and not p.startswith("-")],
            "all_policy": parts[-1] if parts and parts[-1] in ["+all", "-all", "~all", "?all"] else "unknown",
        }

    def _parse_dmarc(self, record: str) -> Dict[str, str]:
        """Parse DMARC record into components."""
        policy = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                policy[key.strip()] = value.strip()
        return policy

    def reverse_dns(self, ip_addresses: List[str]) -> Dict[str, str]:
        """Perform reverse DNS lookups."""
        logger.info("[rDNS] Performing reverse lookups on %d IPs", len(ip_addresses))
        rdns_results = {}
        for ip in ip_addresses:
            try:
                rev_name = dns.reversename.from_address(ip)
                answers = self.resolver.resolve(rev_name, "PTR")
                rdns_results[ip] = str(list(answers)[0]).rstrip(".")
            except Exception:
                rdns_results[ip] = "No PTR record"
        self.results["reverse_dns"] = rdns_results
        return rdns_results

    def run(self, check_axfr: bool = True) -> Dict[str, Any]:
        """Execute full DNS reconnaissance."""
        logger.info("=" * 60)
        logger.info("DNS Reconnaissance: %s", self.domain)
        logger.info("=" * 60)

        self.enumerate_records()
        if check_axfr:
            self.check_zone_transfer()
        self.analyze_email_security()

        # Reverse DNS on discovered A records
        a_records = self.results["records"].get("A", [])
        if a_records:
            self.reverse_dns(a_records)

        self.results["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return self.results


def main():
    parser = argparse.ArgumentParser(
        description="DNS Reconnaissance Tool",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--domain", "-d", required=True, help="Target domain")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--nameserver", "-n", help="Custom nameserver")
    parser.add_argument("--timeout", type=int, default=5, help="DNS timeout (default: 5)")
    parser.add_argument("--check-zone-transfer", action="store_true", default=True, help="Test zone transfers")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    recon = DNSRecon(domain=args.domain, nameserver=args.nameserver, timeout=args.timeout)
    results = recon.run(check_axfr=args.check_zone_transfer)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("Results saved to %s", args.output)
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
