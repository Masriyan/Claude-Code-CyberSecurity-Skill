#!/usr/bin/env python3
"""
Subdomain Enumeration Tool
Discovers subdomains using passive and active techniques.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("[!] 'requests' module required: pip install requests")
    sys.exit(1)

try:
    import dns.resolver
    import dns.query
    import dns.zone
except ImportError:
    print("[!] 'dnspython' module required: pip install dnspython")
    sys.exit(1)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class SubdomainEnumerator:
    """Multi-method subdomain enumeration engine."""

    def __init__(
        self,
        domain: str,
        threads: int = 10,
        timeout: int = 5,
        nameserver: Optional[str] = None,
    ):
        self.domain = domain.lower().strip()
        self.threads = threads
        self.timeout = timeout
        self.discovered: Set[str] = set()
        self.resolved: Dict[str, List[str]] = {}
        self.resolver = dns.resolver.Resolver()
        if nameserver:
            self.resolver.nameservers = [nameserver]
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "Mozilla/5.0 (compatible; SecurityRecon/1.0)"}
        )

    def enumerate_ct_logs(self) -> Set[str]:
        """Query Certificate Transparency logs via crt.sh."""
        logger.info("[CT Logs] Querying crt.sh for %s", self.domain)
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url, timeout=self.timeout * 3)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{self.domain}") or sub == self.domain:
                            if "*" not in sub:
                                subdomains.add(sub)
                logger.info("[CT Logs] Found %d subdomains", len(subdomains))
        except Exception as e:
            logger.warning("[CT Logs] Error: %s", str(e))
        return subdomains

    def enumerate_dns_records(self) -> Set[str]:
        """Extract subdomains from standard DNS records."""
        logger.info("[DNS] Enumerating DNS records for %s", self.domain)
        subdomains = set()
        record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "SRV"]

        for rtype in record_types:
            try:
                answers = self.resolver.resolve(self.domain, rtype)
                for answer in answers:
                    text = str(answer).lower().rstrip(".")
                    if self.domain in text:
                        subdomains.add(text)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            except Exception as e:
                logger.debug("[DNS] %s lookup error: %s", rtype, str(e))

        logger.info("[DNS] Found %d subdomains from records", len(subdomains))
        return subdomains

    def check_zone_transfer(self) -> Set[str]:
        """Attempt zone transfer (AXFR) on nameservers."""
        logger.info("[AXFR] Attempting zone transfer for %s", self.domain)
        subdomains = set()
        try:
            ns_answers = self.resolver.resolve(self.domain, "NS")
            for ns in ns_answers:
                ns_host = str(ns).rstrip(".")
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_host, self.domain, timeout=self.timeout)
                    )
                    for name, node in zone.nodes.items():
                        subdomain = f"{name}.{self.domain}".lower()
                        subdomains.add(subdomain)
                    logger.warning("[AXFR] Zone transfer SUCCESSFUL on %s!", ns_host)
                except Exception:
                    logger.debug("[AXFR] Zone transfer failed on %s", ns_host)
        except Exception as e:
            logger.debug("[AXFR] NS lookup error: %s", str(e))

        return subdomains

    def _resolve_subdomain(self, subdomain: str) -> Optional[str]:
        """Resolve a single subdomain to IP address(es)."""
        try:
            answers = self.resolver.resolve(subdomain, "A")
            ips = [str(r) for r in answers]
            return subdomain, ips
        except Exception:
            return None

    def _bruteforce_single(self, word: str) -> Optional[str]:
        """Test a single subdomain candidate."""
        subdomain = f"{word}.{self.domain}"
        result = self._resolve_subdomain(subdomain)
        if result:
            return result
        return None

    def bruteforce(self, wordlist_path: str) -> Set[str]:
        """Brute-force subdomain enumeration using a wordlist."""
        logger.info("[Brute] Starting brute-force with wordlist: %s", wordlist_path)
        subdomains = set()

        try:
            with open(wordlist_path, "r") as f:
                words = [line.strip().lower() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error("[Brute] Wordlist not found: %s", wordlist_path)
            return subdomains

        logger.info("[Brute] Testing %d candidates with %d threads", len(words), self.threads)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._bruteforce_single, w): w for w in words}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomain, ips = result
                    subdomains.add(subdomain)
                    self.resolved[subdomain] = ips
                    logger.info("[Brute] Found: %s -> %s", subdomain, ", ".join(ips))

        logger.info("[Brute] Discovered %d subdomains via brute-force", len(subdomains))
        return subdomains

    def detect_wildcard(self) -> bool:
        """Detect wildcard DNS resolution."""
        random_sub = f"randomnonexistent12345.{self.domain}"
        try:
            answers = self.resolver.resolve(random_sub, "A")
            logger.warning("[Wildcard] Wildcard DNS detected! Random subdomain resolves.")
            return True
        except Exception:
            return False

    def resolve_all(self) -> Dict[str, List[str]]:
        """Resolve all discovered subdomains to IPs."""
        logger.info("[Resolve] Resolving %d subdomains", len(self.discovered))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._resolve_subdomain, sub): sub
                for sub in self.discovered
                if sub not in self.resolved
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomain, ips = result
                    self.resolved[subdomain] = ips

        return self.resolved

    def run(
        self, wordlist: Optional[str] = None, passive_only: bool = False
    ) -> Dict:
        """Execute full enumeration pipeline."""
        logger.info("=" * 60)
        logger.info("Subdomain Enumeration: %s", self.domain)
        logger.info("=" * 60)

        # Wildcard check
        has_wildcard = self.detect_wildcard()

        # Passive enumeration
        self.discovered.update(self.enumerate_ct_logs())
        self.discovered.update(self.enumerate_dns_records())
        self.discovered.update(self.check_zone_transfer())

        # Active enumeration
        if not passive_only and wordlist:
            self.discovered.update(self.bruteforce(wordlist))

        # Resolve all
        self.resolve_all()

        # Build results
        results = {
            "domain": self.domain,
            "wildcard_detected": has_wildcard,
            "total_discovered": len(self.discovered),
            "total_resolved": len(self.resolved),
            "subdomains": sorted(self.discovered),
            "resolved": {k: v for k, v in sorted(self.resolved.items())},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        logger.info("=" * 60)
        logger.info("Total subdomains discovered: %d", len(self.discovered))
        logger.info("Total subdomains resolved: %d", len(self.resolved))
        logger.info("=" * 60)

        return results


def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Enumeration Tool - Passive & Active Discovery",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument(
        "--domain", "-d", required=True, help="Target domain to enumerate"
    )
    parser.add_argument(
        "--wordlist", "-w", help="Path to wordlist for brute-force enumeration"
    )
    parser.add_argument(
        "--output", "-o", help="Output file path (JSON format)"
    )
    parser.add_argument(
        "--threads", "-t", type=int, default=10, help="Number of threads (default: 10)"
    )
    parser.add_argument(
        "--timeout", type=int, default=5, help="DNS timeout in seconds (default: 5)"
    )
    parser.add_argument(
        "--nameserver", "-n", help="Custom DNS nameserver to use"
    )
    parser.add_argument(
        "--passive-only", action="store_true", help="Only use passive enumeration methods"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose/debug output"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    enumerator = SubdomainEnumerator(
        domain=args.domain,
        threads=args.threads,
        timeout=args.timeout,
        nameserver=args.nameserver,
    )

    results = enumerator.run(
        wordlist=args.wordlist, passive_only=args.passive_only
    )

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("Results written to %s", args.output)
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
