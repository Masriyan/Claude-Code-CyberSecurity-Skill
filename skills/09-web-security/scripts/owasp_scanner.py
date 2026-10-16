#!/usr/bin/env python3
"""
Web Application Security Scanner (OWASP)
Tests for common web vulnerabilities from the OWASP Top 10.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import re
import sys
import time
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

try:
    import requests
    from requests.exceptions import RequestException
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"severity": "HIGH", "description": "HSTS not set — vulnerable to SSL stripping"},
    "Content-Security-Policy": {"severity": "MEDIUM", "description": "CSP not set — XSS risk increased"},
    "X-Content-Type-Options": {"severity": "LOW", "description": "Missing — MIME sniffing possible"},
    "X-Frame-Options": {"severity": "MEDIUM", "description": "Missing — clickjacking possible"},
    "X-XSS-Protection": {"severity": "LOW", "description": "Legacy XSS protection header missing"},
    "Referrer-Policy": {"severity": "LOW", "description": "Referrer policy not configured"},
    "Permissions-Policy": {"severity": "LOW", "description": "Permissions policy not set"},
}

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '{{7*7}}',
]

SQLI_PAYLOADS = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "1; DROP TABLE--", "' UNION SELECT NULL--"]


class OWASPScanner:
    """Basic OWASP Top 10 web vulnerability scanner."""

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "CyberSkill-Scanner/1.0"
        self.session.verify = False
        self.findings: List[Dict] = []

    def check_security_headers(self) -> None:
        logger.info("[A05] Checking security headers...")
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            for header, info in SECURITY_HEADERS.items():
                if header.lower() not in {k.lower(): v for k, v in resp.headers.items()}:
                    self.findings.append({"category": "A05-Security-Misconfiguration", "severity": info["severity"],
                                         "title": f"Missing header: {header}", "description": info["description"]})
            # Check for server version disclosure
            if "Server" in resp.headers:
                server = resp.headers["Server"]
                if any(v in server for v in ["Apache/", "nginx/", "IIS/"]):
                    self.findings.append({"category": "A05-Security-Misconfiguration", "severity": "LOW",
                                         "title": "Server version disclosed", "description": f"Server: {server}"})
        except RequestException as e:
            logger.error("[A05] Request failed: %s", str(e))

    def check_tls(self) -> None:
        logger.info("[A02] Checking TLS configuration...")
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https":
            self.findings.append({"category": "A02-Cryptographic-Failures", "severity": "HIGH",
                                 "title": "Not using HTTPS", "description": "Application is served over HTTP"})

    def check_common_paths(self) -> None:
        logger.info("[A05] Checking for exposed sensitive paths...")
        sensitive_paths = [
            "/.env", "/.git/config", "/wp-admin/", "/admin/", "/phpmyadmin/",
            "/server-status", "/server-info", "/.htaccess", "/robots.txt",
            "/sitemap.xml", "/api/swagger", "/api/docs", "/.well-known/security.txt",
        ]
        for path in sensitive_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code == 200:
                    self.findings.append({"category": "A05-Security-Misconfiguration", "severity": "MEDIUM",
                                         "title": f"Sensitive path accessible: {path}",
                                         "description": f"HTTP {resp.status_code} at {url}"})
            except RequestException:
                pass

    def check_cors(self) -> None:
        logger.info("[A01] Checking CORS configuration...")
        try:
            resp = self.session.get(self.base_url, headers={"Origin": "https://evil.example.com"}, timeout=self.timeout)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*" or "evil.example.com" in acao:
                self.findings.append({"category": "A01-Broken-Access-Control", "severity": "HIGH",
                                     "title": "Permissive CORS policy",
                                     "description": f"Access-Control-Allow-Origin: {acao}"})
        except RequestException:
            pass

    def run(self, tests: List[str] = None) -> Dict[str, Any]:
        if not HAS_REQUESTS:
            return {"error": "requests library required: pip install requests"}
        logger.info("=" * 50)
        logger.info("OWASP Scan: %s", self.base_url)
        logger.info("=" * 50)

        all_tests = {"a01": self.check_cors, "a02": self.check_tls,
                     "a05": lambda: (self.check_security_headers(), self.check_common_paths())}
        if tests:
            for t in tests:
                func = all_tests.get(t.lower())
                if func:
                    func()
        else:
            self.check_tls()
            self.check_security_headers()
            self.check_common_paths()
            self.check_cors()

        severity_counts = {}
        for f in self.findings:
            s = f["severity"]
            severity_counts[s] = severity_counts.get(s, 0) + 1

        return {"target": self.base_url, "total_findings": len(self.findings),
                "severity_counts": severity_counts, "findings": self.findings,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def main():
    parser = argparse.ArgumentParser(description="OWASP Web Security Scanner",
                                     epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill")
    parser.add_argument("--url", "-u", required=True, help="Target URL")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--tests", help="Comma-separated test IDs (e.g., a01,a02,a05)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tests = args.tests.split(",") if args.tests else None
    scanner = OWASPScanner(args.url)
    results = scanner.run(tests=tests)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("Report saved to %s", args.output)
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
