#!/usr/bin/env python3
"""
API Security Tester
Tests REST APIs for common security vulnerabilities including BOLA, mass assignment,
missing authentication, excessive data exposure, and rate limiting gaps.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import re
import sys
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[-] Missing dependency: pip install requests")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DISCLAIMER = """
[!] DISCLAIMER: This tool is for AUTHORIZED security testing only.
[!] Ensure you have written permission before testing any API.
"""


class APISecurityTester:
    """Test REST APIs for common OWASP API Security Top 10 vulnerabilities."""

    def __init__(self, base_url: str, spec_path: Optional[str] = None,
                 token: Optional[str] = None, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.spec_path = spec_path
        self.timeout = timeout
        self.headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self.findings: List[Dict] = []
        self.endpoints: List[Dict] = []

        # Load OpenAPI spec if provided
        if spec_path:
            self._load_spec(spec_path)

    def _load_spec(self, spec_path: str) -> None:
        """Load OpenAPI specification to discover endpoints."""
        try:
            with open(spec_path) as f:
                if spec_path.endswith(".json"):
                    spec = json.load(f)
                else:
                    try:
                        import yaml
                        spec = yaml.safe_load(f)
                    except ImportError:
                        logger.warning("PyYAML not installed — cannot parse YAML spec. pip install pyyaml")
                        return

            paths = spec.get("paths", {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.lower() in ("get", "post", "put", "patch", "delete"):
                        self.endpoints.append({
                            "path": path,
                            "method": method.upper(),
                            "summary": details.get("summary", ""),
                            "requires_auth": bool(details.get("security")),
                        })
            logger.info("Loaded %d endpoints from spec", len(self.endpoints))
        except (IOError, json.JSONDecodeError) as e:
            logger.error("Failed to load spec: %s", e)

    def _request(self, method: str, path: str, headers: Optional[Dict] = None,
                 data: Optional[Dict] = None, params: Optional[Dict] = None,
                 use_auth: bool = True) -> Optional[requests.Response]:
        """Make an HTTP request and return response."""
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        req_headers = dict(self.headers) if use_auth else {
            k: v for k, v in self.headers.items() if k != "Authorization"
        }
        if headers:
            req_headers.update(headers)
        try:
            resp = requests.request(
                method, url, headers=req_headers,
                json=data, params=params,
                timeout=self.timeout, verify=False, allow_redirects=False
            )
            return resp
        except requests.exceptions.ConnectionError:
            logger.warning("Connection failed: %s", url)
            return None
        except requests.exceptions.Timeout:
            logger.warning("Request timeout: %s", url)
            return None

    def add_finding(self, vuln_id: str, title: str, severity: str,
                    description: str, endpoint: str, evidence: str,
                    remediation: str) -> None:
        self.findings.append({
            "id": vuln_id,
            "title": title,
            "severity": severity,
            "owasp_api": vuln_id.split("-")[0],
            "endpoint": endpoint,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
        })
        logger.warning("[%s] %s — %s", severity, vuln_id, title)

    # -------------------------------------------------------------------------
    # API1:2023 — Broken Object Level Authorization (BOLA)
    # -------------------------------------------------------------------------
    def test_bola(self, endpoints: List[str]) -> None:
        """Test for Broken Object Level Authorization by incrementing object IDs."""
        logger.info("Testing BOLA / IDOR on %d endpoints...", len(endpoints))
        id_pattern = re.compile(r"/(\d+)(/|$)")

        for path in endpoints:
            match = id_pattern.search(path)
            if not match:
                continue

            original_id = match.group(1)
            other_id = str(int(original_id) + 1) if original_id.isdigit() else "2"
            modified_path = path.replace(f"/{original_id}", f"/{other_id}", 1)

            original_resp = self._request("GET", path)
            modified_resp = self._request("GET", modified_path)

            if (original_resp and modified_resp and
                    original_resp.status_code == 200 and modified_resp.status_code == 200):
                self.add_finding(
                    "API1-BOLA", f"Possible BOLA on {path}", "HIGH",
                    f"Accessed object ID {other_id} on {modified_path} without additional authorization check.",
                    modified_path,
                    f"GET {modified_path} → HTTP {modified_resp.status_code}",
                    "Implement object-level authorization checks. Verify authenticated user owns the requested resource."
                )

    # -------------------------------------------------------------------------
    # API2:2023 — Broken Authentication
    # -------------------------------------------------------------------------
    def test_broken_auth(self) -> None:
        """Test for endpoints accessible without authentication."""
        logger.info("Testing authentication requirements...")

        if not self.endpoints:
            # Try common sensitive endpoints
            sensitive_paths = [
                "/api/users", "/api/admin", "/api/v1/users", "/api/profile",
                "/api/settings", "/api/keys", "/api/tokens", "/api/accounts",
            ]
            test_endpoints = [{"path": p, "method": "GET", "requires_auth": True} for p in sensitive_paths]
        else:
            test_endpoints = [e for e in self.endpoints if e.get("requires_auth")]

        for ep in test_endpoints:
            resp = self._request(ep["method"], ep["path"], use_auth=False)
            if resp and resp.status_code not in (401, 403):
                self.add_finding(
                    "API2-AUTH", f"Missing Authentication: {ep['path']}", "CRITICAL",
                    f"{ep['method']} {ep['path']} returns HTTP {resp.status_code} without authentication.",
                    ep["path"],
                    f"No Authorization header → HTTP {resp.status_code}",
                    "Enforce authentication on all non-public endpoints. Return 401 for unauthenticated requests."
                )

    # -------------------------------------------------------------------------
    # API3:2023 — Broken Object Property Level Authorization (Mass Assignment)
    # -------------------------------------------------------------------------
    def test_mass_assignment(self, endpoints: List[str]) -> None:
        """Test for mass assignment vulnerabilities."""
        logger.info("Testing for mass assignment vulnerabilities...")
        privileged_fields = ["role", "isAdmin", "is_admin", "admin", "permission",
                             "permissions", "scope", "verified", "active", "status"]
        post_endpoints = [e for e in self.endpoints if e["method"] in ("POST", "PUT", "PATCH")] if self.endpoints else []
        if not post_endpoints:
            return

        for ep in post_endpoints[:5]:  # Test first 5 write endpoints
            payload = {field: "admin" if isinstance(field, str) else True
                       for field in privileged_fields}
            resp = self._request(ep["method"], ep["path"], data=payload)
            if resp and resp.status_code in (200, 201):
                resp_text = resp.text.lower()
                for field in privileged_fields:
                    if field in resp_text:
                        self.add_finding(
                            "API3-MASSASSIGN", f"Possible Mass Assignment: {ep['path']}", "HIGH",
                            f"Privileged field '{field}' appears in response after injection.",
                            ep["path"],
                            f"{ep['method']} {ep['path']} with {field}=admin → field reflected in response",
                            "Implement allowlisting for accepted fields. Never bind user input directly to data models."
                        )
                        break

    # -------------------------------------------------------------------------
    # API4:2023 — Unrestricted Resource Consumption (Rate Limiting)
    # -------------------------------------------------------------------------
    def test_rate_limiting(self, path: str = "/api/login", requests_count: int = 20) -> None:
        """Test for missing rate limiting on sensitive endpoints."""
        logger.info("Testing rate limiting on %s (%d requests)...", path, requests_count)
        success_count = 0
        for _ in range(requests_count):
            resp = self._request("POST", path, data={"username": "test", "password": "wrong"}, use_auth=False)
            if resp and resp.status_code not in (429, 503):
                success_count += 1
            time.sleep(0.1)

        if success_count == requests_count:
            self.add_finding(
                "API4-RATELIMIT", f"No Rate Limiting: {path}", "MEDIUM",
                f"Sent {requests_count} requests to {path} without hitting a rate limit.",
                path,
                f"{requests_count}/{requests_count} requests succeeded without 429 response",
                "Implement rate limiting on authentication and sensitive endpoints. Return HTTP 429 when threshold exceeded."
            )

    # -------------------------------------------------------------------------
    # Security Headers Check
    # -------------------------------------------------------------------------
    def test_security_headers(self) -> None:
        """Check for missing security headers."""
        logger.info("Checking security headers...")
        resp = self._request("GET", "/")
        if not resp:
            resp = self._request("GET", "/api")
        if not resp:
            return

        required_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": None,
            "Strict-Transport-Security": None,
            "Content-Security-Policy": None,
        }

        for header, expected in required_headers.items():
            if header not in resp.headers:
                self.add_finding(
                    "API-HEADERS", f"Missing Security Header: {header}", "LOW",
                    f"The {header} header is not set in API responses.",
                    resp.url,
                    f"Response missing: {header}",
                    f"Add the {header} header to all API responses."
                )

    # -------------------------------------------------------------------------
    # API9:2023 — Improper Inventory Management (Debug/Doc endpoints)
    # -------------------------------------------------------------------------
    def test_exposed_debug_endpoints(self) -> None:
        """Check for exposed debug, documentation, or admin endpoints."""
        logger.info("Testing for exposed debug/admin endpoints...")
        debug_paths = [
            "/api/docs", "/api/swagger", "/swagger.json", "/openapi.json",
            "/api/v1/docs", "/graphql", "/api/__debug__", "/api/admin",
            "/.env", "/api/health", "/api/metrics", "/api/status",
            "/api/v1/admin/users", "/api/debug",
        ]
        for path in debug_paths:
            resp = self._request("GET", path, use_auth=False)
            if resp and resp.status_code in (200, 401) and resp.status_code != 404:
                severity = "MEDIUM" if resp.status_code == 401 else "HIGH"
                self.add_finding(
                    "API9-INVENTORY", f"Exposed Endpoint Discovered: {path}", severity,
                    f"Endpoint {path} exists (HTTP {resp.status_code}).",
                    path,
                    f"GET {path} → HTTP {resp.status_code} (expected 404)",
                    "Remove or restrict debug/documentation endpoints in production."
                )

    def run(self) -> Dict[str, Any]:
        """Run all enabled tests."""
        print(DISCLAIMER)
        logger.info("Starting API security assessment: %s", self.base_url)

        self.test_broken_auth()
        self.test_security_headers()
        self.test_exposed_debug_endpoints()

        endpoint_paths = [e["path"] for e in self.endpoints] if self.endpoints else []
        if endpoint_paths:
            self.test_bola(endpoint_paths)
            self.test_mass_assignment(endpoint_paths)

        # Rate limit test on common auth endpoint
        self.test_rate_limiting()

        # Summary
        by_severity = {}
        for f in self.findings:
            sev = f["severity"]
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            "target": self.base_url,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_findings": len(self.findings),
            "by_severity": by_severity,
            "findings": self.findings,
        }


def print_summary(results: Dict[str, Any]) -> None:
    print("\n" + "=" * 60)
    print("API Security Assessment Summary")
    print("=" * 60)
    print(f"Target:   {results['target']}")
    print(f"Findings: {results['total_findings']}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = results["by_severity"].get(sev, 0)
        if count:
            print(f"  {sev:<10}: {count}")
    print()
    for f in results["findings"]:
        print(f"  [{f['severity']}] {f['id']} — {f['title']}")
        print(f"    Endpoint: {f['endpoint']}")
        print(f"    Fix:      {f['remediation'][:80]}...")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="API Security Tester — OWASP API Security Top 10",
        epilog="Example: api_security_tester.py --base-url https://api.example.com --spec openapi.yaml"
    )
    parser.add_argument("--base-url", required=True, help="Base URL of the API")
    parser.add_argument("--spec", help="OpenAPI/Swagger spec file (JSON or YAML)")
    parser.add_argument("--token", help="Bearer token for authentication")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    args = parser.parse_args()

    tester = APISecurityTester(args.base_url, args.spec, args.token, args.timeout)
    results = tester.run()
    print_summary(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("Results saved to %s", args.output)


if __name__ == "__main__":
    main()
