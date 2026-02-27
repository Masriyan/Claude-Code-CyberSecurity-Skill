#!/usr/bin/env python3
"""
TLS/SSL Configuration Auditor
Audits server TLS configurations for security weaknesses.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import socket
import ssl
import sys
import time
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon"}
STRONG_CIPHERS = {"AES-256-GCM", "AES-128-GCM", "CHACHA20", "AES256-GCM-SHA384"}


class TLSAuditor:
    """TLS/SSL configuration auditing engine."""

    def __init__(self, host: str, port: int = 443, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout

    def audit(self) -> Dict[str, Any]:
        """Perform full TLS audit."""
        logger.info("=" * 60)
        logger.info("TLS Audit: %s:%d", self.host, self.port)
        logger.info("=" * 60)

        results = {
            "host": self.host,
            "port": self.port,
            "certificate": self._check_certificate(),
            "protocol_support": self._check_protocols(),
            "cipher_suites": self._get_cipher_info(),
            "security_headers": self._check_security_headers(),
            "vulnerabilities": [],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        # Assess vulnerabilities
        results["vulnerabilities"] = self._assess_vulnerabilities(results)
        results["grade"] = self._calculate_grade(results)

        logger.info("Overall Grade: %s", results["grade"])
        return results

    def _check_certificate(self) -> Dict[str, Any]:
        """Check server certificate details."""
        cert_info = {"valid": False}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    cert_info = {
                        "valid": True,
                        "subject": dict(x[0] for x in cert.get("subject", ())),
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                        "serial_number": cert.get("serialNumber", ""),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "san": [
                            entry[1] for entry in cert.get("subjectAltName", ())
                        ],
                        "version": cert.get("version", ""),
                        "protocol": ssock.version(),
                        "cipher": ssock.cipher(),
                    }

                    # Check expiration
                    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
                    days_remaining = (not_after - time.time()) / 86400
                    cert_info["days_until_expiry"] = round(days_remaining, 1)
                    cert_info["expired"] = days_remaining < 0
                    cert_info["expiring_soon"] = 0 < days_remaining < 30

                    logger.info("[Cert] Valid, expires in %.0f days", days_remaining)

        except ssl.SSLCertVerificationError as e:
            cert_info["error"] = f"Certificate verification failed: {str(e)}"
            cert_info["valid"] = False
            logger.warning("[Cert] Verification failed: %s", str(e))
        except Exception as e:
            cert_info["error"] = str(e)
            logger.error("[Cert] Error: %s", str(e))

        return cert_info

    def _check_protocols(self) -> Dict[str, str]:
        """Check which TLS/SSL protocols are supported."""
        protocols = {}
        protocol_map = {
            "TLSv1.0": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }

        for name, version in protocol_map.items():
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = version
                context.maximum_version = version

                with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                        protocols[name] = "SUPPORTED"
                        status = "⚠️ WEAK" if name in WEAK_PROTOCOLS else "✓"
                        logger.info("[Protocol] %s: %s", name, status)
            except Exception:
                protocols[name] = "NOT_SUPPORTED"

        return protocols

    def _get_cipher_info(self) -> Dict[str, Any]:
        """Get cipher suite information."""
        cipher_info = {}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cipher = ssock.cipher()
                    cipher_info = {
                        "negotiated_cipher": cipher[0] if cipher else "Unknown",
                        "protocol": cipher[1] if cipher else "Unknown",
                        "key_bits": cipher[2] if cipher else 0,
                    }
                    # Assess cipher strength
                    if cipher:
                        cipher_name = cipher[0]
                        if any(w in cipher_name for w in WEAK_CIPHERS):
                            cipher_info["strength"] = "WEAK"
                        elif any(s in cipher_name for s in STRONG_CIPHERS):
                            cipher_info["strength"] = "STRONG"
                        else:
                            cipher_info["strength"] = "ACCEPTABLE"
        except Exception as e:
            cipher_info["error"] = str(e)

        return cipher_info

    def _check_security_headers(self) -> Dict[str, Any]:
        """Check for security-related HTTP headers (if HTTPS web server)."""
        headers_result = {}
        try:
            import http.client
            conn = http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout,
                context=ssl._create_unverified_context()
            )
            conn.request("HEAD", "/")
            response = conn.getresponse()
            headers = dict(response.getheaders())

            security_headers = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
            ]

            for h in security_headers:
                # Case-insensitive lookup
                found = None
                for k, v in headers.items():
                    if k.lower() == h.lower():
                        found = v
                        break
                headers_result[h] = found or "MISSING"

            conn.close()
        except Exception:
            headers_result["note"] = "Could not check HTTP headers"

        return headers_result

    def _assess_vulnerabilities(self, results: Dict) -> List[Dict]:
        """Assess vulnerabilities based on audit results."""
        vulns = []

        # Weak protocol support
        for proto, status in results.get("protocol_support", {}).items():
            if status == "SUPPORTED" and proto in WEAK_PROTOCOLS:
                vulns.append({
                    "severity": "HIGH",
                    "title": f"Weak protocol supported: {proto}",
                    "remediation": f"Disable {proto} and use TLS 1.2+ only",
                })

        # Certificate issues
        cert = results.get("certificate", {})
        if cert.get("expired"):
            vulns.append({"severity": "CRITICAL", "title": "Certificate expired", "remediation": "Renew certificate immediately"})
        elif cert.get("expiring_soon"):
            vulns.append({"severity": "MEDIUM", "title": "Certificate expiring soon", "remediation": "Renew certificate before expiration"})
        if not cert.get("valid") and "error" in cert:
            vulns.append({"severity": "HIGH", "title": "Certificate validation failed", "remediation": cert["error"]})

        # Weak cipher
        cipher = results.get("cipher_suites", {})
        if cipher.get("strength") == "WEAK":
            vulns.append({"severity": "HIGH", "title": "Weak cipher suite negotiated", "remediation": "Configure strong cipher suites only"})

        # Missing HSTS
        sec_headers = results.get("security_headers", {})
        if sec_headers.get("Strict-Transport-Security") == "MISSING":
            vulns.append({"severity": "MEDIUM", "title": "HSTS not configured", "remediation": "Enable Strict-Transport-Security header"})

        return vulns

    def _calculate_grade(self, results: Dict) -> str:
        """Calculate overall TLS grade (A-F)."""
        score = 100

        # Protocol deductions
        for proto, status in results.get("protocol_support", {}).items():
            if status == "SUPPORTED" and proto in WEAK_PROTOCOLS:
                score -= 20

        # Certificate deductions
        cert = results.get("certificate", {})
        if cert.get("expired"):
            score -= 50
        if not cert.get("valid"):
            score -= 30

        # Cipher deductions
        if results.get("cipher_suites", {}).get("strength") == "WEAK":
            score -= 25

        # Vulnerability deductions
        for vuln in results.get("vulnerabilities", []):
            if vuln["severity"] == "CRITICAL":
                score -= 20
            elif vuln["severity"] == "HIGH":
                score -= 10

        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 40:
            return "D"
        else:
            return "F"


def main():
    parser = argparse.ArgumentParser(
        description="TLS/SSL Configuration Auditor",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--host", "-H", required=True, help="Target hostname")
    parser.add_argument("--port", "-p", type=int, default=443, help="Port (default: 443)")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--grade", action="store_true", help="Show grade only")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    auditor = TLSAuditor(host=args.host, port=args.port)
    results = auditor.audit()

    if args.grade:
        print(f"TLS Grade for {args.host}: {results['grade']}")
        return

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        logger.info("Results saved to %s", args.output)
    else:
        print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
