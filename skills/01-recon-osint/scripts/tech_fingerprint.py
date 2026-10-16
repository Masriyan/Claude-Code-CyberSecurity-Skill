#!/usr/bin/env python3
"""
Technology Fingerprinting Tool
Identifies web technologies, frameworks, and server configurations.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import re
import sys
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[!] 'requests' module required: pip install requests")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# Technology signatures for detection
TECH_SIGNATURES = {
    "cms": {
        "WordPress": [r"wp-content", r"wp-includes", r"wp-json", r"/xmlrpc\.php"],
        "Joomla": [r"/media/jui/", r"com_content", r"/administrator/"],
        "Drupal": [r"Drupal\.settings", r"drupal\.js", r"/sites/default/"],
        "Magento": [r"Mage\.Cookies", r"/skin/frontend/", r"magento"],
        "Shopify": [r"cdn\.shopify\.com", r"shopify\.com"],
    },
    "frameworks": {
        "React": [r"react\.production\.min\.js", r"_reactRootContainer", r"__NEXT_DATA__"],
        "Angular": [r"ng-version", r"angular\.js", r"ng-app"],
        "Vue.js": [r"vue\.js", r"vue\.min\.js", r"__vue__"],
        "jQuery": [r"jquery[\.-]", r"jQuery"],
        "Bootstrap": [r"bootstrap\.min\.(css|js)", r"bootstrap\.bundle"],
        "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
        "Laravel": [r"laravel_session", r"csrf-token"],
        "Rails": [r"csrf-param", r"rails-ujs", r"turbolinks"],
        "Express": [r"X-Powered-By.*Express"],
        "ASP.NET": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"asp\.net"],
    },
    "servers": {
        "Nginx": [r"nginx"],
        "Apache": [r"Apache"],
        "IIS": [r"Microsoft-IIS"],
        "LiteSpeed": [r"LiteSpeed"],
        "Cloudflare": [r"cloudflare"],
    },
    "waf": {
        "Cloudflare": [r"cf-ray", r"__cfduid", r"cloudflare"],
        "AWS WAF": [r"x-amzn-requestid", r"awswaf"],
        "Akamai": [r"akamai", r"x-akamai"],
        "Sucuri": [r"sucuri", r"x-sucuri"],
        "ModSecurity": [r"mod_security", r"NOYB"],
    },
}


class TechFingerprinter:
    """Web technology fingerprinting engine."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        self.session.verify = False

    def fingerprint(self, url: str) -> Dict[str, Any]:
        """Perform full technology fingerprinting on a URL."""
        logger.info("[Fingerprint] Analyzing: %s", url)

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        result = {
            "url": url,
            "technologies": {},
            "headers": {},
            "ssl": {},
            "security_headers": {},
        }

        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            result["status_code"] = response.status_code
            result["final_url"] = response.url
            result["headers"] = dict(response.headers)

            # Analyze components
            result["technologies"]["server"] = self._detect_server(response)
            result["technologies"]["cms"] = self._detect_cms(response)
            result["technologies"]["frameworks"] = self._detect_frameworks(response)
            result["technologies"]["waf"] = self._detect_waf(response)
            result["technologies"]["cdn"] = self._detect_cdn(response)
            result["technologies"]["analytics"] = self._detect_analytics(response)
            result["security_headers"] = self._analyze_security_headers(response)
            result["ssl"] = self._analyze_ssl(url)

        except requests.exceptions.SSLError:
            result["error"] = "SSL Error — certificate verification failed"
            logger.warning("[Fingerprint] SSL error for %s", url)
        except requests.exceptions.ConnectionError:
            result["error"] = "Connection failed"
            logger.error("[Fingerprint] Connection failed for %s", url)
        except Exception as e:
            result["error"] = str(e)
            logger.error("[Fingerprint] Error: %s", str(e))

        result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return result

    def _detect_server(self, response: requests.Response) -> List[str]:
        """Detect web server from headers."""
        servers = []
        server_header = response.headers.get("Server", "")
        powered_by = response.headers.get("X-Powered-By", "")

        for name, patterns in TECH_SIGNATURES["servers"].items():
            for pattern in patterns:
                if re.search(pattern, server_header, re.I) or re.search(pattern, powered_by, re.I):
                    servers.append(name)
                    break

        if server_header and not servers:
            servers.append(f"Unknown ({server_header})")
        if powered_by:
            servers.append(f"Powered-By: {powered_by}")
        return servers

    def _detect_cms(self, response: requests.Response) -> List[str]:
        """Detect CMS from response body and headers."""
        detected = []
        body = response.text
        for name, patterns in TECH_SIGNATURES["cms"].items():
            for pattern in patterns:
                if re.search(pattern, body, re.I):
                    detected.append(name)
                    break
        return detected

    def _detect_frameworks(self, response: requests.Response) -> List[str]:
        """Detect JavaScript frameworks and backend frameworks."""
        detected = []
        body = response.text
        headers_str = str(response.headers)
        combined = body + headers_str

        for name, patterns in TECH_SIGNATURES["frameworks"].items():
            for pattern in patterns:
                if re.search(pattern, combined, re.I):
                    detected.append(name)
                    break
        return detected

    def _detect_waf(self, response: requests.Response) -> List[str]:
        """Detect Web Application Firewalls."""
        detected = []
        headers_str = str(response.headers).lower()
        cookies_str = str(response.cookies.get_dict()).lower()
        combined = headers_str + cookies_str

        for name, patterns in TECH_SIGNATURES["waf"].items():
            for pattern in patterns:
                if re.search(pattern, combined, re.I):
                    detected.append(name)
                    break
        return detected

    def _detect_cdn(self, response: requests.Response) -> List[str]:
        """Detect CDN providers."""
        cdns = []
        headers = response.headers
        if "cf-ray" in headers or "cf-cache-status" in headers:
            cdns.append("Cloudflare")
        if "x-amz-cf-id" in headers:
            cdns.append("AWS CloudFront")
        if "x-fastly-request-id" in headers:
            cdns.append("Fastly")
        if "x-cdn" in headers:
            cdns.append(headers["x-cdn"])
        return cdns

    def _detect_analytics(self, response: requests.Response) -> List[str]:
        """Detect analytics and tracking tools."""
        detected = []
        body = response.text
        patterns = {
            "Google Analytics": [r"google-analytics\.com", r"gtag\(", r"UA-\d+"],
            "Google Tag Manager": [r"googletagmanager\.com", r"GTM-"],
            "Facebook Pixel": [r"connect\.facebook\.net", r"fbq\("],
            "Hotjar": [r"hotjar\.com", r"hj\("],
        }
        for name, pats in patterns.items():
            for p in pats:
                if re.search(p, body, re.I):
                    detected.append(name)
                    break
        return detected

    def _analyze_security_headers(self, response: requests.Response) -> Dict[str, Any]:
        """Analyze security-related HTTP headers."""
        headers = response.headers
        security = {
            "present": {},
            "missing": [],
            "score": 0,
        }

        important_headers = {
            "Strict-Transport-Security": "HSTS — Enforces HTTPS connections",
            "Content-Security-Policy": "CSP — Prevents XSS and injection attacks",
            "X-Content-Type-Options": "Prevents MIME-type sniffing",
            "X-Frame-Options": "Prevents clickjacking attacks",
            "X-XSS-Protection": "Legacy XSS filter (deprecated but still useful)",
            "Referrer-Policy": "Controls referrer information leakage",
            "Permissions-Policy": "Controls browser feature access",
        }

        for header, description in important_headers.items():
            value = headers.get(header)
            if value:
                security["present"][header] = {"value": value, "description": description}
                security["score"] += 1
            else:
                security["missing"].append({"header": header, "description": description})

        security["score_percent"] = round(
            (security["score"] / len(important_headers)) * 100, 1
        )
        return security

    def _analyze_ssl(self, url: str) -> Dict[str, str]:
        """Basic SSL/TLS information."""
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return {"tls": "Not using HTTPS"}
        return {"tls": "HTTPS enabled", "host": parsed.hostname}


def main():
    parser = argparse.ArgumentParser(
        description="Technology Fingerprinting Tool",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--url", "-u", help="Single URL to fingerprint")
    parser.add_argument("--urls", "-U", help="File with list of URLs (one per line)")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.url and not args.urls:
        parser.error("Either --url or --urls is required")

    fingerprinter = TechFingerprinter(timeout=args.timeout)

    if args.url:
        results = fingerprinter.fingerprint(args.url)
    else:
        with open(args.urls, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
        results = [fingerprinter.fingerprint(url) for url in urls]

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("Results saved to %s", args.output)
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
