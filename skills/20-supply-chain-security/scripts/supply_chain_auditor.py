#!/usr/bin/env python3
"""
Software Supply Chain Security Auditor
Scans a project for typosquatted/floating dependencies, risky package
lifecycle scripts, and unpinned CI/CD (GitHub Actions) workflows.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None

try:
    import requests
except ImportError:
    requests = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# A small, curated set of high-download packages per ecosystem used as the
# typosquatting comparison baseline. Not exhaustive -- flags near-misses
# against these names, it does not prove a package is malicious.
POPULAR_PACKAGES = {
    "npm": [
        "react", "react-dom", "lodash", "express", "axios", "chalk", "commander",
        "request", "debug", "async", "moment", "underscore", "webpack", "babel",
        "eslint", "jest", "typescript", "vue", "next", "yargs", "colors", "dotenv",
    ],
    "PyPI": [
        "requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3",
        "pyyaml", "click", "setuptools", "pip", "cryptography", "jinja2",
        "pillow", "pytest", "sqlalchemy", "scipy", "matplotlib",
    ],
    "crates.io": [
        "serde", "tokio", "rand", "clap", "reqwest", "regex", "log", "thiserror",
        "anyhow", "syn", "quote", "libc", "rayon", "once_cell", "itertools",
    ],
    "Go": [
        "gin", "echo", "cobra", "viper", "testify", "zap", "logrus", "grpc",
        "protobuf", "uuid", "gorm", "chi", "errors", "mux",
    ],
}

# Patterns that indicate a package lifecycle script is doing something a
# normal install step has no reason to do.
SUSPICIOUS_SCRIPT_PATTERNS = [
    (r"curl\s+.*\|\s*(sh|bash)", "Downloads and pipes a remote script directly into a shell"),
    (r"wget\s+.*\|\s*(sh|bash)", "Downloads and pipes a remote script directly into a shell"),
    (r"base64\s+-d", "Decodes base64 content during install (common obfuscation)"),
    (r"\beval\s*\(", "Uses eval() to execute dynamically constructed code"),
    (r"child_process", "Spawns a subprocess from within a lifecycle script"),
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Contacts a raw IP literal instead of a named host"),
    (r"process\.env\.(NPM_TOKEN|GITHUB_TOKEN|AWS_SECRET)", "Reads a CI/registry credential from the environment"),
]

FLOATING_VERSION_PATTERNS = [
    (r"^\*$", "Wildcard version — resolves to whatever is newest at install time"),
    (r"^latest$", "'latest' tag — not reproducible, no version pin"),
    (r"^>=", "Open-ended lower bound with no upper bound"),
]

SHA_PIN_RE = re.compile(r"^[0-9a-f]{40}$")


class SupplyChainAuditor:
    """Static software-supply-chain risk scanner for a project directory."""

    def __init__(self, check_registry: bool = False):
        self.check_registry = check_registry and requests is not None
        if check_registry and requests is None:
            logger.warning("'requests' not installed — registry existence checks disabled")
        self.findings: List[Dict[str, Any]] = []

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        """Edit distance between two strings (used for typosquat detection)."""
        if a == b:
            return 0
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            cur = [i] + [0] * len(b)
            for j, cb in enumerate(b, 1):
                cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            prev = cur
        return prev[-1]

    def _add(self, finding_id: str, severity: str, title: str, description: str, **extra):
        finding = {"id": finding_id, "severity": severity, "title": title, "description": description}
        finding.update(extra)
        self.findings.append(finding)

    # ---- Manifest parsing -------------------------------------------------

    def parse_package_json(self, filepath: str) -> Dict[str, Any]:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps.update(data.get(key, {}) or {})
        return {"deps": deps, "scripts": data.get("scripts", {}) or {}}

    def parse_requirements_txt(self, filepath: str) -> Dict[str, str]:
        deps = {}
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith(("-", "git+", "http")):
                    continue
                match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9_.\-*]*)", line)
                if match:
                    name, op, version = match.groups()
                    deps[name] = f"{op or ''}{version or '*'}"
        return deps

    def parse_cargo_toml(self, filepath: str) -> Dict[str, str]:
        """Lightweight [dependencies]-section parser (no full TOML parser required)."""
        deps = {}
        in_deps_section = False
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if re.match(r"^\[.*dependencies.*\]$", stripped, re.I):
                    in_deps_section = True
                    continue
                if stripped.startswith("["):
                    in_deps_section = False
                    continue
                if not in_deps_section or not stripped or stripped.startswith("#"):
                    continue
                match = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*"([^"]*)"', stripped)
                if not match:
                    match = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*\{.*version\s*=\s*"([^"]*)"', stripped)
                if match:
                    deps[match.group(1)] = match.group(2)
        return deps

    def parse_go_mod(self, filepath: str) -> Dict[str, str]:
        """Extract module paths and versions from single-line and require(...) block forms."""
        deps = {}
        in_require_block = False
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.split("//", 1)[0].strip()
                if stripped.startswith("require ("):
                    in_require_block = True
                    continue
                if in_require_block and stripped == ")":
                    in_require_block = False
                    continue
                if in_require_block:
                    match = re.match(r"^(\S+)\s+(v[0-9]\S*)", stripped)
                elif stripped.startswith("require "):
                    match = re.match(r"^require\s+(\S+)\s+(v[0-9]\S*)", stripped)
                else:
                    match = None
                if match:
                    deps[match.group(1)] = match.group(2)
        return deps

    # ---- Checks -------------------------------------------------------------

    def check_typosquatting(self, deps: Dict[str, str], ecosystem: str, filepath: str, key_fn=None):
        popular = POPULAR_PACKAGES.get(ecosystem, [])
        for name in deps:
            candidate = key_fn(name) if key_fn else name
            normalized = candidate.lower()
            if normalized in popular:
                continue
            for known in popular:
                distance = self._levenshtein(normalized, known)
                if 0 < distance <= 2 and abs(len(normalized) - len(known)) <= 2:
                    self._add(
                        "SC-001", "HIGH", "Possible typosquatted package name",
                        f"'{name}' is a distance-{distance} near-match of popular package '{known}'",
                        file=filepath, package=name, similar_to=known,
                    )
                    break

    def check_lockfile_presence(self, project_dir: str, manifest_path: str, lockfile_names: List[str]):
        has_lockfile = any(os.path.exists(os.path.join(project_dir, lf)) for lf in lockfile_names)
        if not has_lockfile:
            self._add(
                "SC-009", "HIGH", f"No lockfile committed alongside {os.path.basename(manifest_path)}",
                f"Without {'/'.join(lockfile_names)}, installs are not reproducible and "
                "transitive versions/hashes can drift or be swapped",
                file=manifest_path,
            )

    def check_floating_versions(self, deps: Dict[str, str], filepath: str):
        for name, version in deps.items():
            version = (version or "").strip()
            for pattern, reason in FLOATING_VERSION_PATTERNS:
                if re.match(pattern, version):
                    self._add(
                        "SC-002", "MEDIUM", "Unpinned / floating dependency version",
                        reason, file=filepath, package=name, version_spec=version,
                    )
                    break
            else:
                if version.startswith(("^", "~")):
                    self._add(
                        "SC-003", "LOW", "Range-pinned dependency version",
                        f"'{version}' allows automatic minor/patch upgrades without review",
                        file=filepath, package=name, version_spec=version,
                    )

    def check_lifecycle_scripts(self, scripts: Dict[str, str], filepath: str):
        risky_hooks = {"preinstall", "install", "postinstall", "prepare"}
        for hook, command in scripts.items():
            if hook not in risky_hooks:
                continue
            for pattern, reason in SUSPICIOUS_SCRIPT_PATTERNS:
                if re.search(pattern, command, re.I):
                    self._add(
                        "SC-004", "CRITICAL", "Suspicious package lifecycle script",
                        f"'{hook}' script: {reason}",
                        file=filepath, hook=hook, command=command,
                    )

    def check_registry_existence(self, deps: Dict[str, str], ecosystem: str, filepath: str):
        if not self.check_registry:
            return
        url_map = {
            "npm": "https://registry.npmjs.org/{}",
            "PyPI": "https://pypi.org/pypi/{}/json",
            "crates.io": "https://crates.io/api/v1/crates/{}",
        }
        url_template = url_map.get(ecosystem)
        if not url_template:
            return
        headers = {"User-Agent": "supply_chain_auditor.py (Claude-Code-CyberSecurity-Skill)"}
        for name in deps:
            try:
                resp = requests.get(url_template.format(name), timeout=10, headers=headers)
                if resp.status_code == 404:
                    self._add(
                        "SC-005", "HIGH", "Dependency not found on public registry",
                        f"'{name}' does not exist on {ecosystem} — possible removed/typosquat/dependency-confusion package",
                        file=filepath, package=name,
                    )
            except requests.RequestException as exc:
                logger.debug("Registry lookup failed for %s: %s", name, exc)

    def check_github_actions(self, workflow_dir: str):
        if yaml is None:
            logger.warning("'pyyaml' not installed — GitHub Actions workflow checks skipped")
            return
        if not os.path.isdir(workflow_dir):
            return
        for filename in sorted(os.listdir(workflow_dir)):
            if not filename.endswith((".yml", ".yaml")):
                continue
            filepath = os.path.join(workflow_dir, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                try:
                    workflow = yaml.safe_load(f)
                except yaml.YAMLError as exc:
                    logger.warning("YAML parse error in %s: %s", filepath, exc)
                    continue
            if not isinstance(workflow, dict):
                continue

            if "permissions" not in workflow:
                self._add(
                    "SC-006", "MEDIUM", "Workflow has no explicit top-level permissions",
                    "GITHUB_TOKEN defaults to broad read/write scopes unless 'permissions' is set",
                    file=filepath,
                )

            # PyYAML parses the unquoted 'on:' key as the boolean True.
            triggers = workflow.get(True, workflow.get("on", {}))
            if isinstance(triggers, str):
                trigger_names = [triggers]
            elif isinstance(triggers, list):
                trigger_names = triggers
            elif isinstance(triggers, dict):
                trigger_names = list(triggers)
            else:
                trigger_names = []
            if "pull_request_target" in trigger_names:
                self._add(
                    "SC-007", "HIGH", "pull_request_target trigger in use",
                    "Runs with base-repo secrets/token against untrusted fork content — "
                    "verify the workflow never checks out or executes PR head code",
                    file=filepath,
                )

            for job_name, job in (workflow.get("jobs") or {}).items():
                if not isinstance(job, dict):
                    continue
                for step in job.get("steps", []) or []:
                    uses = step.get("uses") if isinstance(step, dict) else None
                    if not uses or "@" not in uses:
                        continue
                    action, ref = uses.rsplit("@", 1)
                    if not SHA_PIN_RE.match(ref):
                        self._add(
                            "SC-008", "MEDIUM", "GitHub Action not pinned to a commit SHA",
                            f"'{action}' is pinned to mutable ref '{ref}' — a tag/branch can be "
                            "repointed by the action's maintainer (or an attacker who compromises them)",
                            file=filepath, job=job_name, action=action, ref=ref,
                        )

    # ---- Orchestration ------------------------------------------------------

    def scan_directory(self, project_dir: str) -> Dict[str, Any]:
        logger.info("=" * 60)
        logger.info("Supply Chain Security Audit: %s", project_dir)
        logger.info("=" * 60)

        package_json = os.path.join(project_dir, "package.json")
        if os.path.exists(package_json):
            parsed = self.parse_package_json(package_json)
            self.check_lockfile_presence(
                project_dir, package_json,
                ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"],
            )
            self.check_typosquatting(parsed["deps"], "npm", package_json)
            self.check_floating_versions(parsed["deps"], package_json)
            self.check_lifecycle_scripts(parsed["scripts"], package_json)
            self.check_registry_existence(parsed["deps"], "npm", package_json)

        requirements_txt = os.path.join(project_dir, "requirements.txt")
        if os.path.exists(requirements_txt):
            deps = self.parse_requirements_txt(requirements_txt)
            self.check_typosquatting(deps, "PyPI", requirements_txt)
            self.check_floating_versions(deps, requirements_txt)
            self.check_registry_existence(deps, "PyPI", requirements_txt)

        cargo_toml = os.path.join(project_dir, "Cargo.toml")
        if os.path.exists(cargo_toml):
            deps = self.parse_cargo_toml(cargo_toml)
            self.check_lockfile_presence(project_dir, cargo_toml, ["Cargo.lock"])
            self.check_typosquatting(deps, "crates.io", cargo_toml)
            self.check_registry_existence(deps, "crates.io", cargo_toml)

        go_mod = os.path.join(project_dir, "go.mod")
        if os.path.exists(go_mod):
            deps = self.parse_go_mod(go_mod)
            self.check_lockfile_presence(project_dir, go_mod, ["go.sum"])
            self.check_typosquatting(deps, "Go", go_mod, key_fn=lambda m: m.rsplit("/", 1)[-1])

        self.check_github_actions(os.path.join(project_dir, ".github", "workflows"))

        severity_counts: Dict[str, int] = {}
        for finding in self.findings:
            severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1

        results = {
            "project_dir": project_dir,
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "findings": self.findings,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        logger.info("Total findings: %d", len(self.findings))
        return results


def main():
    parser = argparse.ArgumentParser(
        description="Software Supply Chain Security Auditor",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--project-dir", "-p", required=True, help="Project directory to scan")
    parser.add_argument("--check-registry", action="store_true",
                         help="Also verify each dependency exists on its public registry (network calls)")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    auditor = SupplyChainAuditor(check_registry=args.check_registry)
    results = auditor.scan_directory(args.project_dir)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("Results saved to %s", args.output)
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
