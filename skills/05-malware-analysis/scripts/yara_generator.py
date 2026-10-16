#!/usr/bin/env python3
"""
YARA Rule Generator
Generates YARA rules from malware samples for detection.

Repository: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
from collections import Counter
from typing import Any, Dict, List, Set

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Common strings to exclude from YARA rules (too generic)
COMMON_STRINGS = {
    "http://", "https://", "www.", ".com", ".exe", ".dll", ".sys",
    "Microsoft", "Windows", "kernel32", "ntdll", "user32",
    "GetProcAddress", "LoadLibrary", "GetModuleHandle",
    "This program", "cannot be run", "DOS mode",
}


class YaraGenerator:
    """YARA rule generation engine from malware samples."""

    def __init__(self, author: str = "CyberSkill YARA Generator"):
        self.author = author

    def extract_unique_strings(
        self, data: bytes, min_length: int = 6, max_strings: int = 20
    ) -> List[Dict[str, str]]:
        """Extract unique and meaningful strings from binary data."""
        ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
        strings_found = []

        for match in ascii_pattern.finditer(data):
            s = match.group().decode("ascii")
            # Filter out common/generic strings
            if not any(common in s for common in COMMON_STRINGS):
                if len(s) <= 200:  # Skip extremely long strings
                    strings_found.append({
                        "value": s,
                        "offset": hex(match.start()),
                        "type": "ascii",
                    })

        # Deduplicate and sort by uniqueness (longer = more unique)
        seen: Set[str] = set()
        unique = []
        for s in sorted(strings_found, key=lambda x: len(x["value"]), reverse=True):
            if s["value"] not in seen:
                seen.add(s["value"])
                unique.append(s)

        return unique[:max_strings]

    def extract_hex_patterns(
        self, data: bytes, min_length: int = 8, max_patterns: int = 5
    ) -> List[Dict[str, str]]:
        """Extract unique hex byte patterns from binary."""
        patterns = []

        # Look for interesting byte sequences (not all zeros/FFs)
        for i in range(0, len(data) - min_length, min_length * 4):
            chunk = data[i:i + min_length]
            # Skip boring sequences
            if len(set(chunk)) < 3:
                continue
            # Skip too common sequences
            entropy = len(set(chunk)) / len(chunk)
            if 0.3 < entropy < 0.9:
                pattern = " ".join(f"{b:02X}" for b in chunk)
                patterns.append({
                    "value": pattern,
                    "offset": hex(i),
                    "type": "hex",
                })

        seen: Set[str] = set()
        unique = []
        for p in patterns:
            if p["value"] not in seen:
                seen.add(p["value"])
                unique.append(p)

        return unique[:max_patterns]

    def generate_rule(
        self,
        filepath: str,
        rule_name: str,
        description: str = "",
        tags: List[str] = None,
    ) -> str:
        """Generate a YARA rule from a single sample."""
        logger.info("[YARA] Generating rule from: %s", filepath)

        with open(filepath, "rb") as f:
            data = f.read()

        sha256 = hashlib.sha256(data).hexdigest()
        filesize = len(data)

        # Detect file type
        is_pe = data[:2] == b"\x4d\x5a"
        is_elf = data[:4] == b"\x7fELF"

        # Extract indicators
        strings = self.extract_unique_strings(data)
        hex_patterns = self.extract_hex_patterns(data)

        if not strings and not hex_patterns:
            logger.warning("[YARA] No unique patterns found in %s", filepath)
            return ""

        # Build rule
        tag_str = " : " + " ".join(tags) if tags else ""
        rule_lines = [
            f'rule {rule_name}{tag_str} {{',
            '    meta:',
            f'        author = "{self.author}"',
            f'        description = "{description or f"Detects {rule_name}"}"',
            f'        date = "{time.strftime("%Y-%m-%d")}"',
            f'        hash = "{sha256}"',
            f'        reference = "https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill"',
            '',
            '    strings:',
        ]

        # Add string indicators
        for i, s in enumerate(strings[:15]):
            escaped = s["value"].replace("\\", "\\\\").replace('"', '\\"')
            rule_lines.append(f'        $s{i + 1} = "{escaped}" ascii wide')

        # Add hex patterns
        for i, h in enumerate(hex_patterns[:5]):
            rule_lines.append(f'        $h{i + 1} = {{ {h["value"]} }}')

        # Build condition
        rule_lines.append('')
        rule_lines.append('    condition:')

        conditions = []
        if is_pe:
            conditions.append('uint16(0) == 0x5A4D')
        elif is_elf:
            conditions.append('uint32(0) == 0x464C457F')

        conditions.append(f'filesize < {filesize * 3}')

        total_indicators = len(strings[:15]) + len(hex_patterns[:5])
        if total_indicators > 3:
            min_match = max(2, total_indicators // 2)
            all_vars = [f"$s{i+1}" for i in range(len(strings[:15]))]
            all_vars += [f"$h{i+1}" for i in range(len(hex_patterns[:5]))]
            conditions.append(f'{min_match} of ({", ".join(all_vars)})')
        else:
            conditions.append('all of them')

        rule_lines.append('        ' + ' and\n        '.join(conditions))
        rule_lines.append('}')

        return '\n'.join(rule_lines)

    def generate_from_directory(
        self, directory: str, prefix: str = "Malware"
    ) -> str:
        """Generate YARA rules from all samples in a directory."""
        logger.info("[YARA] Processing directory: %s", directory)

        rules = []
        rule_header = [
            '/*',
            f'    YARA Rules — Auto-generated from samples',
            f'    Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}',
            f'    Generator: https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill',
            '*/',
            '',
            'import "pe"',
            '',
        ]

        for i, filename in enumerate(sorted(os.listdir(directory)), 1):
            filepath = os.path.join(directory, filename)
            if not os.path.isfile(filepath):
                continue

            safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", filename)
            rule_name = f"{prefix}_{safe_name}_{i:03d}"

            rule = self.generate_rule(
                filepath=filepath,
                rule_name=rule_name,
                description=f"Detection rule for sample: {filename}",
                tags=["malware", "auto_generated"],
            )

            if rule:
                rules.append(rule)
                logger.info("[YARA] Generated rule: %s", rule_name)

        return '\n'.join(rule_header) + '\n\n'.join(rules)


def main():
    parser = argparse.ArgumentParser(
        description="YARA Rule Generator",
        epilog="https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill",
    )
    parser.add_argument("--file", "-f", help="Single sample file")
    parser.add_argument("--samples", "-s", help="Directory of samples")
    parser.add_argument("--rule-name", "-n", default="Malware_Sample", help="Rule name")
    parser.add_argument("--description", "-d", default="", help="Rule description")
    parser.add_argument("--author", "-a", default="CyberSkill YARA Generator", help="Rule author")
    parser.add_argument("--output", "-o", help="Output .yar file")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.file and not args.samples:
        parser.error("Either --file or --samples is required")

    generator = YaraGenerator(author=args.author)

    if args.file:
        result = generator.generate_rule(
            filepath=args.file,
            rule_name=args.rule_name,
            description=args.description,
        )
    else:
        result = generator.generate_from_directory(
            directory=args.samples, prefix=args.rule_name
        )

    if args.output:
        with open(args.output, "w") as f:
            f.write(result)
        logger.info("YARA rules saved to %s", args.output)
    else:
        print(result)


if __name__ == "__main__":
    main()
