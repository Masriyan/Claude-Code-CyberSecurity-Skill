#!/usr/bin/env python3
"""Produce an offline provenance manifest for handoff artifacts."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyberskill.evidence import MODES, artifact_record


def main() -> None:
    """Hash local inputs without executing their content."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+")
    parser.add_argument("--producer", required=True)
    parser.add_argument("--mode", choices=sorted(MODES), default="offline")
    args = parser.parse_args()
    try:
        records = [artifact_record(path, args.producer, args.mode) for path in args.files]
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
