"""Versioned provenance records for local artifact handoffs."""
import hashlib
from datetime import datetime, timezone
from pathlib import Path

MODES = {"offline", "passive", "authorized-active", "simulation"}


def artifact_record(path: str, producer: str, mode: str = "offline") -> dict:
    """Hash actual bytes and record collection time, not presumed event time."""
    if mode not in MODES:
        raise ValueError("invalid execution mode")
    source = Path(path)
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return {"schema_version": "1.0", "source": str(source.resolve()),
            "sha256": digest.hexdigest(), "producer": producer, "mode": mode,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "epistemic_status": "observed", "maliciousness": "unknown",
            "validation": "file-hash-only"}
