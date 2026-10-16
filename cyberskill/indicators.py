"""Normalization and standards-based export without maliciousness inference."""
import re
import uuid


def refang(text: str) -> str:
    """Normalize explicit defanging; do not rewrite ordinary prose."""
    for pattern, replacement in [
        (r"\bhxxps(?=://)", "https"), (r"\bhxxp(?=://)", "http"),
        (r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", "."),
        (r"\[@\]|\[at\]|\(at\)", "@"), (r"\[:\]", ":"), (r"\[//\]", "//"),
    ]:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


def observable_bundle(indicators: list[dict], tlp: str | None = None) -> dict:
    """Export extracted values as SCOs, not assertions of malicious activity.

    Use a statement marking for TLP 2.0, which is not the legacy STIX TLP enum.
    Unsupported indicator kinds are explicitly listed in bundle metadata.
    """
    objects = []
    marking_id = None
    if tlp:
        if tlp not in {"CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"}:
            raise ValueError("unsupported TLP 2.0 marking")
        marking_id = f"marking-definition--{uuid.uuid4()}"
        objects.append({
            "type": "marking-definition", "spec_version": "2.1", "id": marking_id,
            "created": "2022-08-05T00:00:00.000Z", "definition_type": "statement",
            "definition": {"statement": f"TLP:{tlp} (FIRST TLP 2.0)"},
        })
    types = {"ipv4": "ipv4-addr", "ipv6": "ipv6-addr", "domain": "domain-name",
             "url": "url", "email": "email-addr"}
    hashes = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}
    skipped = set()
    seen = set()
    for ind in indicators:
        kind, value = ind["type"], refang(ind["value"])
        if (kind, value) in seen:
            continue
        seen.add((kind, value))
        if kind in hashes:
            obj = {"type": "file", "hashes": {hashes[kind]: value.lower()}}
        elif kind in types:
            obj = {"type": types[kind], "value": value}
        else:
            skipped.add(kind)
            continue
        obj.update(spec_version="2.1", id=f"{obj['type']}--{uuid.uuid4()}")
        if marking_id:
            obj["object_marking_refs"] = [marking_id]
        objects.append(obj)
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    if skipped:
        bundle["x_cyberskill_unsupported_types"] = sorted(skipped)
    return bundle
