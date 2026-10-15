"""Regression cases for neutral IOC handling and STIX interoperability."""
import json
import subprocess
import sys

import pytest
import stix2
from stix2validator import ValidationOptions, validate_instance

from conftest import ROOT, load_script
from cyberskill.indicators import observable_bundle, refang


def test_defanged_extraction_and_stix_roundtrip():
    extractor = load_script("ioc_extractor").IOCExtractor(defang=True)
    result = extractor.extract("hxxps://evil[.]com/Test?q=AbC 8[.]8[.]8[.]8")
    assert "hxxps://evil[.]com/Test?q=AbC" in result["indicators"]["url"]
    bundle = extractor.to_stix(result)
    stix2.parse(bundle, allow_custom=True)
    assert any(o.get("value") == "https://evil.com/Test?q=AbC" for o in bundle["objects"])


@pytest.mark.parametrize("tlp", ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"])
def test_stix_schema(tlp):
    bundle = observable_bundle([
        {"type": "sha256", "value": "0123456789abcdef" * 4},
        {"type": "sha1", "value": "a" * 40},
        {"type": "ipv6", "value": "2001:db8::1"},
        {"type": "url", "value": "https://example.org/Test"},
    ], tlp)
    stix2.parse(bundle)
    result = validate_instance(bundle, ValidationOptions(version="2.1"))
    assert result.is_valid, result.errors
    assert "malicious-activity" not in json.dumps(bundle)


def test_cti_valid_hash_is_not_malicious():
    processor = load_script("cti_processor").CTIProcessor(keep_noise=True)
    indicators = processor.process("0123456789abcdef" * 4 + " CVE-2024-3400 https://EXAMPLE.org/Case?X=Y")
    assert all(i["maliciousness_confidence"] is None for i in indicators)
    assert all(i["detection_readiness"] == "needs-review" for i in indicators)
    assert any(i["value"] == "https://example.org/Case?X=Y" for i in indicators)
    assert not any(a["to_ids"] for a in processor.to_misp()["Event"]["Attribute"])
    stix2.parse(processor.to_stix(), allow_custom=True)


def test_refang_does_not_corrupt_prose():
    assert refang("a dot b") == "a dot b"
    assert refang("HXXPS://a[.]com") == "https://a.com"


def test_pdf_input_rejected(tmp_path):
    source = tmp_path / "report.pdf"
    source.write_bytes(b"%PDF-1.7 binary document")
    result = subprocess.run([
        sys.executable, str(ROOT / "skills/06-threat-hunting/scripts/ioc_extractor.py"),
        "--input", str(source),
    ], capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "extract PDF/document text first" in result.stderr


@pytest.mark.parametrize("change", [{"executed": "false"}, {"outcome": "typo"},
                                    {"time_to_detect_seconds": -1}, {"technique_id": "bad"}])
def test_invalid_purple_team_records_rejected(change):
    module = load_script("detection_validator")
    with pytest.raises(ValueError):
        module.DetectionValidator([{"technique_id": "T1059.001", **change}])


def test_purple_team_excludes_unexecuted_and_overrides_release():
    module = load_script("detection_validator")
    validator = module.DetectionValidator([
        {"technique_id": "T1059.001", "executed": False, "outcome": "detection"},
        {"technique_id": "T1486", "executed": True, "outcome": "none"},
    ])
    assert validator.score()["detection_rate"] == 0
    assert validator.score()["executed"] == 1
    assert validator.navigator_layer(attack_version="18")["versions"]["attack"] == "18"
