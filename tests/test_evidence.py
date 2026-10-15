"""Validate real provenance and reject malformed handoff artifacts."""
import hashlib
import json

import jsonschema
import pytest

from conftest import ROOT
from cyberskill.evidence import artifact_record


def test_provenance_schema_and_tampering(tmp_path):
    source = tmp_path / "log.txt"
    source.write_bytes(b"benign event\n")
    record = artifact_record(str(source), "12-log-analysis")
    schema = json.loads((ROOT / "schemas/evidence.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    validator.validate(record)
    assert record["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    source.write_bytes(b"changed")
    assert artifact_record(str(source), "12-log-analysis")["sha256"] != record["sha256"]
    record["sha256"] = "invalid"
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(record)


def test_invalid_mode(tmp_path):
    with pytest.raises(ValueError):
        artifact_record(str(tmp_path), "test", "unrestricted")
