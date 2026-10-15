# Quality and migration notes — 3.2 foundation

## Reproduce checks

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
make check PYTHON=.venv/bin/python
```

The suite checks 22 frontmatter documents, exact marketplace membership, all 35
script help/error interfaces, IOC regression cases, STIX parsing and OASIS schema
validation, malformed purple-team inputs, and artifact provenance. These tests do
not measure detection precision or Claude activation quality.

Ruff currently gates correctness rules E9/F63/F7/F82, not full style compliance.
Bandit gates medium/high findings in `cyberskill/` and `tools/`. CI additionally
publishes the full legacy-script scan as an advisory artifact. Legacy findings
need contextual review, especially authorized security-testing templates.
`stix2-validator` is pinned to 3.2.0: the tested 3.3.1 wheel lacked required schemas.

## Output compatibility changes

- CTI `confidence` is replaced by `extraction_confidence`; maliciousness confidence
  defaults to null, relevance to unverified, readiness to needs-review.
- CTI and IOC STIX exports contain cyber-observable objects rather than malicious
  indicator assertions. Hash algorithm names are STIX-compatible; IDs use UUIDs.
  Unsupported kinds are listed in `x_cyberskill_unsupported_types`.
- TLP 2.0 is preserved as a statement marking, not misrepresented as legacy STIX TLP.
- MISP-style attributes default to `to_ids: false`, threat level undefined.
- URL path/query case is preserved. IOC CLI rejects binary/PDF input; convert to text first.
- Purple-team scoring rejects invalid booleans, technique IDs, outcomes, and negative/non-finite times.
- Navigator CLI supports `--attack-version`; changing it does not update the bundled
  technique knowledge. Mapper remains a limited legacy v14 subset, not current/full ATT&CK.
- Keep the full plugin directory when distributing scripts: the shared `cyberskill/`
  package is required by skills 06 and 21.

## Evidence foundation

```bash
python tools/evidence_manifest.py results.json --producer 21-threat-intelligence > manifest.json
```

Each list entry conforms to `schemas/evidence.schema.json`. This records the bytes'
SHA-256, source, collection time, producer, and declared execution mode. A hash proves
byte identity, not source authenticity or maliciousness. Mode is metadata, not an
OS sandbox. The tool does not execute artifacts or perform network requests.

## Remaining roadmap (not shipped functionality)

- End-to-end workflow runner with scoped execution enforcement and validated handoffs.
- Behavioral fixtures for every legacy script; Sigma/YARA backend execution and rule QA.
- Versioned upstream ATT&CK ingestion and dataset-derived release metadata.
- Source-linked IOC evidence spans, confidence calibration and temporal decay.
- Skills 23–30: Detection QA, Identity, Digital Risk, Email, Vulnerability Research,
  Knowledge Graph, Forensic Correlation, and MCP Trust Validation.
- With-skill/without-skill activation benchmarks using recorded model/version and
  labeled near-miss prompts. Targets (95% precision, 90% recall) are not measured results.

The evidence contract in all 22 skills is instruction-level guidance. It does not
retroactively make every existing generator schema-validated or enforce execution
permissions outside a controlled runner.
