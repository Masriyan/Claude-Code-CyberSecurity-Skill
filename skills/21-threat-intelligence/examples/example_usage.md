# Threat Intelligence & CTI — Example Usage

## Extract & Export Indicators

```bash
# Extract, defang, normalize, and dedup IOCs from a report; print a summary
python scripts/cti_processor.py --input report.txt

# Full dissemination set: JSON list + STIX 2.1 bundle + MISP event, TLP:AMBER, source B2
python scripts/cti_processor.py --input report.txt \
    --tlp AMBER --source-score B2 \
    --output iocs.json --stix iocs_stix.json --misp event.json

# Keep private/documentation indicators (e.g. internal lab reports)
python scripts/cti_processor.py --input report.txt --keep-noise

# Optional live domain enrichment (RDAP; needs `requests`)
python scripts/cti_processor.py --input report.txt --enrich --output iocs.json

# Self-contained demo on a bundled sample report
python scripts/cti_processor.py --demo
```

## Example Prompts

```
> Pull every IOC out of this vendor report, defang them, and give me a STIX bundle
> Score this source A–F/1–6 and tell me how much confidence the attribution deserves
> Build a Diamond Model for this intrusion and map the observed behavior to ATT&CK
> Turn these indicators into a MISP event marked TLP:AMBER for our ISAC
> Write a strategic one-pager for leadership from this tactical report
> What are good PIRs for a healthcare org worried about ransomware this quarter?
> These indicators are 9 months old — which should we expire before pushing to the firewall?
```

## Interpreting the Output

- **Confidence** is heuristic: hashes/CVEs/BTC are `high` (self-identifying), network indicators are `medium`, bare regex-extracted domains are `low`. Verify a `low`/`medium` indicator before publishing it as confirmed.
- **Kill-chain phase** is inferred from surrounding keywords — treat it as a hint, not ground truth.
- **`--source-score`** is validated as an Admiralty code (letter `A`–`F` + digit `1`–`6`); it scores the *source*, separate from the per-indicator confidence.
- **`--tlp`** stamps every exported indicator and the STIX marking-definition — set it to the sharing contract you actually have.

## Typical Handoffs

| After this skill | Go to |
|------------------|-------|
| Indicators ready to hunt | Skill 06 — Threat Hunting |
| A sample needs technical analysis | Skill 05 — Malware Analysis |
| TTPs need to become detections | Skill 12 (Sigma) / Skill 15 (Blue Team) |
| Validate the actor's TTPs are detected | Skill 22 — Purple Team |
