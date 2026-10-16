# GRC & Compliance — Example Usage

## Risk Register Scoring

### YAML input (`risks.yaml`)

```yaml
risks:
  - id: R-001
    risk: Ransomware encrypts file servers
    asset: File services
    threat: Organized crime
    likelihood: 4
    impact: 5
    control_effectiveness: 0.6   # 0..1, how much existing controls reduce it
    treatment: Mitigate
    owner: IT Ops
    due: 2026-09-30
  - id: R-002
    risk: Phishing leads to credential theft
    asset: M365 tenant
    threat: Phishing
    likelihood: 5
    impact: 3
    control_effectiveness: 0.4
    treatment: Mitigate
    owner: SecOps
    due: 2026-08-15
```

```bash
python scripts/risk_register.py --input risks.yaml --output risk_register.json
```

### Quantitative (ALE) view from CSV

```bash
# CSV with sle ($ per event) and aro (events/year) columns
python scripts/risk_register.py --input risks.csv --quant --output register.json
```

## Cross-Framework Control Mapping

```bash
# Show how "access control" maps across all frameworks
python scripts/control_mapper.py --control "access control" --frameworks all

# Map a NIST CSF 2.0 subcategory to ISO 27001 + SOC 2
python scripts/control_mapper.py --csf PR.AA-01 --frameworks iso27001,soc2

# List available control domains
python scripts/control_mapper.py --list
```

## Conversational Examples (skill activates automatically)

```
> Run a risk assessment for our customer-facing web app and build a risk register
> We're pursuing SOC 2 Type II — do a gap analysis and remediation roadmap
> Map our existing ISO 27001 controls to NIST CSF 2.0 so we don't double our audit work
> Draft an Acceptable Use Policy and map it to the controls it satisfies
> Build an evidence index for our upcoming SOC 2 audit
> Create a Statement of Applicability template for ISO 27001:2022 Annex A
```

## Integration Workflow

```bash
# 1. Score risks (this skill)
python scripts/risk_register.py --input risks.yaml -o register.json
# 2. Map controls across frameworks to reuse evidence
python scripts/control_mapper.py --control "logging and monitoring"
# 3. Validate technical controls work: → Skill 02/09/10
# 4. Prove detection coverage (DE function): → Skill 12/15
# 5. AI systems in scope → Skill 16 for AI governance controls
```
