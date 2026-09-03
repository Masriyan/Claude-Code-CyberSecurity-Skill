# Supply Chain Security — Example Usage

## Dependency & Pipeline Audit

```bash
python scripts/supply_chain_auditor.py --project-dir . --output audit.json
python scripts/supply_chain_auditor.py --project-dir ./myapp --check-registry --output audit.json
```

## Example Prompts

```
> Audit this repo for typosquatted or floating dependencies and unpinned GitHub Actions
> Generate a CycloneDX SBOM for this project and flag anything with no known source repo
> Is this postinstall script safe to run?
> What SLSA level are our release builds at, and what would it take to reach the next one?
```
