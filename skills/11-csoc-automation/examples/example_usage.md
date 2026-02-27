# CSOC Automation — Example Usage

## Alert Triage

```bash
python scripts/alert_triager.py --alerts siem_export.json -o triage_results.json
python scripts/alert_triager.py --alerts alerts.json -o prioritized.json -v
```
