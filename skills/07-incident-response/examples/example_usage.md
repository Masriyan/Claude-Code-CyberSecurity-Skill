# Incident Response — Example Usage

## Timeline Building

```bash
python scripts/timeline_builder.py -l ./collected_logs/ -o timeline.csv -f csv
python scripts/timeline_builder.py -l /var/log/ -o timeline.html -f html --start "2024-01-15" --end "2024-01-16"
python scripts/timeline_builder.py -l auth.log -o timeline.json -f json
```
