# Log Analysis — Example Usage

## Log Parsing

```bash
python scripts/log_parser.py -i /var/log/auth.log -o parsed.json
python scripts/log_parser.py -i events.log -f syslog --summary -o summary.json
```
