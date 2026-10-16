# Web Security — Example Usage

## OWASP Scan

```bash
python scripts/owasp_scanner.py -u https://target.com -o report.json
python scripts/owasp_scanner.py -u https://target.com --tests a01,a02,a05 -o focused.json
```
