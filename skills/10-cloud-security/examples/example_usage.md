# Cloud Security — Example Usage

## IaC Scanning

```bash
python scripts/iac_scanner.py -p ./terraform/ -o findings.json
python scripts/iac_scanner.py -p ./k8s/ -t kubernetes -o k8s_audit.json
python scripts/iac_scanner.py -p ./docker/ -t docker -o docker_audit.json
```
