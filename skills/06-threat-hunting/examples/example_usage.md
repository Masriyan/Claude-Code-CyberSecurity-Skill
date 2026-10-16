# Threat Hunting — Example Usage

## IOC Extraction

```bash
python scripts/ioc_extractor.py -i threat_report.txt -o iocs.json
python scripts/ioc_extractor.py -i report.txt --defang -f csv -o iocs.csv
python scripts/ioc_extractor.py -i report.txt -f stix -o iocs_stix.json
```

## MITRE ATT&CK Mapping

```bash
python scripts/mitre_mapper.py -t T1059.001 -o technique.json
python scripts/mitre_mapper.py -i techniques.txt --navigator -o layer.json
python scripts/mitre_mapper.py -t T1110.001 --detection-query splunk
```
