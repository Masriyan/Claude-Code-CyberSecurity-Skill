# Recon & OSINT — Example Usage

## Subdomain Enumeration

### Passive Only (Safest)

```bash
python scripts/subdomain_enum.py -d example.com --passive-only -o results.json
```

### With Brute-Force

```bash
python scripts/subdomain_enum.py -d example.com -w /usr/share/wordlists/subdomains.txt -t 20 -o results.json
```

### Custom DNS Server

```bash
python scripts/subdomain_enum.py -d example.com -n 8.8.8.8 --passive-only
```

## DNS Reconnaissance

### Full DNS Recon

```bash
python scripts/dns_recon.py -d example.com -o dns_report.json
```

### Check Zone Transfer

```bash
python scripts/dns_recon.py -d example.com --check-zone-transfer -v
```

## Technology Fingerprinting

### Single Target

```bash
python scripts/tech_fingerprint.py -u https://example.com -o tech.json
```

### Multiple Targets

```bash
echo "https://site1.com\nhttps://site2.com" > targets.txt
python scripts/tech_fingerprint.py -U targets.txt -o report.json
```

## Integration Workflow

```bash
# Step 1: Discover subdomains
python scripts/subdomain_enum.py -d target.com --passive-only -o subs.json

# Step 2: DNS recon on the domain
python scripts/dns_recon.py -d target.com -o dns.json

# Step 3: Fingerprint discovered web services
# (Extract URLs from subs.json and pass to fingerprinter)
python scripts/tech_fingerprint.py -U discovered_urls.txt -o tech.json
```
