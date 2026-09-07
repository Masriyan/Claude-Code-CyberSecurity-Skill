---
name: Threat Intelligence & CTI
description: Cyber threat intelligence production — the intelligence cycle, IOC extraction/normalization/enrichment, STIX/TAXII and MISP, structured analytic models (Diamond, Kill Chain, ATT&CK), source scoring, actor/campaign tracking, and finished intelligence reporting
version: 3.1.0
author: Masriyan
tags: [cybersecurity, threat-intelligence, cti, stix, taxii, misp, diamond-model, attribution, ioc, tlp]
---

# Threat Intelligence & CTI

## Purpose

Enable Claude to turn raw observations into *finished intelligence* — assessments a defender can act on and decision-makers can trust. This skill governs the whole intelligence cycle: framing requirements, collecting and normalizing indicators, applying structured analytic models, scoring sources and confidence, tracking actors and campaigns, and disseminating in machine-readable (STIX/MISP) and human-readable (report) form.

This is distinct from Skill 06 (Threat Hunting): hunting *uses* intelligence to search an environment for adversary activity; this skill *produces and manages* the intelligence itself. It is also distinct from Skill 05 (Malware Analysis), which produces the technical facts this skill contextualizes and disseminates.

---

## Activation Triggers

This skill activates when the user asks about:
- Extracting, defanging/refanging, normalizing, or deduplicating IOCs from reports, emails, or feeds
- Producing a STIX 2.1 bundle, a MISP event, or a TAXII-servable indicator set
- Scoring the reliability of a source or the confidence of an assessment (Admiralty/NATO code, words of estimative probability)
- Applying the Diamond Model, Cyber Kill Chain, or MITRE ATT&CK to structure an intrusion
- Tracking or clustering a threat actor / campaign, or reasoning about attribution
- Writing a tactical, operational, or strategic threat intelligence report or an intelligence estimate
- Setting Priority Intelligence Requirements (PIRs) or building a collection plan
- TLP marking, intelligence dissemination, or feed aging/decay and false-positive suppression
- Enriching an indicator (WHOIS/passive DNS/reputation) or pivoting from one indicator to related infrastructure

---

## Prerequisites

```bash
python3 --version          # 3.10+; standard library only for the core script
pip install requests       # optional — only for --enrich (live reputation/WHOIS lookups)
```

**Optional enhanced tooling:**
- `misp` / PyMISP — event creation and sharing on a MISP instance
- `stix2` / `taxii2-client` (OASIS) — richer STIX object modeling and TAXII push/pull
- `opencti` — CTI platform for actor/campaign knowledge-graph management
- A passive-DNS / reputation provider (VirusTotal, Shodan, GreyNoise, urlscan) for enrichment

> **Handling live malware and indicators:** treat sample hashes, live C2 domains, and payload URLs as hostile. Keep them defanged in prose (`hxxp://`, `evil[.]com`), never resolve or fetch them from a production host, and mark sharing scope with TLP before dissemination.

---

## Core Capabilities

### 1. The Intelligence Cycle & Requirements

Anchor every task to where it sits in the cycle, and never skip framing:

1. **Direction** — establish Priority Intelligence Requirements (PIRs). A good PIR is a decision-relevant question with a consumer and a deadline (e.g., "Which ransomware groups actively target our sector's ERP stack this quarter?"), not "tell me about threats."
2. **Collection** — map each PIR to specific sources (internal telemetry, OSINT, commercial feeds, ISAC/sharing communities) and note collection gaps explicitly.
3. **Processing** — normalize, defang, deduplicate, translate, and structure raw data (see §2).
4. **Analysis** — apply structured models (§3) and estimative language (§4); separate *observation* from *assessment*.
5. **Dissemination** — deliver in the form the consumer can use (§5): STIX for machines, a brief for executives, a detection for the SOC.
6. **Feedback** — capture whether the product answered the PIR and refine.

State which stage a request touches and what the governing PIR is before producing output.

### 2. IOC Extraction, Normalization & Enrichment

**When the user provides a report, email, or blob and asks for indicators:**

1. **Extract** IPv4/IPv6, domains, URLs, email addresses, file hashes (MD5/SHA1/SHA256), CVE IDs, ASNs, registry keys, mutexes, and Bitcoin/crypto addresses.
2. **Refang then re-defang consistently** — accept `hxxp`, `[.]`, `(dot)`, `[at]`, `\.`; internally canonicalize; always emit defanged in prose and clean values only inside structured/quoted fields.
3. **Normalize** — lowercase domains, strip URL fragments/default ports where irrelevant, validate hash length per algorithm, drop obvious noise (RFC 1918/loopback/`example.com`/documentation ranges) unless the user asks to keep them.
4. **Deduplicate & type** each indicator, and attach context: first/last seen, the report it came from, the kill-chain phase it maps to, and a confidence.
5. **Enrich** (optional) — WHOIS/registrar, passive DNS, ASN/geo, reputation, and relationships (this domain resolves to that IP, that IP hosts these other domains) to enable pivoting.
6. Use `scripts/cti_processor.py` for the automatable extraction/defang/normalize/dedup/STIX-export steps; apply human judgment before publishing anything as a confirmed indicator.

### 3. Structured Analytic Models

Choose the model that fits the question; layer them rather than treating them as alternatives:

- **Diamond Model** — for a single intrusion event, populate the four vertices (adversary, capability, infrastructure, victim) plus meta-features (timestamp, phase, result, direction, methodology). Pivot across vertices to expand knowledge (from one capability to the infrastructure that delivered it, etc.).
- **Cyber Kill Chain** (Lockheed Martin) — sequence observed activity across Recon → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives. Earlier detection is cheaper; note the earliest phase with a detection opportunity.
- **MITRE ATT&CK** — map each observed behavior to a technique/sub-technique ID and tactic. This is the lingua franca that hands off to Skills 06, 12, 15, and 22.
- **Analysis of Competing Hypotheses (ACH)** — when attribution or intent is contested, enumerate hypotheses, list evidence, and score evidence by how well it *dis*confirms each hypothesis (diagnostic evidence), not how well it confirms your favorite.

### 4. Source & Confidence Scoring

Separate *how much you trust the source* from *how much you trust the claim*, and make both explicit:

- **Admiralty / NATO source-reliability code** — reliability `A`–`F` (Reliable → Cannot be judged) × information credibility `1`–`6` (Confirmed → Cannot be judged). Report as e.g. `B2`.
- **Words of estimative probability** — use calibrated language ("almost certainly", "likely", "roughly even chance", "unlikely") and, where useful, an explicit percentage band; never let "could" masquerade as "will".
- **Confidence level** (low/medium/high) on each *assessment*, with the drivers named (source count, corroboration, analytic assumptions).
- Flag assumptions and information gaps in-line — an unstated assumption is the most common failure mode in CTI.

### 5. Actor & Campaign Tracking + Attribution Discipline

1. **Cluster by TTP first, name later.** Group activity into an unnamed activity cluster (UNC-style) from shared infrastructure, tooling, and behavior before reaching for a public actor name.
2. **Attribution is a spectrum, not a verdict.** Distinguish *technical* attribution (this cluster did this) from *actor* attribution (this named group) from *nation/sponsor* attribution (the hardest and most consequential). State the confidence and the evidence class for each level.
3. **Beware overlap and false flags** — shared tooling, commodity malware, and deliberate false flags make single-indicator attribution unreliable. Weight durable behavioral TTPs over swappable infrastructure.
4. Track campaigns with a consistent internal schema (cluster ID, aliases, associated malware, targeted sectors/geos, first/last activity) and map aliases across vendor naming (MISP galaxies help).

### 6. Production, Dissemination & Feed Hygiene

- **Match the product to the consumer** — *tactical* (IOCs/detections for the SOC), *operational* (TTPs/campaigns for defenders and IR), *strategic* (trends/risk for leadership). One input often yields three different products.
- **TLP 2.0 marking** on every product (`TLP:RED / AMBER+STRICT / AMBER / GREEN / CLEAR`) — the marking is the sharing contract; state it before distributing.
- **Machine-readable dissemination** — emit STIX 2.1 bundles (indicators, relationships, marking-definitions) for automated ingestion; MISP events for community sharing; TAXII for pull/push.
- **Feed hygiene** — indicators decay. Apply aging/scoring so stale indicators expire, suppress known-false-positive infrastructure (CDNs, sinkholes, shared hosting) with an allowlist, and never push an un-triaged feed straight to blocking.

---

## Output Template

```markdown
# Threat Intelligence Product
**Title:** [Short descriptive title]
**Date:** [YYYY-MM-DD]  |  **TLP:** [RED / AMBER+STRICT / AMBER / GREEN / CLEAR]
**Product type:** [Tactical / Operational / Strategic]
**PIR addressed:** [the requirement this answers]

---

## Bottom Line Up Front (BLUF)
[2–3 sentences of assessment, with an estimative-language judgment and an overall confidence level.]

## Key Assessments
- [Assessment 1] — *Confidence: [Low/Med/High]* — *Source: [Admiralty e.g. B2]*
- [Assessment 2] — ...

## Diamond / Kill Chain Summary
| Vertex / Phase | Observed |
|----------------|----------|
| Adversary | [cluster/actor + attribution confidence] |
| Capability | [malware/tooling + ATT&CK techniques] |
| Infrastructure | [C2/staging + defanged] |
| Victim | [sector/geo/asset] |
| Earliest detection opportunity | [kill-chain phase] |

## Indicators of Compromise
| Indicator (defanged) | Type | Kill-chain phase | Confidence | First seen | Source |
|----------------------|------|------------------|------------|-----------|--------|

## ATT&CK Techniques Observed
| Tactic | Technique (ID) | Evidence |
|--------|----------------|----------|

## Assumptions & Intelligence Gaps
- [Assumption / gap and how it affects confidence]

## Recommended Actions
- [Detection to deploy → Skill 12 / 15] · [Hunt to run → Skill 06] · [Emulation to validate → Skill 22]
```

---

## Script Reference

### `cti_processor.py`
```bash
# Extract, defang, normalize, dedup IOCs from a report and print a summary
python scripts/cti_processor.py --input report.txt

# Emit a STIX 2.1 bundle and a MISP-style event
python scripts/cti_processor.py --input report.txt --stix iocs_stix.json --misp event.json

# Tag every indicator with a TLP marking and an Admiralty source score
python scripts/cti_processor.py --input report.txt --tlp AMBER --source-score B2 --output iocs.json

# Optional live enrichment (adds network calls; requires `requests`)
python scripts/cti_processor.py --input report.txt --enrich --output iocs.json

# Self-contained demonstration on a bundled sample report
python scripts/cti_processor.py --demo
```

Extracts IPv4/IPv6, domains, URLs, emails, MD5/SHA1/SHA256 hashes, CVEs, ASNs, and crypto addresses; refangs mixed defang styles, canonicalizes and validates, drops private/documentation noise, deduplicates, and exports STIX 2.1 / MISP-style JSON with TLP and Admiralty scoring. Extraction and confidence are heuristic — verify before publishing an indicator as confirmed.

---

## Skill Integration

| Condition | Next Skill |
|-----------|------------|
| Indicators ready to search an environment | → Skill 06 (Threat Hunting) |
| A malware sample underlies the reporting | → Skill 05 (Malware Analysis) for the technical facts |
| A referenced CVE needs prioritization | → Skill 02 (Vulnerability Scanner) for CVSS/EPSS/KEV |
| Indicators/TTPs need to become detections | → Skill 12 (Log Analysis / Sigma) and Skill 15 (Blue Team) |
| Assessments should drive an emulation | → Skill 22 (Purple Team) to validate detection of the actor's TTPs |
| CTI shapes an offensive engagement's threat model | → Skill 14 (Red Team Operations) |
| Strategic risk framing for leadership/compliance | → Skill 19 (GRC & Compliance) |
| Intelligence produced during live IR | ← Skill 07 (Incident Response) |

---

## References

- [STIX 2.1 (OASIS)](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) · [TAXII 2.1 (OASIS)](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [The Diamond Model of Intrusion Analysis (Caltagirone, Pendergast, Betz)](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [MISP — Open Source Threat Intelligence Platform](https://www.misp-project.org/)
- [FIRST Traffic Light Protocol (TLP) 2.0](https://www.first.org/tlp/)
- [Admiralty / NATO source-reliability grading](https://en.wikipedia.org/wiki/Admiralty_code)
- [CIA — Words of Estimative Probability (Sherman Kent)](https://www.cia.gov/resources/csi/studies-in-intelligence/)
- [Psychology of Intelligence Analysis / ACH (Richards Heuer)](https://www.cia.gov/resources/csi/books-monographs/psychology-of-intelligence-analysis-2/)
