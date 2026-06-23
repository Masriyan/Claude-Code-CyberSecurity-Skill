---
name: AI & LLM Security
description: LLM and AI application security testing — prompt injection, jailbreak resistance, OWASP LLM Top 10 (2025), RAG and agent/tool-use security, model supply chain, and AI red teaming for authorized assessments
version: 3.0.0
author: Masriyan
tags: [cybersecurity, ai-security, llm, prompt-injection, owasp-llm, agent-security, rag, mlsecops, red-teaming]
---

# AI & LLM Security

## Purpose

Enable Claude to assess the security of AI/LLM-powered applications — chatbots, RAG pipelines, autonomous agents, and tool-using systems. Claude maps findings to the **OWASP Top 10 for LLM Applications (2025)** and the **MITRE ATLAS** adversarial-ML knowledge base, builds reproducible attack cases, and recommends concrete mitigations (input/output guardrails, least-privilege tool scopes, content provenance).

> **Authorization Required**: Only test AI systems you own or are explicitly authorized to assess. Prompt-injection and data-exfiltration testing against third-party AI services may violate their terms of service and local law. Confirm written scope before proceeding.

---

## Activation Triggers

This skill activates when the user asks about:
- Prompt injection (direct or indirect), jailbreaks, or system-prompt extraction
- OWASP LLM Top 10, MITRE ATLAS, or AI/ML threat modeling
- Securing a RAG pipeline, vector database, or retrieval layer
- LLM agent / tool-use / function-calling security and confused-deputy risks
- Guardrail, content-filter, or model output validation design
- Sensitive-information disclosure or training-data leakage from a model
- Model / ML supply chain security (model files, `pickle`, model registries)
- AI red teaming, jailbreak corpora, or automated adversarial prompt generation
- Securing MCP (Model Context Protocol) servers and tool integrations

---

## Prerequisites

```bash
pip install requests pyyaml rich
```

**Optional enhanced capabilities:**
- `garak` — LLM vulnerability scanner (NVIDIA)
- `promptfoo` — prompt/red-team evaluation harness
- API key for the target LLM endpoint (test environment only)
- `modelscan` / `picklescan` — ML model file safety scanning

---

## Core Capabilities

### 1. Threat Modeling (OWASP LLM Top 10 — 2025)

When asked to threat-model an AI application, map the system against each category and record exposure:

| ID | Risk | What to look for |
|----|------|------------------|
| LLM01 | Prompt Injection | Untrusted text reaching the prompt (direct & indirect via RAG/web/email) |
| LLM02 | Sensitive Information Disclosure | PII/secrets in prompts, outputs, or training data; system-prompt leakage |
| LLM03 | Supply Chain | Untrusted models, LoRA adapters, datasets, plugins, `pickle` deserialization |
| LLM04 | Data & Model Poisoning | Tainted training/fine-tune/RAG data; backdoors |
| LLM05 | Improper Output Handling | LLM output passed unsanitized to SQL, shell, browser (XSS), or `eval` |
| LLM06 | Excessive Agency | Over-broad tool scopes, autonomous side effects, no human-in-the-loop |
| LLM07 | System Prompt Leakage | Secrets/authz logic embedded in the system prompt |
| LLM08 | Vector & Embedding Weaknesses | RAG access-control bypass, embedding inversion, cross-tenant leakage |
| LLM09 | Misinformation | Hallucinations relied on for security/safety decisions |
| LLM10 | Unbounded Consumption | Cost/DoS via token floods, model extraction, wallet-drain |

Produce a per-category table: **Exposure (Yes/No/Partial) → Evidence → Severity → Mitigation**.

### 2. Prompt Injection & Jailbreak Testing

**Direct injection** — user input that overrides instructions. Test families:
- Instruction override ("ignore previous instructions and …")
- Role-play / persona escape (DAN-style, hypothetical framing)
- Encoding/obfuscation (Base64, ROT13, leetspeak, homoglyphs, zero-width chars)
- Token smuggling and prompt-boundary confusion (fake delimiters, fake system tags)
- Many-shot jailbreaking (long context of faux dialogue priming compliance)
- Crescendo / multi-turn gradual escalation

**Indirect injection** — payload arrives via retrieved/processed content (web page, PDF, email, RAG doc, tool output). This is the highest-impact class for agents. Test that retrieved text **cannot** issue commands, exfiltrate context, or trigger tools.

For every test record: payload, channel (direct/indirect), goal (override / exfiltrate / tool-abuse), and result (blocked / partial / success). Use `scripts/prompt_injection_tester.py` to run a corpus and score outcomes.

**Refusal-quality note:** a single refusal is not a pass. Re-test the same goal across ≥3 phrasings and obfuscations before marking a control effective.

### 3. RAG & Vector Store Security

When reviewing a RAG pipeline:
1. **Access control at retrieval** — confirm the vector query is filtered by the *caller's* permissions, not just the app's. Test cross-tenant / cross-user document leakage.
2. **Indirect injection surface** — treat every ingested document as attacker-controlled; verify retrieved chunks are clearly delimited and never executed as instructions.
3. **Embedding inversion / membership** — sensitive source text may be partially reconstructable from embeddings; flag PII stored unencrypted in the vector DB.
4. **Chunk poisoning** — a single malicious document can dominate retrieval; check ranking/dedup and source allow-listing.
5. **Citation integrity** — outputs should cite retrieved sources so injected claims are traceable.

### 4. Agent & Tool-Use (Function Calling / MCP) Security

The agent is a **confused deputy**: it holds privileges the user may not. Review:
- **Least-privilege tools** — each tool scoped to the minimum action; no broad `execute_shell`/`http_request` to arbitrary hosts
- **Human-in-the-loop gates** on irreversible/outbound actions (payments, email send, file delete, deploy)
- **Argument validation** — tool args are model-generated and untrusted; validate/allow-list server-side
- **Injection → tool chain** — verify retrieved/indirect content cannot drive tool calls (e.g., a web page telling the agent to email its memory out)
- **MCP server hardening** — authenticate clients, scope resources, rate-limit, log every tool invocation; never expose secrets via resource reads
- **Memory poisoning** — persistent agent memory can be seeded with malicious instructions that fire on later turns

### 5. Model & ML Supply Chain

- Scan model artifacts for unsafe deserialization — **`pickle`/`.pt`/`.bin` can execute code on load**. Prefer `safetensors`. Run `scripts/model_supply_chain.py` or `modelscan`.
- Verify model provenance, hashes, and signatures; pin versions from trusted registries.
- Review fine-tune/LoRA adapters and datasets for poisoning and licensing.
- Treat third-party plugins/MCP servers as untrusted dependencies (review + pin).

### 6. Output Handling & Guardrails

- **Never** pass raw LLM output into `eval`, SQL, shell, or innerHTML. Encode/parameterize at the sink (LLM05).
- Layered guardrails: input filter → policy in system prompt → output classifier → sink-specific sanitization. Defense in depth, since any single layer is bypassable.
- Validate structured output against a strict schema; reject on parse failure.
- Apply egress controls so an injected agent cannot reach attacker URLs.

---

## Output Standards

Produce a structured AI security assessment:

```markdown
# AI/LLM Security Assessment — [Application]
Date: [Date] | Scope: [Endpoints/Models] | Model: [name/version] | Analyst: [Name]

## Executive Summary
[2-3 sentences: overall posture, highest risks]

## OWASP LLM Top 10 Coverage
| ID | Risk | Exposure | Severity | Evidence |
|----|------|----------|----------|----------|
| LLM01 | Prompt Injection | Yes | High | [repro] |
...

## Confirmed Findings
### [F-01] Indirect Prompt Injection via RAG → Tool Abuse  (Critical)
- ATLAS: AML.T0051 / OWASP LLM01+LLM06
- Repro: [payload, channel, steps]
- Impact: [data exfil / unauthorized action]
- Mitigation: [least-privilege tool scope + retrieved-content isolation + HITL]

## Guardrail Bypass Matrix
| Goal | Direct | Encoded | Multi-turn | Indirect | Result |

## Recommendations (Prioritized)
1. ...
```

---

## Script Reference

### `prompt_injection_tester.py`
```bash
# Run the built-in injection/jailbreak corpus against an endpoint
python scripts/prompt_injection_tester.py --url https://app.test/api/chat --field message --output results.json

# Use a custom payload corpus and a refusal-detection keyword set
python scripts/prompt_injection_tester.py --url ... --corpus payloads.txt --judge-keywords refusals.txt
```

### `model_supply_chain.py`
```bash
# Scan a model directory/file for unsafe pickle opcodes and risky imports
python scripts/model_supply_chain.py --path ./models/model.pt
python scripts/model_supply_chain.py --path ./models/ --recursive --output scan.json
```

---

## Skill Integration

| Next Step | Condition | Target Skill |
|-----------|-----------|--------------|
| Web/API vuln testing of the app shell | App exposes web/API surface | → Skill 09 |
| Cloud/infra hosting the model | Model served on AWS/Azure/GCP/K8s | → Skill 10 |
| Detection rules for prompt-injection attempts | Need SIEM coverage | → Skill 12 |
| Dependency/model-package CVEs | ML libs in use | → Skill 02 |
| Red team narrative incorporating AI abuse | Full engagement | → Skill 14 |

---

## References

- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)
- [MITRE ATLAS — Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework (AI RMF 1.0) + Generative AI Profile](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP Agentic AI — Threats and Mitigations](https://genai.owasp.org/)
- [Google SAIF — Secure AI Framework](https://saif.google/)
- [NVIDIA garak — LLM vulnerability scanner](https://github.com/NVIDIA/garak)
