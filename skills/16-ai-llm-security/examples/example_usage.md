# AI & LLM Security — Example Usage

## Prompt Injection / Jailbreak Testing

### Run the built-in corpus against a chat endpoint

```bash
python scripts/prompt_injection_tester.py \
  --url https://app.test/api/chat \
  --field message \
  --output injection_results.json
```

### OpenAI-style response shape (dotted response path)

```bash
python scripts/prompt_injection_tester.py \
  --url https://app.test/v1/chat \
  --field message \
  --response-path "choices.0.message.content" \
  --header "Authorization: Bearer $TEST_TOKEN"
```

### Custom payload corpus + custom refusal keywords

```bash
python scripts/prompt_injection_tester.py \
  --url https://app.test/api/chat \
  --corpus my_payloads.txt \
  --judge-keywords refusal_words.txt
```

## Model Supply Chain Scanning

### Scan a single PyTorch checkpoint

```bash
python scripts/model_supply_chain.py --path ./models/model.pt
```

### Recursively scan a model directory and export JSON

```bash
python scripts/model_supply_chain.py --path ./models --recursive --output model_scan.json
```

## Conversational Examples (skill activates automatically)

```
> Threat-model this RAG chatbot against the OWASP LLM Top 10
> Review my LangChain agent's tools for excessive agency
> Build a test set to check whether indirect injection via retrieved docs can trigger tool calls
> Is this .pt model file safe to load? Scan it for pickle code execution
> Design layered guardrails for an LLM that writes SQL from user questions
```

## Integration Workflow

```bash
# 1. Scan model artifacts before deployment (supply chain / LLM03)
python scripts/model_supply_chain.py --path ./models --recursive -o model_scan.json

# 2. Test the running app for prompt injection (LLM01)
python scripts/prompt_injection_tester.py --url https://app.test/api/chat --field message -o inj.json

# 3. Feed confirmed injection signatures to Skill 12 for SIEM detection rules
# 4. Feed app web/API surface to Skill 09 for traditional vuln testing
```
