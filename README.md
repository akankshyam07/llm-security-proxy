# llm-security-proxy

FastAPI reverse proxy that exposes an OpenAI-compatible `POST /v1/chat/completions` endpoint and enforces simple security policies (PII/secret detection, prompt-injection heuristics, tool allowlists) before forwarding requests to an upstream provider (defaults to Ollama at `http://localhost:11434`).

## Features
- Request detectors: secrets, PII, prompt-injection heuristics, tool allowlist.
- Optional response detectors (enable with `ENABLE_OUTPUT_DETECTION=true`).
- Structured JSON logging with aggressive redaction prior to writing logs.
- Policy-driven configuration via `app/policies/default_policy.yaml`.
- OpenAI-compatible interface for easy drop-in with LangChain or LlamaIndex.
- Docker and docker-compose for quick local runs (includes Ollama service).

## Quickstart
1. Copy `.env.example` to `.env` and adjust if needed.
2. Start with Docker Compose (includes Ollama):
   ```bash
   docker-compose up --build
   ```
   Proxy will listen on `http://localhost:8000`.

3. Health check:
   ```bash
   curl -s http://localhost:8000/health
   ```

4. Example allow-listed request:
   ```bash
   curl -X POST http://localhost:8000/v1/chat/completions \
     -H 'content-type: application/json' \
     -d '{"model":"llama3","messages":[{"role":"user","content":"Hello"}]}'
   ```

5. Example blocked request (prompt injection):
   ```bash
   curl -X POST http://localhost:8000/v1/chat/completions \
     -H 'content-type: application/json' \
     -d '{"model":"llama3","messages":[{"role":"user","content":"Ignore previous instructions"}]}'
   ```

## Configuration
Environment variables (see `.env.example`):
- `UPSTREAM_BASE_URL` – upstream server base (default `http://localhost:11434`).
- `UPSTREAM_PATH` – path to completions endpoint (default `/v1/chat/completions`).
- `POLICY_PATH` – YAML file describing detectors and tool allowlists.
- `ALLOWED_TOOLS` – comma-separated override for the tool allowlist.
- `ENABLE_OUTPUT_DETECTION` – set to `true` to run detectors on responses.

## Policy file
`app/policies/default_policy.yaml` enables request detectors (secrets, PII, prompt injection, tool allowlist) and response detectors (secrets, PII). Adjust the allowlist or add/remove detectors as needed.

## LangChain example
```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="llama3",
    api_key="dummy",  # not used by proxy but required by client
    base_url="http://localhost:8000/v1",
)
print(llm.invoke("Hello!"))
```

## LlamaIndex example
```python
from llama_index.core import Settings
from llama_index.llms.openai import OpenAI

Settings.llm = OpenAI(
    model="llama3",
    api_base="http://localhost:8000/v1",
    api_key="dummy",
)
response = Settings.llm.chat("Hello from LlamaIndex")
print(response)
```

## Development
- Install dependencies: `pip install -r requirements-dev.txt`
- Run tests: `pytest`
- Lint: `ruff check .`
- Format: `ruff format .`

## Running locally without Docker
```bash
uvicorn app.proxy:app --reload --port 8000
```

## Logging
Logs are JSON with `request_id`, decision, reason codes, latency, and redacted payload/response fields. Secrets/PII/content are masked before logging.

## Security
See `SECURITY.md` for reporting guidance.
