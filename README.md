# VeilGate

**Local privacy proxy for OpenAI-compatible Chat Completions clients, with a focus on Hermes Agent and FreeLLMAPI.**

VeilGate examines text requests **before** they reach FreeLLMAPI. It replaces common personal identifiers with per-request placeholders and **rejects requests** that match known credential patterns. VeilGate itself does not log or persist prompts, send telemetry, or contact third-party services.

> **Privacy notice:** Pattern matching **does not guarantee anonymization**. Names, physical addresses, contextual clues, and unrecognized formats may pass through. External providers can still learn account and connection metadata through FreeLLMAPI. Review the [threat model](docs/threat-model.md) before use.

## Architecture

```text
Hermes Agent / OpenAI-compatible client
                  |
                  v
VeilGate  http://127.0.0.1:8080/v1
  |-- locally redacts email addresses, valid Brazilian CPF/CNPJ identifiers,
  |   Brazilian mobile phone numbers, and usernames in /Users or /home paths
  |-- redacts custom terms from an untracked local configuration file
  |-- blocks requests containing recognized credential patterns
  |-- validates JSON, request size, and routes; rejects multimodal content
  `-- relays JSON / SSE responses without modification
                  |
                  v
FreeLLMAPI http://127.0.0.1:3001/v1
                  |
                  v
External model providers
```

## Requirements

Python **3.11+**. The proxy uses only the Python standard library at runtime. It supports macOS (including Apple Silicon), Linux, and Windows.

## Installation

Clone the public repository and install it locally:

```bash
git clone https://github.com/MarcosAlves90/veilgate.git
cd veilgate
python3 -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
```

Start FreeLLMAPI locally on port `3001`, then launch VeilGate in another terminal:

```bash
veilgate --upstream http://127.0.0.1:3001 --listen 127.0.0.1 --port 8080
```

Check the health endpoint:

```bash
curl http://127.0.0.1:8080/healthz
```

Configure Hermes Agent, or another OpenAI-compatible Chat Completions client, to use:

```text
base_url: http://127.0.0.1:8080/v1
```

Keep your existing FreeLLMAPI API key (`freellmapi-...`) and model/API settings. VeilGate forwards the `Authorization` header only to the **local FreeLLMAPI upstream**; it does not send that header directly to external providers. Use the Chat Completions endpoint (`/v1/chat/completions`).

## Example with synthetic data

Replace the placeholder below with your **local** FreeLLMAPI key. Do not publish the actual value or paste it into an issue:

```bash
export FREELLMAPI_API_KEY='freellmapi-EXAMPLE-KEY'
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $FREELLMAPI_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"auto","messages":[{"role":"user","content":"Contact: sample@example.com; say hello"}]}'
```

The response is **not automatically restored**: if a model returns a placeholder such as `[REDACTED_EMAIL_1]`, it remains in the response. VeilGate also relays SSE responses (`"stream":true`) without modifying their content, including tool-call deltas.

## Custom private terms

```bash
cp private-terms.example.txt private-terms.txt
# Edit private-terms.txt with private local terms; never commit this file.
veilgate --private-terms private-terms.txt
```

Each noncomment line containing at least three characters is redacted without regard to letter case. Avoid overly broad terms that could alter code or other useful context. A missing or unreadable configured file prevents startup.

## Configuration

| CLI argument | Environment variable | Default |
| --- | --- | --- |
| `--listen` | `VEILGATE_LISTEN` | `127.0.0.1` |
| `--port` | `VEILGATE_PORT` | `8080` |
| `--upstream` | `VEILGATE_UPSTREAM` | `http://127.0.0.1:3001` |
| `--private-terms` | `VEILGATE_PRIVATE_TERMS_FILE` | None |

The proxy rejects non-loopback listeners, remote upstreams, and upstream redirects. It supports only `POST /v1/chat/completions`, `GET /v1/models`, and `GET /healthz`. Unsupported or invalid requests are rejected before they reach the upstream. The maximum request body is 2 MiB, and the maximum upstream response is 16 MiB.

## Tests and validation

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Tests use a mock local HTTP upstream, not real model providers, and verify the actual bytes forwarded by VeilGate. GitHub Actions runs the suite on Python 3.11, 3.12, and 3.13.

Install the optional development dependency to run tests with coverage:

```bash
python -m pip install -e '.[dev]'
python scripts/validate.py test
python scripts/validate.py coverage
```

The generated `coverage.xml` report is ignored by Git. The committed [POLIS](https://github.com/MarcosAlves90/polis) policy is in `.polis/policy.json`. If POLIS is installed, run `polis plan --repo .` and `polis gates --repo .` to validate the configured tests and the strict coverage threshold of greater than 80%. POLIS is not required to run VeilGate.

## Limitations

- Requests sent directly to FreeLLMAPI or an external provider bypass VeilGate.
- Names, postal addresses, unknown identifiers, contextual secrets, and sensitive information that must be inferred may pass through.
- `Authorization` is intentionally forwarded to the local gateway. This does not remove the external provider's account, network, or billing metadata.
- Images, audio, files, the Responses API, legacy completions, and other unsupported formats are rejected rather than silently forwarded.
- Credential detection is heuristic and cannot detect every secret format.
- Placeholder numbering is consistent **within one request**, but there is no mapping stored between requests or sessions.
- For stronger confidentiality, run the model entirely locally without using third-party model services.

## Community and security

Before contributing, read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Read [SECURITY.md](SECURITY.md) before reporting vulnerabilities. Public issues and pull requests must use synthetic data only.

## License

[MIT](LICENSE). Contributions and bug reports that contain no private or personal data are welcome.
