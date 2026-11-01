# Threat model / Modelo de ameaças

## Assets
- Personal identifiers in text chat messages, tool results, and tool arguments.
- Tokens and credentials accidentally included inside a JSON request body.
- Local model gateway credentials passed in `Authorization`.

## Supported boundary
- Input is JSON OpenAI `POST /v1/chat/completions`, including ordinary text arrays and tool calls.
- Output is passed through unchanged (JSON or SSE).
- Requests to other API endpoints are explicitly rejected (except `GET /v1/models`).
- Both listening socket and upstream must resolve to local loopback as configured; use a genuine local upstream.
- No redaction of protocol headers: the Authorization header is intentionally forwarded to FreeLLMAPI.
- Unknown top-level JSON keys, unsupported media types and certain credentials fail closed.

## Out of scope
- No claims of anonymity for provider account, IP, billing data, or upstream service.
- No prevention of prompt re-identification from contextual clues.
- No NER-based detection of names, addresses, places or custom sensitive terms unless configured.
- No automatic encryption or isolation of traffic inside FreeLLMAPI or its third-party providers.
- No PII checking of image, audio, file, multipart, Responses API, embeddings, completions, or Anthropic protocol.
- No stream rehydration, placeholder restoration, or session-stable pseudonyms.
- Secret detection uses heuristics; unknown token formats or passwords without labels may pass.
- A malicious local process may access the localhost listener; upstream auth still applies.
- No protection if the application bypasses VeilGate by calling upstream or providers directly.

## Design choices
- A dependency-free standard-library Python service, with no telemetry, prompt logging, cloud calls or raw content persistence.
- Explicit path allowlist, content size limits, recursive body scanning and refusal of redirects.
- Credential-like text is blocked, not merely redacted.
- Per-request placeholders retain useful structure but are not cryptographic anonymization.
- Streaming response frames are forwarded byte-for-byte to preserve tool-calling compatibility.

## Validation
Use a mock local upstream, not a real provider, to inspect outbound bytes and verify a privacy rule before trusting it. Tests assert that common identifiers are absent from upstream-captured traffic.
