"""Conservative, local-only text sanitization. No network calls or telemetry."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field


class RejectedInput(ValueError):
    """Request cannot safely be forwarded."""


# Strong indicators of credentials: BLOCK, rather than attempting reversible masking.
SECRET_PATTERNS = (
    re.compile(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|gsk_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b"),
    re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:authorization\s*:\s*bearer|(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=])\s*['\"]?[^\s,'\"}]{8,}"),
)
EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
CPF_RE = re.compile(r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)")
CNPJ_RE = re.compile(r"(?<!\d)\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}(?!\d)")
PHONE_RE = re.compile(r"(?<!\d)(?:\+55[\s-]?)?\(?[1-9]\d\)?[\s-]?9\d{4}[\s-]?\d{4}(?!\d)")
HOME_RE = re.compile(r"(?P<prefix>/(?:Users|home)/)(?P<username>[^/\s\"'\\]+)")


def _valid_cpf(text: str) -> bool:
    digits = [int(c) for c in text if c.isdigit()]
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for size in (9, 10):
        value = (sum(d * (size + 1 - i) for i, d in enumerate(digits[:size])) * 10) % 11
        if (0 if value == 10 else value) != digits[size]:
            return False
    return True


def _valid_cnpj(text: str) -> bool:
    digits = [int(c) for c in text if c.isdigit()]
    if len(digits) != 14 or len(set(digits)) == 1:
        return False
    for weights, check in (([5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2], 12),
                           ([6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2], 13)):
        r = sum(d * w for d, w in zip(digits, weights)) % 11
        if (0 if r < 2 else 11 - r) != digits[check]:
            return False
    return True


@dataclass
class Sanitizer:
    private_terms: tuple[str, ...] = ()
    count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _seen: dict[tuple[str, str], str] = field(default_factory=dict)

    def _replace(self, kind: str, value: str) -> str:
        key = (kind, value.casefold())
        if key not in self._seen:
            self.count[kind] += 1
            self._seen[key] = f"[REDACTED_{kind}_{self.count[kind]}]"
        return self._seen[key]

    def clean(self, text: str) -> str:
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                raise RejectedInput("Possible credential in request body")
        if self.private_terms:
            terms = sorted((x for x in self.private_terms if x), key=len, reverse=True)
            for term in terms:
                text = re.sub(re.escape(term), lambda m: self._replace("CUSTOM", m.group()), text, flags=re.IGNORECASE)
        text = EMAIL_RE.sub(lambda m: self._replace("EMAIL", m.group()), text)
        text = CPF_RE.sub(lambda m: self._replace("CPF", m.group()) if _valid_cpf(m.group()) else m.group(), text)
        text = CNPJ_RE.sub(lambda m: self._replace("CNPJ", m.group()) if _valid_cnpj(m.group()) else m.group(), text)
        text = PHONE_RE.sub(lambda m: self._replace("PHONE", m.group()), text)
        text = HOME_RE.sub(lambda m: m.group('prefix') + self._replace("USER", m.group('username')), text)
        return text


# OpenAI Chat Completions request fields only: unknown fields fail closed rather than
# silently allowing uninspected content through a new API feature.
ALLOWED_FIELDS = frozenset({
    "model", "messages", "tools", "tool_choice", "stream", "stream_options", "temperature",
    "top_p", "max_tokens", "max_completion_tokens", "presence_penalty", "frequency_penalty",
    "stop", "n", "response_format", "seed", "parallel_tool_calls", "logit_bias",
    "user", "metadata", "service_tier", "reasoning_effort", "verbosity", "store",
})
MEDIA_KEYS = frozenset({"image_url", "input_audio", "audio_url", "file_data", "file_id", "image", "video", "attachments", "input_image", "input_file"})
STRUCTURAL_KEYS = frozenset({"role", "type", "model", "tool_call_id", "id", "name"})


def sanitize_request(payload: object, sanitizer: Sanitizer) -> dict:
    if not isinstance(payload, dict):
        raise RejectedInput("JSON root must be an object")
    if unknown := (payload.keys() - ALLOWED_FIELDS):
        raise RejectedInput("Unsupported top-level field(s): " + ", ".join(sorted(unknown)))
    if not isinstance(payload.get("model"), str) or not payload["model"]:
        raise RejectedInput("model must be a non-empty string")
    if not isinstance(payload.get("messages"), list) or not payload["messages"]:
        raise RejectedInput("messages must be a non-empty array")
    if "stream" in payload and not isinstance(payload["stream"], bool):
        raise RejectedInput("stream must be boolean")
    for message in payload["messages"]:
        if not isinstance(message, dict) or message.get("role") not in ("system", "developer", "user", "assistant", "tool", "function"):
            raise RejectedInput("invalid message role")
        content = message.get("content")
        if isinstance(content, list):
            if not all(isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str) for item in content):
                raise RejectedInput("Only text content parts are supported")
        elif content is not None and not isinstance(content, str):
            raise RejectedInput("Only text message content is supported")
    nodes = 0

    def visit(obj: object, key: str = "", depth: int = 0) -> object:
        nonlocal nodes
        nodes += 1
        if depth > 35 or nodes > 50000:
            raise RejectedInput("Request structure exceeds limits")
        if isinstance(obj, str):
            if key in STRUCTURAL_KEYS:
                # Preserve protocol identifiers; refuse the request if they contain PII/secrets.
                if sanitizer.clean(obj) != obj:
                    raise RejectedInput("Sensitive data in structural field")
                return obj
            return sanitizer.clean(obj)
        if isinstance(obj, list):
            return [visit(value, depth=depth + 1) for value in obj]
        if isinstance(obj, dict):
            for item_key in obj:
                if not isinstance(item_key, str) or item_key in MEDIA_KEYS:
                    raise RejectedInput("Unsupported media field or non-string key")
                # Do not allow PII in keys; modifying protocol keys would break semantics.
                if sanitizer.clean(item_key) != item_key:
                    raise RejectedInput("Sensitive data in JSON field name")
            return {k: visit(v, k, depth + 1) for k, v in obj.items()}
        if obj is None or type(obj) in (bool, int, float):
            return obj
        raise RejectedInput("Unsupported JSON value")

    return visit(payload)
