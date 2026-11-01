"""Minimal OpenAI Chat Completions privacy gateway, binding to loopback only."""
from __future__ import annotations

import argparse
import http.client
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .privacy import RejectedInput, Sanitizer, sanitize_request

MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def validate_upstream(raw: str) -> tuple[str, int]:
    url = urlsplit(raw)
    if (url.scheme != "http" or url.hostname not in ("127.0.0.1", "localhost", "::1")
            or url.path not in ("", "/") or url.query or url.fragment or url.username or url.password):
        raise ValueError("Upstream must be a loopback HTTP origin such as http://127.0.0.1:3001")
    try:
        return url.hostname, url.port or 80
    except ValueError as exc:
        raise ValueError("Invalid upstream port") from exc


def read_private_terms(filename: str | None) -> tuple[str, ...]:
    if not filename:
        return ()
    text = Path(filename).read_text(encoding="utf-8")  # fail closed on unreadable configuration
    terms = tuple(t.strip() for t in text.splitlines() if t.strip() and not t.lstrip().startswith("#"))
    if any(len(term) < 3 for term in terms):
        raise ValueError("Each private term must be at least 3 characters")
    return terms


def handler_factory(upstream: tuple[str, int], private_terms: tuple[str, ...]):
    class Handler(BaseHTTPRequestHandler):
        server_version = "VeilGate"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:
            # Never log prompts, URLs, request headers, tokens, or upstream messages.
            pass

        def _error(self, status: int, message: str) -> None:
            body = json.dumps({"error": {"message": message, "type": "veilgate_error"}}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def _relay(self, method: str, path: str, body: bytes | None, stream: bool = False) -> None:
            headers = {"Accept": "text/event-stream" if stream else "application/json", "Accept-Encoding": "identity"}
            auth = self.headers.get("Authorization")
            if auth:
                headers["Authorization"] = auth
            if body is not None:
                headers["Content-Type"] = "application/json"
            connection = http.client.HTTPConnection(*upstream, timeout=120)
            try:
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                if 300 <= response.status < 400:
                    self._error(502, "Upstream redirects are refused")
                    return
                content_type = response.getheader("Content-Type", "application/json").split(";", 1)[0].strip().lower()
                if content_type not in ("application/json", "text/event-stream"):
                    self._error(502, "Unsupported upstream content type")
                    return
                if stream and content_type != "text/event-stream" and response.status < 400:
                    self._error(502, "Streaming upstream did not return SSE")
                    return
                if content_type == "text/event-stream" and stream and response.status < 400:
                    self.send_response(response.status)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.close_connection = True
                    total = 0
                    while chunk := response.read1(16384):
                        total += len(chunk)
                        if total > MAX_RESPONSE_BYTES:
                            break  # connection drops; never silently truncate a complete SSE frame
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    return
                data = response.read(MAX_RESPONSE_BYTES + 1)
                if len(data) > MAX_RESPONSE_BYTES:
                    self._error(502, "Upstream response too large")
                    return
                self.send_response(response.status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
                self.close_connection = True
            except (OSError, http.client.HTTPException, TimeoutError):
                # Only emit a clean error if headers have not been sent yet.
                if not self.close_connection:
                    self._error(502, "Local upstream unavailable")
            finally:
                connection.close()

        def do_GET(self) -> None:
            if self.path == "/healthz":
                body = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/v1/models":
                self._relay("GET", "/v1/models", None)
            else:
                self._error(404, "Unsupported route")

        def do_POST(self) -> None:
            if self.path != "/v1/chat/completions":
                self._error(404, "Unsupported route")
                return
            if self.headers.get("Transfer-Encoding"):
                self._error(411, "Chunked uploads are not supported")
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._error(411, "Content-Length required")
                return
            if length <= 0 or length > MAX_REQUEST_BYTES:
                self._error(413, "Request body missing or too large")
                return
            if self.headers.get("Content-Type", "").split(";", 1)[0].lower() != "application/json":
                self._error(415, "application/json required")
                return
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise RejectedInput("JSON request must be an object")
                sanitized = sanitize_request(payload, Sanitizer(private_terms=private_terms))
                encoded = json.dumps(sanitized, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
            except (ValueError, UnicodeDecodeError, RejectedInput):
                self._error(422, "Request rejected by privacy policy or invalid JSON")
                return
            self._relay("POST", "/v1/chat/completions", encoded, stream=(sanitized.get("stream") is True))

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local-only privacy proxy for OpenAI-compatible LLM clients")
    parser.add_argument("--listen", default=os.getenv("VEILGATE_LISTEN", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("VEILGATE_PORT", "8080")))
    parser.add_argument("--upstream", default=os.getenv("VEILGATE_UPSTREAM", "http://127.0.0.1:3001"))
    parser.add_argument("--private-terms", default=os.getenv("VEILGATE_PRIVATE_TERMS_FILE"))
    args = parser.parse_args(argv)
    if args.listen not in ("127.0.0.1", "::1", "localhost"):
        parser.error("Only a loopback listen address is permitted")
    try:
        upstream = validate_upstream(args.upstream)
        terms = read_private_terms(args.private_terms)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    try:
        httpd = ThreadingHTTPServer((args.listen, args.port), handler_factory(upstream, terms))
    except OSError as exc:
        parser.error(f"Cannot bind listener: {exc}")
    print(f"VeilGate listening on {args.listen}:{httpd.server_port}; upstream {args.upstream}; no request logging", flush=True)
    try:
        httpd.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
