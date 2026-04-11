from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha1
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin

import httpx

from knives_out.models import CapturedRequest, CapturedResponse, CaptureEvent

_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
_SENSITIVE_TOKENS = (
    "auth",
    "token",
    "secret",
    "password",
    "passwd",
    "cookie",
    "session",
    "api-key",
    "api_key",
    "client_secret",
)
_JSON_CONTENT_TYPES = ("application/json", "application/problem+json")


def _normalized_header_mapping(headers: Mapping[str, str]) -> dict[str, str]:
    return {name: value for name, value in headers.items()}


def _looks_sensitive(name: str) -> bool:
    normalized = name.strip().lower().replace("_", "-")
    return any(token in normalized for token in _SENSITIVE_TOKENS)


def _placeholder_for(name: str) -> str:
    normalized = name.strip().lower().replace("_", "-")
    return f"<redacted:{normalized}>"


def _identity_context(secret_values: list[tuple[str, str]]) -> str | None:
    if not secret_values:
        return None
    normalized = "|".join(f"{key}={value}" for key, value in sorted(secret_values))
    return f"authctx_{sha1(normalized.encode('utf-8')).hexdigest()[:12]}"


def redact_headers(headers: Mapping[str, str]) -> tuple[dict[str, str], str | None]:
    sanitized: dict[str, str] = {}
    secret_values: list[tuple[str, str]] = []
    for name, value in headers.items():
        if _looks_sensitive(name):
            sanitized[name] = _placeholder_for(name)
            secret_values.append((name.lower(), value))
        else:
            sanitized[name] = value
    return sanitized, _identity_context(secret_values)


def redact_query(query: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    sanitized: dict[str, Any] = {}
    secret_values: list[tuple[str, str]] = []
    for name, value in query.items():
        if _looks_sensitive(name):
            sanitized[name] = _placeholder_for(name)
            secret_values.append((name.lower(), str(value)))
        else:
            sanitized[name] = value
    return sanitized, _identity_context(secret_values)


def redact_body(value: Any, *, key_name: str | None = None) -> Any:
    if key_name and _looks_sensitive(key_name):
        return _placeholder_for(key_name)
    if isinstance(value, dict):
        return {name: redact_body(item, key_name=name) for name, item in value.items()}
    if isinstance(value, list):
        return [redact_body(item, key_name=key_name) for item in value]
    return value


def parse_body(body: bytes, content_type: str | None) -> tuple[Any | None, str | None]:
    if not body:
        return None, None

    decoded = body.decode("utf-8", errors="replace")
    normalized_content_type = (content_type or "").split(";", 1)[0].strip().lower()
    if normalized_content_type in _JSON_CONTENT_TYPES:
        try:
            return json.loads(decoded), None
        except ValueError:
            return None, decoded
    return None, decoded


def read_capture_events(path: str | Path) -> list[CaptureEvent]:
    capture_path = Path(path)
    events: list[CaptureEvent] = []
    for line in capture_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        events.append(CaptureEvent.model_validate_json(stripped))
    return events


@dataclass
class CaptureRecorder:
    path: Path

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    def record(self, event: CaptureEvent) -> int:
        payload = event.model_dump_json(exclude_none=True)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(payload + "\n")
            self._count += 1
            return self._count


def _merge_identity_contexts(*values: str | None) -> str | None:
    unique = sorted({value for value in values if value})
    if not unique:
        return None
    return (
        unique[0]
        if len(unique) == 1
        else f"authctx_{sha1('|'.join(unique).encode()).hexdigest()[:12]}"
    )


def _forwardable_request_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in _HOP_BY_HOP_HEADERS and name.lower() != "host"
    }


def _forwardable_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        name: value for name, value in headers.items() if name.lower() not in _HOP_BY_HOP_HEADERS
    }


def serve_capture_proxy(
    *,
    listen_host: str,
    listen_port: int,
    target_base_url: str,
    output_path: str | Path,
    timeout_seconds: float = 30.0,
    max_events: int | None = None,
) -> None:
    recorder = CaptureRecorder(Path(output_path))
    client = httpx.Client(timeout=timeout_seconds, follow_redirects=False)

    class ProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

        def _handle_request(self) -> None:
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(content_length) if content_length else b""
            target_url = urljoin(target_base_url.rstrip("/") + "/", self.path.lstrip("/"))
            request_headers = _normalized_header_mapping(self.headers)
            request_query = {
                key: value
                for key, value in parse_qsl(
                    httpx.URL(target_url).query.decode("utf-8"),
                    keep_blank_values=True,
                )
            }
            request_content_type = self.headers.get("Content-Type")
            sanitized_headers, header_identity = redact_headers(request_headers)
            sanitized_query, query_identity = redact_query(request_query)
            request_body_json, request_raw_body = parse_body(body, request_content_type)
            if request_body_json is not None:
                request_body_json = redact_body(request_body_json)

            forwarded_headers = _forwardable_request_headers(request_headers)
            try:
                response = client.request(
                    self.command,
                    target_url,
                    headers=forwarded_headers,
                    content=body if body else None,
                )
                response_headers = _forwardable_response_headers(response.headers)
                response_content_type = response.headers.get("Content-Type")
                response_body_json, response_raw_body = parse_body(
                    response.content,
                    response_content_type,
                )
                if response_body_json is not None:
                    response_body_json = redact_body(response_body_json)
                sanitized_response_headers, response_identity = redact_headers(response_headers)

                self.send_response(response.status_code)
                for name, value in response_headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(response.content)

                captured_response = CapturedResponse(
                    status_code=response.status_code,
                    headers=sanitized_response_headers,
                    body_json=response_body_json,
                    raw_body=response_raw_body,
                    content_type=response_content_type,
                    duration_ms=response.elapsed.total_seconds() * 1000.0,
                )
            except httpx.HTTPError as exc:
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                payload = json.dumps({"error": str(exc)}).encode("utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                captured_response = CapturedResponse(
                    error=str(exc),
                    status_code=502,
                    headers={"Content-Type": "application/json"},
                    raw_body=payload.decode("utf-8"),
                    content_type="application/json",
                )
                response_identity = None

            event = CaptureEvent(
                source="proxy",
                identity_context=_merge_identity_contexts(
                    header_identity,
                    query_identity,
                    response_identity,
                ),
                request=CapturedRequest(
                    method=self.command,
                    url=target_url,
                    headers=sanitized_headers,
                    query=sanitized_query,
                    body_json=request_body_json,
                    raw_body=request_raw_body,
                    content_type=request_content_type,
                ),
                response=captured_response,
            )
            count = recorder.record(event)
            if max_events is not None and count >= max_events:
                threading.Thread(target=self.server.shutdown, daemon=True).start()

        def do_GET(self) -> None:  # noqa: N802
            self._handle_request()

        def do_POST(self) -> None:  # noqa: N802
            self._handle_request()

        def do_PUT(self) -> None:  # noqa: N802
            self._handle_request()

        def do_PATCH(self) -> None:  # noqa: N802
            self._handle_request()

        def do_DELETE(self) -> None:  # noqa: N802
            self._handle_request()

        def do_OPTIONS(self) -> None:  # noqa: N802
            self._handle_request()

        def do_HEAD(self) -> None:  # noqa: N802
            self._handle_request()

    server = ThreadingHTTPServer((listen_host, listen_port), ProxyHandler)
    try:
        server.serve_forever()
    finally:
        client.close()
        server.server_close()
