from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from knives_out.models import AttackResult, AttackResults, AttackSuite


def load_attack_suite(path: str | Path) -> AttackSuite:
    raw = Path(path).read_text(encoding="utf-8")
    return AttackSuite.model_validate_json(raw)


def _render_path(path_template: str, path_params: dict[str, Any]) -> str:
    rendered = path_template
    for name, value in path_params.items():
        rendered = rendered.replace(f"{{{name}}}", quote(str(value), safe=""))
    return rendered


def _remove_header_names(headers: dict[str, str], names: list[str]) -> dict[str, str]:
    if not names:
        return headers
    lowered = {name.lower() for name in names}
    return {key: value for key, value in headers.items() if key.lower() not in lowered}


def evaluate_result(status_code: int | None, error: str | None) -> tuple[bool, str | None]:
    if error:
        return True, "transport_error"
    if status_code is None:
        return True, "no_status"
    if 500 <= status_code < 600:
        return True, "server_error"
    if 200 <= status_code < 400:
        return True, "unexpected_success"
    return False, None


def _excerpt(text: str, limit: int = 300) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def execute_attack_suite(
    suite: AttackSuite,
    *,
    base_url: str,
    default_headers: dict[str, str] | None = None,
    default_query: dict[str, Any] | None = None,
    timeout_seconds: float = 10.0,
) -> AttackResults:
    default_headers = dict(default_headers or {})
    default_query = dict(default_query or {})
    results: list[AttackResult] = []

    normalized_base_url = base_url.rstrip("/")

    with httpx.Client(timeout=timeout_seconds, follow_redirects=False) as client:
        for attack in suite.attacks:
            url = normalized_base_url + _render_path(attack.path, attack.path_params)
            headers = {**default_headers, **attack.headers}
            headers = _remove_header_names(headers, attack.omit_header_names)
            query = {**default_query, **attack.query}
            for name in attack.omit_query_names:
                query.pop(name, None)

            request_kwargs: dict[str, Any] = {
                "params": query,
                "headers": headers,
            }

            if not attack.omit_body:
                if attack.raw_body is not None:
                    request_kwargs["content"] = attack.raw_body
                    if attack.content_type and "Content-Type" not in headers:
                        request_kwargs["headers"] = {**headers, "Content-Type": attack.content_type}
                elif attack.body_json is not None:
                    request_kwargs["json"] = attack.body_json

            start = time.perf_counter()
            response: httpx.Response | None = None
            error: str | None = None
            try:
                response = client.request(attack.method, url, **request_kwargs)
            except Exception as exc:  # noqa: BLE001
                error = str(exc)
            duration_ms = (time.perf_counter() - start) * 1000.0

            flagged, issue = evaluate_result(response.status_code if response else None, error)
            results.append(
                AttackResult(
                    attack_id=attack.id,
                    operation_id=attack.operation_id,
                    kind=attack.kind,
                    name=attack.name,
                    method=attack.method,
                    url=url,
                    status_code=response.status_code if response else None,
                    error=error,
                    duration_ms=round(duration_ms, 2),
                    flagged=flagged,
                    issue=issue,
                    response_excerpt=_excerpt(response.text) if response is not None else None,
                )
            )

    return AttackResults(source=suite.source, base_url=base_url, results=results)
