from __future__ import annotations

import httpx

from knives_out.models import AttackCase, AttackResult, AttackResults, AttackSuite
from knives_out.reporting import render_markdown_report
from knives_out.runner import execute_attack_suite


class _StubClient:
    def __init__(self, response: httpx.Response) -> None:
        self._response = response

    def __enter__(self) -> _StubClient:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def request(self, *_: object, **__: object) -> httpx.Response:
        return self._response


class _RecordingClient:
    def __init__(self, response: httpx.Response) -> None:
        self._response = response
        self.requests: list[dict[str, object]] = []

    def __enter__(self) -> _RecordingClient:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        self.requests.append(
            {
                "method": method,
                "url": url,
                "params": kwargs.get("params"),
                "headers": kwargs.get("headers"),
            }
        )
        return self._response


def _install_stub_response(monkeypatch, response: httpx.Response) -> None:
    monkeypatch.setattr(
        "knives_out.runner.httpx.Client",
        lambda **_: _StubClient(response),
    )


def _install_recording_client(monkeypatch, response: httpx.Response) -> _RecordingClient:
    client = _RecordingClient(response)
    monkeypatch.setattr(
        "knives_out.runner.httpx.Client",
        lambda **_: client,
    )
    return client


def _attack_case(*, response_schemas: dict[str, dict[str, object]]) -> AttackCase:
    return AttackCase(
        id="atk_test",
        name="Test attack",
        kind="wrong_type_param",
        operation_id="createPet",
        method="POST",
        path="/pets",
        description="Test attack",
        response_schemas=response_schemas,
    )


def test_execute_attack_suite_flags_response_schema_mismatch(monkeypatch) -> None:
    response = httpx.Response(
        201,
        headers={"Content-Type": "application/json"},
        json={"id": "not-an-integer"},
    )
    _install_stub_response(monkeypatch, response)

    suite = AttackSuite(
        source="unit",
        attacks=[
            _attack_case(
                response_schemas={
                    "201": {
                        "content_type": "application/json",
                        "schema_def": {
                            "type": "object",
                            "required": ["id"],
                            "properties": {
                                "id": {"type": "integer"},
                            },
                        },
                    }
                }
            )
        ],
    )

    results = execute_attack_suite(suite, base_url="https://example.com")

    assert len(results.results) == 1
    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "response_schema_mismatch"
    assert result.response_schema_status == "201"
    assert result.response_schema_valid is False
    assert result.response_schema_error == "$.id: expected integer, got string"


def test_execute_attack_suite_uses_default_response_schema(monkeypatch) -> None:
    response = httpx.Response(
        422,
        headers={"Content-Type": "application/json"},
        json={"error": "invalid input"},
    )
    _install_stub_response(monkeypatch, response)

    suite = AttackSuite(
        source="unit",
        attacks=[
            _attack_case(
                response_schemas={
                    "default": {
                        "content_type": "application/json",
                        "schema_def": {
                            "type": "object",
                            "required": ["error"],
                            "properties": {
                                "error": {"type": "string"},
                            },
                        },
                    }
                }
            )
        ],
    )

    results = execute_attack_suite(suite, base_url="https://example.com")

    result = results.results[0]
    assert result.flagged is False
    assert result.issue is None
    assert result.response_schema_status == "default"
    assert result.response_schema_valid is True
    assert result.response_schema_error is None


def test_execute_attack_suite_skips_unmapped_status_codes(monkeypatch) -> None:
    response = httpx.Response(
        422,
        headers={"Content-Type": "application/json"},
        json={"error": "invalid input"},
    )
    _install_stub_response(monkeypatch, response)

    suite = AttackSuite(
        source="unit",
        attacks=[
            _attack_case(
                response_schemas={
                    "201": {
                        "content_type": "application/json",
                        "schema_def": {
                            "type": "object",
                            "required": ["id"],
                            "properties": {
                                "id": {"type": "integer"},
                            },
                        },
                    }
                }
            )
        ],
    )

    results = execute_attack_suite(suite, base_url="https://example.com")

    result = results.results[0]
    assert result.flagged is False
    assert result.issue is None
    assert result.response_schema_status is None
    assert result.response_schema_valid is None
    assert result.response_schema_error is None


def test_render_markdown_report_highlights_response_schema_mismatches() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_test",
                operation_id="createPet",
                kind="wrong_type_param",
                name="Test attack",
                method="POST",
                url="https://example.com/pets",
                status_code=201,
                flagged=True,
                issue="response_schema_mismatch",
                response_schema_status="201",
                response_schema_valid=False,
                response_schema_error="$.id: expected integer, got string",
            )
        ],
    )

    report = render_markdown_report(results)

    assert "Response schema mismatches" in report
    assert "| Attack | Kind | Status | Issue | Schema | URL |" in report
    assert "response_schema_mismatch" in report
    assert "mismatch" in report
    assert "$.id: expected integer, got string" in report


def test_execute_attack_suite_removes_only_declared_auth_header(monkeypatch) -> None:
    response = httpx.Response(401, text="missing api key")
    client = _install_recording_client(monkeypatch, response)

    suite = AttackSuite(
        source="unit",
        attacks=[
            AttackCase(
                id="atk_header_auth",
                name="Missing header auth",
                kind="missing_auth",
                operation_id="headerAuth",
                method="GET",
                path="/pets",
                description="Missing header auth",
                headers={"X-Tenant": "tenant-123"},
                omit_header_names=["X-API-Key"],
            )
        ],
    )

    execute_attack_suite(
        suite,
        base_url="https://example.com",
        default_headers={
            "X-API-Key": "secret-key",
            "X-Trace-Id": "trace-123",
            "X-Tenant": "default-tenant",
        },
    )

    request = client.requests[0]
    assert request["headers"] == {
        "X-Trace-Id": "trace-123",
        "X-Tenant": "tenant-123",
    }


def test_execute_attack_suite_removes_only_declared_auth_query_param(monkeypatch) -> None:
    response = httpx.Response(401, text="missing api key")
    client = _install_recording_client(monkeypatch, response)

    suite = AttackSuite(
        source="unit",
        attacks=[
            AttackCase(
                id="atk_query_auth",
                name="Missing query auth",
                kind="missing_auth",
                operation_id="queryAuth",
                method="GET",
                path="/pets",
                description="Missing query auth",
                query={"limit": 10},
                omit_query_names=["api_key"],
            )
        ],
    )

    execute_attack_suite(
        suite,
        base_url="https://example.com",
        default_query={
            "api_key": "secret-key",
            "page": "2",
        },
    )

    request = client.requests[0]
    assert request["params"] == {
        "limit": 10,
        "page": "2",
    }
