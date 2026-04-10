from __future__ import annotations

import json

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
    assert result.severity == "medium"
    assert result.confidence == "high"
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
    assert result.severity == "none"
    assert result.confidence == "none"
    assert result.response_schema_status is None
    assert result.response_schema_valid is None
    assert result.response_schema_error is None


def test_execute_attack_suite_scores_server_errors(monkeypatch) -> None:
    response = httpx.Response(503, text="upstream unavailable")
    _install_stub_response(monkeypatch, response)

    suite = AttackSuite(source="unit", attacks=[_attack_case(response_schemas={})])

    results = execute_attack_suite(suite, base_url="https://example.com")

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "server_error"
    assert result.severity == "high"
    assert result.confidence == "high"


def test_render_markdown_report_sorts_flagged_findings_by_score() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_transport",
                operation_id="listPets",
                kind="missing_auth",
                name="Transport error",
                method="GET",
                url="https://example.com/pets",
                flagged=True,
                issue="transport_error",
                severity="low",
                confidence="low",
                error="timed out",
            ),
            AttackResult(
                attack_id="atk_unexpected",
                operation_id="listPets",
                kind="missing_auth",
                name="Unexpected success",
                method="GET",
                url="https://example.com/pets",
                status_code=200,
                flagged=True,
                issue="unexpected_success",
                severity="high",
                confidence="medium",
            ),
            AttackResult(
                attack_id="atk_test",
                operation_id="createPet",
                kind="wrong_type_param",
                name="Schema mismatch",
                method="POST",
                url="https://example.com/pets",
                status_code=201,
                flagged=True,
                issue="response_schema_mismatch",
                severity="medium",
                confidence="high",
                response_schema_status="201",
                response_schema_valid=False,
                response_schema_error="$.id: expected integer, got string",
            ),
            AttackResult(
                attack_id="atk_server",
                operation_id="createPet",
                kind="missing_request_body",
                name="Server failure",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            ),
        ],
    )

    report = render_markdown_report(results)

    assert "Response schema mismatches" in report
    assert "| Attack | Kind | Status | Issue | Severity | Confidence | Schema | URL |" in report
    assert "response_schema_mismatch" in report
    assert "mismatch" in report
    assert "$.id: expected integer, got string" in report
    assert report.index("| Server failure |") < report.index("| Unexpected success |")
    assert report.index("| Unexpected success |") < report.index("| Schema mismatch |")
    assert report.index("| Schema mismatch |") < report.index("| Transport error |")


def test_render_markdown_report_with_baseline_shows_regression_sections() -> None:
    current = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_new",
                operation_id="createPet",
                kind="missing_request_body",
                name="New server failure",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            ),
            AttackResult(
                attack_id="atk_shared",
                operation_id="createPet",
                kind="wrong_type_param",
                name="Persisting mismatch",
                method="POST",
                url="https://example.com/pets",
                status_code=200,
                flagged=True,
                issue="response_schema_mismatch",
                severity="medium",
                confidence="high",
            ),
        ],
    )
    baseline = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_shared",
                operation_id="createPet",
                kind="wrong_type_param",
                name="Persisting mismatch",
                method="POST",
                url="https://example.com/pets",
                status_code=200,
                flagged=True,
                issue="response_schema_mismatch",
                severity="medium",
                confidence="high",
            ),
            AttackResult(
                attack_id="atk_resolved",
                operation_id="listPets",
                kind="missing_auth",
                name="Resolved auth failure",
                method="GET",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            ),
        ],
    )

    report = render_markdown_report(current, baseline=baseline)

    assert "## Verification summary" in report
    assert "## New findings" in report
    assert "## Resolved findings" in report
    assert "## Persisting findings" in report
    assert "New server failure" in report
    assert "Resolved auth failure" in report
    assert "Persisting mismatch" in report


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


def test_execute_attack_suite_writes_artifacts(tmp_path, monkeypatch) -> None:
    response = httpx.Response(422, text="invalid input from server")
    _install_recording_client(monkeypatch, response)
    artifact_dir = tmp_path / "artifacts"

    suite = AttackSuite(
        source="unit",
        attacks=[
            AttackCase(
                id="atk_artifact",
                name="Artifact attack",
                kind="wrong_type_param",
                operation_id="createPet",
                method="POST",
                path="/pets",
                description="Artifact attack",
                headers={"X-Tenant": "tenant-123"},
                query={"limit": 10},
                body_json={"name": "Milo"},
            )
        ],
    )

    execute_attack_suite(
        suite,
        base_url="https://example.com",
        default_headers={"Authorization": "Bearer dev-token"},
        default_query={"page": "2"},
        artifact_dir=artifact_dir,
    )

    artifact_path = artifact_dir / "atk_artifact.json"
    assert artifact_path.exists()

    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert artifact["attack"]["id"] == "atk_artifact"
    assert artifact["request"]["method"] == "POST"
    assert artifact["request"]["url"] == "https://example.com/pets"
    assert artifact["request"]["headers"] == {
        "Authorization": "Bearer dev-token",
        "X-Tenant": "tenant-123",
    }
    assert artifact["request"]["query"] == {
        "limit": 10,
        "page": "2",
    }
    assert artifact["request"]["body"] == {
        "present": True,
        "kind": "json",
        "content_type": "application/json",
        "excerpt": '{"name": "Milo"}',
    }
    assert artifact["response"]["status_code"] == 422
    assert artifact["response"]["body_excerpt"] == "invalid input from server"
