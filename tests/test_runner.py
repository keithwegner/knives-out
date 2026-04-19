from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date
from pathlib import Path

import httpx
import pytest
from websockets.sync.server import serve

from knives_out.auth_config import BuiltInAuthConfig
from knives_out.auth_plugins import PreparedRequest, RuntimePlugin
from knives_out.models import (
    AttackCase,
    AttackResult,
    AttackResults,
    AttackSuite,
    AuthProfile,
    ExtractRule,
    GraphQLOutputShape,
    ProfileAttackResult,
    WorkflowAttackCase,
    WorkflowStep,
    WorkflowStepResult,
)
from knives_out.reporting import (
    render_html_report,
    render_markdown_report,
    render_markdown_summary,
    summarize_results,
)
from knives_out.runner import (
    _graphql_subscription_payload,
    _graphql_subscription_url,
    _recv_graphql_subscription_frame,
    execute_attack_suite,
    execute_attack_suite_profiles,
)
from knives_out.suppressions import SuppressionRule


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


class _NoopClient:
    def __enter__(self) -> _NoopClient:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def request(self, *_: object, **__: object) -> httpx.Response:
        raise AssertionError("This client should not have been used.")


class _HandlerClient:
    def __init__(self, handler) -> None:
        self._handler = handler
        self.requests: list[dict[str, object]] = []
        self.cookies: dict[str, str] = {}

    def __enter__(self) -> _HandlerClient:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        headers = dict(kwargs.get("headers") or {})
        if self.cookies and "Cookie" not in headers:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in self.cookies.items())

        request = {
            "method": method,
            "url": url,
            "params": kwargs.get("params"),
            "headers": headers,
            "json": kwargs.get("json"),
            "content": kwargs.get("content"),
        }
        self.requests.append(request)
        response = self._handler(request)

        set_cookie = response.headers.get("set-cookie")
        if set_cookie:
            cookie_name, cookie_value = set_cookie.split(";", 1)[0].split("=", 1)
            self.cookies[cookie_name] = cookie_value
        return response


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


def _install_client_sequence(monkeypatch, clients: list[object]) -> None:
    remaining = list(clients)

    def _client_factory(**_: object):
        if not remaining:
            raise AssertionError("No more fake clients were configured.")
        return remaining.pop(0)

    monkeypatch.setattr("knives_out.runner.httpx.Client", _client_factory)


def _attack_case(
    *,
    response_schemas: dict[str, dict[str, object]],
    auth_required: bool = False,
) -> AttackCase:
    return AttackCase(
        id="atk_test",
        name="Test attack",
        kind="wrong_type_param",
        operation_id="createPet",
        method="POST",
        path="/pets",
        auth_required=auth_required,
        description="Test attack",
        response_schemas=response_schemas,
    )


def _workflow_attack(
    *,
    extracts: list[ExtractRule] | None = None,
    terminal_path_param: object = "{{id}}",
    setup_path: str = "/pets",
    terminal_path: str = "/pets/{petId}",
) -> WorkflowAttackCase:
    setup_extracts = (
        [ExtractRule(name="id", json_pointer="/0/id")] if extracts is None else extracts
    )
    return WorkflowAttackCase(
        id="wf_lookup",
        name="Workflow lookup",
        kind="wrong_type_param",
        operation_id="getPet",
        method="GET",
        path=terminal_path,
        description="Workflow lookup",
        setup_steps=[
            WorkflowStep(
                name="List pets",
                operation_id="listPets",
                method="GET",
                path=setup_path,
                extracts=setup_extracts,
            )
        ],
        terminal_attack=AttackCase(
            id="atk_terminal",
            name="Terminal attack",
            kind="wrong_type_param",
            operation_id="getPet",
            method="GET",
            path=terminal_path,
            description="Terminal attack",
            path_params={"petId": terminal_path_param},
        ),
    )


def _graphql_shape_book(*, nullable: bool = True) -> GraphQLOutputShape:
    return GraphQLOutputShape(
        kind="object",
        type_name="Book",
        nullable=nullable,
        fields={
            "__typename": GraphQLOutputShape(
                kind="scalar",
                type_name="String",
                nullable=False,
            ),
            "id": GraphQLOutputShape(
                kind="scalar",
                type_name="ID",
                nullable=False,
            ),
            "title": GraphQLOutputShape(
                kind="scalar",
                type_name="String",
                nullable=False,
            ),
            "rating": GraphQLOutputShape(
                kind="scalar",
                type_name="Int",
                nullable=True,
            ),
        },
    )


def _graphql_shape_author(*, nullable: bool = True) -> GraphQLOutputShape:
    return GraphQLOutputShape(
        kind="object",
        type_name="Author",
        nullable=nullable,
        fields={
            "__typename": GraphQLOutputShape(
                kind="scalar",
                type_name="String",
                nullable=False,
            ),
            "id": GraphQLOutputShape(
                kind="scalar",
                type_name="ID",
                nullable=False,
            ),
            "name": GraphQLOutputShape(
                kind="scalar",
                type_name="String",
                nullable=False,
            ),
        },
    )


def _graphql_shape_book_with_author(*, nullable: bool = True) -> GraphQLOutputShape:
    return GraphQLOutputShape(
        kind="object",
        type_name="Book",
        nullable=nullable,
        fields={
            "__typename": GraphQLOutputShape(
                kind="scalar",
                type_name="String",
                nullable=False,
            ),
            "id": GraphQLOutputShape(
                kind="scalar",
                type_name="ID",
                nullable=False,
            ),
            "title": GraphQLOutputShape(
                kind="scalar",
                type_name="String",
                nullable=False,
            ),
            "author": _graphql_shape_author(),
        },
    )


def _graphql_shape_magazine(*, nullable: bool = True) -> GraphQLOutputShape:
    return GraphQLOutputShape(
        kind="object",
        type_name="Magazine",
        nullable=nullable,
        fields={
            "__typename": GraphQLOutputShape(
                kind="scalar",
                type_name="String",
                nullable=False,
            ),
            "id": GraphQLOutputShape(
                kind="scalar",
                type_name="ID",
                nullable=False,
            ),
            "title": GraphQLOutputShape(
                kind="scalar",
                type_name="String",
                nullable=False,
            ),
            "issue": GraphQLOutputShape(
                kind="scalar",
                type_name="Int",
                nullable=False,
            ),
        },
    )


def _graphql_attack_case(
    *,
    output_shape: GraphQLOutputShape | None = None,
    federated: bool = False,
    entity_types: list[str] | None = None,
) -> AttackCase:
    return AttackCase(
        id="atk_graphql",
        name="Wrong-type GraphQL variable",
        kind="wrong_type_variable",
        operation_id="book",
        protocol="graphql",
        method="POST",
        path="/graphql",
        description="Wrong type for GraphQL variable.",
        body_json={
            "query": ("query Book($id: ID!) { book(id: $id) { __typename id title rating } }"),
            "variables": {"id": 123},
        },
        expected_outcomes=["graphql_error", "4xx"],
        graphql_root_field_name="book",
        graphql_output_shape=output_shape or _graphql_shape_book(),
        graphql_federated=federated,
        graphql_entity_types=list(entity_types or []),
    )


def _graphql_subscription_attack_case(
    *,
    body_json: dict[str, object] | None = None,
    expected_outcomes: list[str] | None = None,
    output_shape: GraphQLOutputShape | None = None,
) -> AttackCase:
    return AttackCase(
        id="atk_graphql_subscription",
        name="GraphQL subscription",
        kind="subscription_probe",
        operation_id="bookEvents",
        protocol="graphql",
        method="SUBSCRIBE",
        path="/graphql",
        description="GraphQL subscription probe.",
        body_json=body_json
        or {
            "query": (
                "subscription BookEvents($id: ID!) { "
                "bookEvents(id: $id) { __typename id title rating } "
                "}"
            ),
            "variables": {"id": "1"},
        },
        expected_outcomes=list(expected_outcomes or ["2xx"]),
        graphql_operation_type="subscription",
        graphql_root_field_name="bookEvents",
        graphql_output_shape=output_shape or _graphql_shape_book(),
    )


def _prepared_subscription_request(**overrides: object) -> PreparedRequest:
    request = PreparedRequest(
        phase="request",
        attack_id="atk_graphql_subscription",
        name="GraphQL subscription",
        kind="subscription_probe",
        operation_id="bookEvents",
        method="SUBSCRIBE",
        path="/graphql",
        description="GraphQL subscription probe.",
    )
    for field_name, value in overrides.items():
        setattr(request, field_name, value)
    return request


@contextmanager
def _graphql_subscription_server(handler) -> Iterator[str]:
    with serve(
        handler,
        "127.0.0.1",
        0,
        subprotocols=["graphql-transport-ws"],
        compression=None,
    ) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.socket.getsockname()[:2]
        try:
            yield f"http://{host}:{port}"
        finally:
            server.shutdown()
            thread.join(timeout=1)


class _StubSubscriptionWebSocket:
    def __init__(self, frame_or_error: object) -> None:
        self._frame_or_error = frame_or_error

    def recv(self, timeout: float) -> object:
        assert timeout > 0
        if isinstance(self._frame_or_error, BaseException):
            raise self._frame_or_error
        return self._frame_or_error


def test_graphql_subscription_url_rewrites_scheme_and_query() -> None:
    assert _graphql_subscription_url(
        "https://example.com/graphql",
        {"tag": ["books", "events"], "cursor": "abc123"},
    ) == ("wss://example.com/graphql?tag=books&tag=events&cursor=abc123")


@pytest.mark.parametrize(
    ("prepared_request", "request_kwargs", "expected"),
    [
        pytest.param(
            _prepared_subscription_request(omit_body=True),
            None,
            (False, None),
            id="omit-body",
        ),
        pytest.param(
            _prepared_subscription_request(body_json={"query": "ignored"}),
            {"json": {"query": "subscription { bookEvents { id } }"}},
            (True, {"query": "subscription { bookEvents { id } }"}),
            id="request-kwargs-json",
        ),
        pytest.param(
            _prepared_subscription_request(body_json={"query": "ignored"}),
            {"content": '{"query":"subscription { bookEvents { id } }"}'},
            (True, '{"query":"subscription { bookEvents { id } }"}'),
            id="request-kwargs-content",
        ),
        pytest.param(
            _prepared_subscription_request(
                body_json={"query": "subscription { bookEvents { id } }"}
            ),
            None,
            (True, {"query": "subscription { bookEvents { id } }"}),
            id="body-json",
        ),
        pytest.param(
            _prepared_subscription_request(
                raw_body='{"query":"subscription { bookEvents { id } }"}'
            ),
            None,
            (True, '{"query":"subscription { bookEvents { id } }"}'),
            id="raw-body",
        ),
        pytest.param(
            _prepared_subscription_request(),
            None,
            (False, None),
            id="no-payload",
        ),
    ],
)
def test_graphql_subscription_payload_selects_expected_body(
    prepared_request: PreparedRequest,
    request_kwargs: dict[str, object] | None,
    expected: tuple[bool, object | None],
) -> None:
    assert _graphql_subscription_payload(prepared_request, request_kwargs) == expected


def test_recv_graphql_subscription_frame_accepts_valid_json_object() -> None:
    frame = _recv_graphql_subscription_frame(
        _StubSubscriptionWebSocket('{"type":"next","payload":{"data":{"bookEvents":{"id":"1"}}}}'),
        timeout_seconds=0.5,
    )

    assert frame["type"] == "next"
    assert frame["payload"]["data"]["bookEvents"]["id"] == "1"


@pytest.mark.parametrize(
    ("frame_or_error", "message"),
    [
        pytest.param(
            TimeoutError(), "timed out waiting for a subscription protocol frame", id="timeout"
        ),
        pytest.param(b"\x00\x01", "received a non-text subscription frame", id="non-text"),
        pytest.param("{", "received invalid JSON frame", id="invalid-json"),
        pytest.param("[]", "received a non-object JSON subscription frame", id="non-object"),
        pytest.param(
            '{"payload":{}}',
            "received a subscription frame without a string 'type'",
            id="missing-type",
        ),
    ],
)
def test_recv_graphql_subscription_frame_rejects_invalid_frames(
    frame_or_error: object,
    message: str,
) -> None:
    with pytest.raises(RuntimeError, match=message):
        _recv_graphql_subscription_frame(
            _StubSubscriptionWebSocket(frame_or_error),
            timeout_seconds=0.5,
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
    assert result.path == "/pets"
    assert result.tags == []
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
    assert "### By issue" in report
    assert "| server_error | 1 |" in report
    assert "| response_schema_mismatch | 1 |" in report
    assert "### By attack kind" in report
    assert "| missing_auth | 2 |" in report
    assert "| wrong_type_param | 1 |" in report
    assert (
        "| Protocol | Attack | Kind | Status | Issue | Severity | Confidence | Schema | URL |"
        in report
    )
    assert "response_schema_mismatch" in report
    assert "mismatch" in report
    assert "$.id: expected integer, got string" in report
    assert report.index("| Server failure |") < report.index("| Unexpected success |")
    assert report.index("| Unexpected success |") < report.index("| Schema mismatch |")
    assert report.index("| Schema mismatch |") < report.index("| Transport error |")


def test_render_markdown_report_shows_graphql_protocol_details() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_graphql",
                operation_id="book",
                kind="wrong_type_variable",
                name="GraphQL mismatch",
                protocol="graphql",
                method="POST",
                url="https://example.com/graphql",
                status_code=200,
                flagged=True,
                issue="graphql_response_shape_mismatch",
                severity="medium",
                confidence="high",
                graphql_response_valid=False,
                graphql_response_error="$.data.book.title: expected String, got integer",
                graphql_response_hint="Schema appears federated.",
            )
        ],
    )

    report = render_markdown_report(results)

    assert "GraphQL response-shape mismatches" in report
    assert "`graphql`=1" in report
    assert "graphql_response_shape_mismatch" in report
    assert "graphql-mismatch" in report
    assert "GraphQL federation hint" in report


def test_render_markdown_report_shows_graphql_subscription_protocol_issue() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_graphql_subscription",
                operation_id="bookEvents",
                kind="subscription_probe",
                name="GraphQL subscription protocol error",
                protocol="graphql",
                method="SUBSCRIBE",
                url="https://example.com/graphql",
                flagged=True,
                issue="graphql_subscription_protocol_error",
                severity="low",
                confidence="high",
                error="expected 'connection_ack', got 'pong'",
            )
        ],
    )

    report = render_markdown_report(results)

    assert "graphql_subscription_protocol_error" in report
    assert "expected 'connection_ack', got 'pong'" in report


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


def test_render_markdown_report_shows_persisting_deltas() -> None:
    current = AttackResults(
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
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
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
                status_code=401,
                flagged=True,
                issue="server_error",
                severity="medium",
                confidence="low",
            )
        ],
    )

    report = render_markdown_report(current, baseline=baseline)

    assert "Persisting findings with deltas: **1**" in report
    assert "severity medium -> high" in report
    assert "confidence low -> high" in report
    assert "status 401 -> 500" in report


def test_render_markdown_report_shows_suppressed_findings() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_suppressed",
                operation_id="createPet",
                kind="missing_request_body",
                name="Suppressed failure",
                method="POST",
                path="/pets",
                tags=["pets", "write"],
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ],
    )

    report = render_markdown_report(
        results,
        suppressions=[
            SuppressionRule(
                attack_id="atk_suppressed",
                issue="server_error",
                reason="known issue",
                owner="api-team",
            )
        ],
    )

    assert "## Suppressed findings" in report
    assert "Suppressed failure" in report
    assert "known issue" in report
    assert "Active flagged results: **0**" in report
    assert "Suppressed flagged results: **1**" in report


def test_render_markdown_report_shows_auth_diagnostics() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        auth_events=[
            {
                "name": "user",
                "strategy": "client_credentials",
                "phase": "acquire",
                "success": False,
                "trigger": "suite",
                "endpoint": "/oauth/token",
                "error": "invalid client credentials",
            },
            {
                "name": "user",
                "strategy": "client_credentials",
                "phase": "refresh",
                "success": True,
                "trigger": "401",
            },
        ],
        results=[],
    )

    report = render_markdown_report(results)

    assert "## Auth summary" in report
    assert "| - | user | client_credentials | 1 | 1 | 1 | 401, suite |" in report
    assert "## Auth diagnostics" in report
    assert "client_credentials" in report
    assert "invalid client credentials" in report


def test_execute_attack_suite_applies_static_bearer_auth_config(monkeypatch) -> None:
    response = httpx.Response(422, text="invalid input")
    client = _install_recording_client(monkeypatch, response)
    suite = AttackSuite(source="unit", attacks=[_attack_case(response_schemas={})])

    results = execute_attack_suite(
        suite,
        base_url="https://example.com",
        built_in_auth_configs=[
            BuiltInAuthConfig(
                name="user",
                strategy="static_bearer",
                token="dev-token",
            )
        ],
    )

    assert client.requests[0]["headers"]["Authorization"] == "Bearer dev-token"
    assert len(results.auth_events) == 1
    assert results.auth_events[0].success is True
    assert results.auth_events[0].name == "user"


def test_execute_attack_suite_refreshes_bearer_token_on_401(monkeypatch) -> None:
    tokens = ["expired-token", "fresh-token"]

    def _handler(request: dict[str, object]) -> httpx.Response:
        if request["url"] == "https://example.com/oauth/token":
            return httpx.Response(
                200,
                json={"access_token": tokens.pop(0), "expires_in": 3600},
            )
        authorization = (request.get("headers") or {}).get("Authorization")
        if authorization == "Bearer expired-token":
            return httpx.Response(401, json={"detail": "expired"})
        if authorization == "Bearer fresh-token":
            return httpx.Response(422, json={"detail": "invalid payload"})
        return httpx.Response(500, json={"detail": "unexpected"})

    client = _HandlerClient(_handler)
    _install_client_sequence(monkeypatch, [client])

    suite = AttackSuite(source="unit", attacks=[_attack_case(response_schemas={})])
    results = execute_attack_suite(
        suite,
        base_url="https://example.com",
        built_in_auth_configs=[
            BuiltInAuthConfig(
                name="service",
                strategy="client_credentials",
                endpoint="/oauth/token",
                request_form={
                    "grant_type": "client_credentials",
                    "client_id": "client",
                    "client_secret": "secret",
                },
                token_pointer="/access_token",
                expires_in_pointer="/expires_in",
            )
        ],
    )

    assert [request["url"] for request in client.requests] == [
        "https://example.com/oauth/token",
        "https://example.com/pets",
        "https://example.com/oauth/token",
        "https://example.com/pets",
    ]
    assert client.requests[1]["headers"]["Authorization"] == "Bearer expired-token"
    assert client.requests[3]["headers"]["Authorization"] == "Bearer fresh-token"
    assert results.results[0].status_code == 422
    assert results.results[0].flagged is False
    assert [event.phase for event in results.auth_events] == ["acquire", "refresh"]


def test_execute_attack_suite_records_auth_failures_separately(monkeypatch) -> None:
    def _handler(request: dict[str, object]) -> httpx.Response:
        if request["url"] == "https://example.com/login":
            return httpx.Response(500, json={"detail": "boom"})
        return httpx.Response(401, json={"detail": "unauthorized"})

    _install_client_sequence(monkeypatch, [_HandlerClient(_handler)])
    suite = AttackSuite(source="unit", attacks=[_attack_case(response_schemas={})])

    results = execute_attack_suite(
        suite,
        base_url="https://example.com",
        built_in_auth_configs=[
            BuiltInAuthConfig(
                name="user",
                strategy="login_json_bearer",
                endpoint="/login",
                request_json={"username": "demo", "password": "pw"},
                token_pointer="/token",
            )
        ],
    )

    assert len(results.auth_events) == 1
    assert results.auth_events[0].success is False
    assert results.auth_events[0].status_code is None
    assert "status 500" in (results.auth_events[0].error or "")
    assert results.results[0].status_code == 401
    assert results.results[0].flagged is False


def test_execute_attack_suite_establishes_cookie_session_with_form_login(monkeypatch) -> None:
    def _handler(request: dict[str, object]) -> httpx.Response:
        if request["url"] == "https://example.com/login":
            return httpx.Response(200, headers={"set-cookie": "session=abc123; Path=/"})
        cookie = (request.get("headers") or {}).get("Cookie")
        if cookie == "session=abc123":
            return httpx.Response(422, json={"detail": "invalid payload"})
        return httpx.Response(401, json={"detail": "unauthorized"})

    client = _HandlerClient(_handler)
    _install_client_sequence(monkeypatch, [client])
    suite = AttackSuite(source="unit", attacks=[_attack_case(response_schemas={})])

    results = execute_attack_suite(
        suite,
        base_url="https://example.com",
        built_in_auth_configs=[
            BuiltInAuthConfig(
                name="session-user",
                strategy="login_form_cookie",
                endpoint="/login",
                request_form={"username": "demo", "password": "pw"},
            )
        ],
    )

    assert client.requests[0]["url"] == "https://example.com/login"
    assert client.requests[1]["headers"]["Cookie"] == "session=abc123"
    assert results.results[0].status_code == 422
    assert results.results[0].flagged is False


def test_execute_attack_suite_profiles_flags_anonymous_access(monkeypatch) -> None:
    def _handler(request: dict[str, object]) -> httpx.Response:
        authorization = (request.get("headers") or {}).get("Authorization")
        if authorization is None:
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(403, json={"detail": "forbidden"})

    _install_client_sequence(
        monkeypatch,
        [
            _HandlerClient(_handler),
            _HandlerClient(_handler),
            _HandlerClient(_handler),
        ],
    )

    suite = AttackSuite(
        source="unit",
        attacks=[
            AttackCase(
                id="atk_secret",
                name="Secret lookup",
                kind="missing_auth",
                operation_id="getSecret",
                method="GET",
                path="/secrets",
                auth_required=True,
                description="Secret lookup",
            )
        ],
    )

    results = execute_attack_suite_profiles(
        suite,
        base_url="https://example.com",
        profiles=[
            AuthProfile(name="anonymous", anonymous=True, level=0),
            AuthProfile(name="user", level=10, headers={"Authorization": "Bearer user"}),
            AuthProfile(name="admin", level=20, headers={"Authorization": "Bearer admin"}),
        ],
    )

    issues = [result.issue for result in results.results if result.flagged]

    assert results.profiles == ["anonymous", "user", "admin"]
    assert issues == ["unexpected_success", "anonymous_access"]
    auth_result = results.results[1]
    assert auth_result.profile_results is not None
    assert [profile.profile for profile in auth_result.profile_results] == [
        "anonymous",
        "user",
        "admin",
    ]


def test_execute_attack_suite_profiles_flags_authorization_inversion(monkeypatch) -> None:
    def _handler(request: dict[str, object]) -> httpx.Response:
        authorization = (request.get("headers") or {}).get("Authorization")
        if authorization == "Bearer user":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(403, json={"detail": "forbidden"})

    _install_client_sequence(
        monkeypatch,
        [
            _HandlerClient(_handler),
            _HandlerClient(_handler),
        ],
    )

    suite = AttackSuite(
        source="unit",
        attacks=[
            AttackCase(
                id="atk_admin",
                name="Admin-only lookup",
                kind="wrong_type_param",
                operation_id="getAdminSecret",
                method="GET",
                path="/admin/secrets",
                auth_required=True,
                description="Admin-only lookup",
            )
        ],
    )

    results = execute_attack_suite_profiles(
        suite,
        base_url="https://example.com",
        profiles=[
            AuthProfile(name="user", level=10, headers={"Authorization": "Bearer user"}),
            AuthProfile(name="admin", level=20, headers={"Authorization": "Bearer admin"}),
        ],
    )

    issues = [result.issue for result in results.results if result.flagged]

    assert issues == ["unexpected_success", "authorization_inversion"]
    inversion = results.results[1]
    assert inversion.error is not None
    assert "higher-trust profile 'admin'" in inversion.error


def test_render_markdown_report_shows_profile_outcomes() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        profiles=["anonymous", "user", "admin"],
        results=[
            AttackResult(
                attack_id="atk_secret",
                operation_id="getSecret",
                kind="missing_auth",
                name="Secret lookup",
                method="GET",
                path="/secrets",
                url="https://example.com/secrets",
                status_code=200,
                flagged=True,
                issue="anonymous_access",
                severity="high",
                confidence="high",
                profile_results=[
                    ProfileAttackResult(
                        profile="anonymous",
                        level=0,
                        anonymous=True,
                        url="https://example.com/secrets",
                        status_code=200,
                        flagged=True,
                        issue="unexpected_success",
                        severity="high",
                        confidence="medium",
                    ),
                    ProfileAttackResult(
                        profile="user",
                        level=10,
                        url="https://example.com/secrets",
                        status_code=403,
                    ),
                    ProfileAttackResult(
                        profile="admin",
                        level=20,
                        url="https://example.com/secrets",
                        status_code=403,
                    ),
                ],
            )
        ],
    )

    report = render_markdown_report(results)

    assert "- Profiles: **3**" in report
    assert "anonymous (anonymous)" in report
    assert "| user | rest | 10 | 403 | ok | - | `https://example.com/secrets` |" in report


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


def test_execute_attack_suite_applies_auth_plugin_before_omitting_auth_headers(monkeypatch) -> None:
    class _BearerPlugin(RuntimePlugin):
        def before_request(self, request, context) -> None:
            del context
            request.headers["Authorization"] = "Bearer plugin-token"
            request.headers["X-Trace-Id"] = "trace-123"

    response = httpx.Response(401, text="missing auth")
    client = _install_recording_client(monkeypatch, response)

    suite = AttackSuite(
        source="unit",
        attacks=[
            AttackCase(
                id="atk_plugin_auth",
                name="Missing plugin auth",
                kind="missing_auth",
                operation_id="listPets",
                method="GET",
                path="/pets",
                description="Missing plugin auth",
                omit_header_names=["Authorization"],
            )
        ],
    )

    execute_attack_suite(
        suite,
        base_url="https://example.com",
        auth_plugins=[_BearerPlugin()],
    )

    request = client.requests[0]
    assert request["headers"] == {
        "X-Trace-Id": "trace-123",
    }


def test_execute_attack_suite_copies_suite_auth_state_into_workflows(monkeypatch) -> None:
    class _SuiteTokenPlugin(RuntimePlugin):
        def before_suite(self, context) -> None:
            context.state["token"] = "suite-token"

        def before_request(self, request, context) -> None:
            token = context.state.get("token")
            if token is not None:
                request.headers["Authorization"] = f"Bearer {token}"

    def _handler(request: dict[str, object]) -> httpx.Response:
        if request["url"] == "https://example.com/pets":
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=[{"id": 7}],
            )
        if request["url"] == "https://example.com/pets/7":
            return httpx.Response(404, text="not found")
        raise AssertionError(f"Unexpected request: {request}")

    workflow_client = _HandlerClient(_handler)
    _install_client_sequence(monkeypatch, [_NoopClient(), workflow_client])

    suite = AttackSuite(source="unit", attacks=[_workflow_attack()])

    results = execute_attack_suite(
        suite,
        base_url="https://example.com",
        auth_plugins=[_SuiteTokenPlugin()],
    )

    assert results.results[0].type == "workflow"
    assert workflow_client.requests[0]["headers"]["Authorization"] == "Bearer suite-token"
    assert workflow_client.requests[1]["headers"]["Authorization"] == "Bearer suite-token"


def test_execute_attack_suite_auth_plugin_can_create_workflow_session(monkeypatch) -> None:
    class _LoginPlugin(RuntimePlugin):
        def before_workflow(self, workflow, context) -> None:
            del workflow
            context.client.request("POST", context.build_url("/login"))

    def _handler(request: dict[str, object]) -> httpx.Response:
        if request["url"] == "https://example.com/login":
            return httpx.Response(200, headers={"set-cookie": "session=abc; Path=/"})
        if request["url"] == "https://example.com/pets":
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=[{"id": 1}],
            )
        if request["url"] == "https://example.com/pets/1":
            return httpx.Response(404, text="not found")
        raise AssertionError(f"Unexpected request: {request}")

    workflow_client = _HandlerClient(_handler)
    _install_client_sequence(monkeypatch, [_NoopClient(), workflow_client])

    suite = AttackSuite(source="unit", attacks=[_workflow_attack()])

    execute_attack_suite(
        suite,
        base_url="https://example.com",
        auth_plugins=[_LoginPlugin()],
    )

    assert workflow_client.requests[1]["headers"]["Cookie"] == "session=abc"
    assert workflow_client.requests[2]["headers"]["Cookie"] == "session=abc"


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


def test_attack_suite_supports_mixed_request_and_workflow_round_trip() -> None:
    suite = AttackSuite(
        source="unit",
        attacks=[
            AttackCase(
                id="atk_request",
                name="Request attack",
                kind="missing_auth",
                operation_id="listPets",
                method="GET",
                path="/pets",
                description="Request attack",
            ),
            _workflow_attack(),
        ],
    )

    loaded = AttackSuite.model_validate_json(suite.model_dump_json(indent=2))

    assert loaded.attacks[0].type == "request"
    assert loaded.attacks[1].type == "workflow"


def test_attack_results_support_workflow_round_trip() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                type="workflow",
                attack_id="wf_lookup",
                operation_id="getPet",
                kind="wrong_type_param",
                name="Workflow lookup",
                method="GET",
                url="https://example.com/pets/42",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
                workflow_steps=[
                    WorkflowStepResult(
                        name="List pets",
                        operation_id="listPets",
                        method="GET",
                        url="https://example.com/pets",
                        status_code=200,
                    )
                ],
            )
        ],
    )

    loaded = AttackResults.model_validate_json(results.model_dump_json(indent=2))

    assert loaded.results[0].type == "workflow"
    assert loaded.results[0].workflow_steps
    assert loaded.results[0].workflow_steps[0].name == "List pets"


def test_execute_attack_suite_runs_workflow_setup_then_terminal_attack(monkeypatch) -> None:
    workflow_client = _HandlerClient(
        lambda request: (
            httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=[{"id": 42}],
            )
            if request["url"] == "https://example.com/pets"
            else httpx.Response(500, text="boom")
        )
    )
    _install_client_sequence(monkeypatch, [_NoopClient(), workflow_client])

    suite = AttackSuite(source="unit", attacks=[_workflow_attack()])

    results = execute_attack_suite(suite, base_url="https://example.com")

    result = results.results[0]
    assert result.type == "workflow"
    assert result.flagged is True
    assert result.issue == "server_error"
    assert result.url == "https://example.com/pets/42"
    assert result.workflow_steps and len(result.workflow_steps) == 1
    assert [request["url"] for request in workflow_client.requests] == [
        "https://example.com/pets",
        "https://example.com/pets/42",
    ]


def test_execute_attack_suite_writes_workflow_artifacts(tmp_path, monkeypatch) -> None:
    workflow_client = _HandlerClient(
        lambda request: (
            httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=[{"id": 42}],
            )
            if request["url"] == "https://example.com/pets"
            else httpx.Response(422, text="invalid")
        )
    )
    _install_client_sequence(monkeypatch, [_NoopClient(), workflow_client])

    artifact_dir = tmp_path / "artifacts"
    execute_attack_suite(
        AttackSuite(source="unit", attacks=[_workflow_attack()]),
        base_url="https://example.com",
        artifact_dir=artifact_dir,
    )

    assert (artifact_dir / "wf_lookup-step-01.json").exists()
    assert (artifact_dir / "wf_lookup.json").exists()


def test_execute_attack_suite_persists_cookies_across_workflow_steps(monkeypatch) -> None:
    workflow = _workflow_attack(extracts=[], terminal_path_param=42)
    workflow.terminal_attack.path = "/profile"
    workflow.path = "/profile"
    workflow.terminal_attack.path_params = {}
    workflow.terminal_attack.operation_id = "getProfile"

    workflow_client = _HandlerClient(
        lambda request: (
            httpx.Response(200, headers={"set-cookie": "session=abc123; Path=/"})
            if request["url"] == "https://example.com/pets"
            else httpx.Response(403, text="forbidden")
        )
    )
    _install_client_sequence(monkeypatch, [_NoopClient(), workflow_client])

    execute_attack_suite(
        AttackSuite(source="unit", attacks=[workflow]),
        base_url="https://example.com",
    )

    assert workflow_client.requests[1]["headers"]["Cookie"] == "session=abc123"


def test_execute_attack_suite_returns_non_flagged_result_when_required_extract_is_missing(
    monkeypatch,
) -> None:
    workflow_client = _HandlerClient(
        lambda request: httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json=[{"name": "Milo"}],
        )
    )
    _install_client_sequence(monkeypatch, [_NoopClient(), workflow_client])

    results = execute_attack_suite(
        AttackSuite(source="unit", attacks=[_workflow_attack()]),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.type == "workflow"
    assert result.flagged is False
    assert "Workflow setup failed during 'List pets'" in (result.error or "")
    assert len(workflow_client.requests) == 1


def test_execute_attack_suite_returns_non_flagged_result_for_unresolved_terminal_placeholder(
    monkeypatch,
) -> None:
    workflow_client = _HandlerClient(lambda request: httpx.Response(200, json={"ok": True}))
    _install_client_sequence(monkeypatch, [_NoopClient(), workflow_client])

    workflow = _workflow_attack(extracts=[])
    results = execute_attack_suite(
        AttackSuite(source="unit", attacks=[workflow]),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is False
    assert "before terminal step" in (result.error or "")
    assert len(workflow_client.requests) == 1


def test_execute_attack_suite_requires_json_for_setup_extractions(monkeypatch) -> None:
    workflow_client = _HandlerClient(
        lambda request: httpx.Response(200, text="<html>not json</html>")
    )
    _install_client_sequence(monkeypatch, [_NoopClient(), workflow_client])

    results = execute_attack_suite(
        AttackSuite(source="unit", attacks=[_workflow_attack()]),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is False
    assert "response body was not JSON" in (result.error or "")


def test_execute_attack_suite_treats_graphql_errors_as_expected_failures(monkeypatch) -> None:
    _install_stub_response(monkeypatch, httpx.Response(200, json={"errors": [{"message": "bad"}]}))

    results = execute_attack_suite(
        AttackSuite(
            source="unit",
            attacks=[_graphql_attack_case()],
        ),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is False
    assert result.issue is None
    assert result.status_code == 200
    assert result.response_schema_status is None
    assert result.response_schema_valid is None
    assert result.graphql_response_valid is None


def test_execute_attack_suite_flags_graphql_success_without_errors(monkeypatch) -> None:
    _install_stub_response(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "data": {
                    "book": {
                        "__typename": "Book",
                        "id": "1",
                        "title": "Dune",
                        "rating": 5,
                    }
                }
            },
        ),
    )

    results = execute_attack_suite(
        AttackSuite(
            source="unit",
            attacks=[_graphql_attack_case()],
        ),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "unexpected_success"
    assert result.graphql_response_valid is True


def test_execute_attack_suite_flags_missing_graphql_selected_field(monkeypatch) -> None:
    _install_stub_response(
        monkeypatch,
        httpx.Response(
            200,
            json={"data": {"book": {"__typename": "Book", "id": "1", "rating": 5}}},
        ),
    )

    results = execute_attack_suite(
        AttackSuite(source="unit", attacks=[_graphql_attack_case()]),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "graphql_response_shape_mismatch"
    assert result.graphql_response_valid is False
    assert result.graphql_response_error == "$.data.book: missing selected field 'title'"


def test_execute_attack_suite_flags_wrong_graphql_scalar_type(monkeypatch) -> None:
    _install_stub_response(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "data": {
                    "book": {
                        "__typename": "Book",
                        "id": "1",
                        "title": "Dune",
                        "rating": "five",
                    }
                }
            },
        ),
    )

    results = execute_attack_suite(
        AttackSuite(source="unit", attacks=[_graphql_attack_case()]),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "graphql_response_shape_mismatch"
    assert result.graphql_response_error == "$.data.book.rating: expected Int, got string"


def test_execute_attack_suite_flags_missing_nested_graphql_selected_field(monkeypatch) -> None:
    _install_stub_response(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "data": {
                    "book": {
                        "__typename": "Book",
                        "id": "1",
                        "title": "Dune",
                        "author": {"__typename": "Author", "id": "a1"},
                    }
                }
            },
        ),
    )

    results = execute_attack_suite(
        AttackSuite(
            source="unit",
            attacks=[
                _graphql_attack_case(
                    output_shape=_graphql_shape_book_with_author(),
                )
            ],
        ),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "graphql_response_shape_mismatch"
    assert result.graphql_response_error == "$.data.book.author: missing selected field 'name'"


def test_execute_attack_suite_flags_wrong_nested_graphql_scalar_type(monkeypatch) -> None:
    _install_stub_response(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "data": {
                    "book": {
                        "__typename": "Book",
                        "id": "1",
                        "title": "Dune",
                        "author": {"__typename": "Author", "id": "a1", "name": 99},
                    }
                }
            },
        ),
    )

    results = execute_attack_suite(
        AttackSuite(
            source="unit",
            attacks=[
                _graphql_attack_case(
                    output_shape=_graphql_shape_book_with_author(),
                )
            ],
        ),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "graphql_response_shape_mismatch"
    assert result.graphql_response_error == "$.data.book.author.name: expected String, got integer"


def test_execute_attack_suite_flags_graphql_list_item_shape_mismatch(monkeypatch) -> None:
    _install_stub_response(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "data": {
                    "books": [
                        {
                            "__typename": "Book",
                            "id": "1",
                            "title": 7,
                            "rating": 5,
                        }
                    ]
                }
            },
        ),
    )

    attack = _graphql_attack_case(
        output_shape=GraphQLOutputShape(
            kind="list",
            type_name="Book",
            nullable=False,
            item_shape=_graphql_shape_book(nullable=False),
        )
    ).model_copy(
        update={
            "operation_id": "books",
            "graphql_root_field_name": "books",
            "body_json": {
                "query": "query Books { books { __typename id title rating } }",
                "variables": {},
            },
        }
    )

    results = execute_attack_suite(
        AttackSuite(source="unit", attacks=[attack]),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "graphql_response_shape_mismatch"
    assert result.graphql_response_error == "$.data.books[0].title: expected String, got integer"


def test_execute_attack_suite_allows_partial_graphql_data_when_shape_is_valid(monkeypatch) -> None:
    _install_stub_response(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "data": {
                    "book": {"__typename": "Book", "id": "1", "title": "Dune", "rating": None}
                },
                "errors": [{"message": "rating resolver failed"}],
            },
        ),
    )

    results = execute_attack_suite(
        AttackSuite(source="unit", attacks=[_graphql_attack_case()]),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is False
    assert result.issue is None
    assert result.graphql_response_valid is True


def test_execute_attack_suite_flags_partial_graphql_data_when_shape_is_invalid(monkeypatch) -> None:
    _install_stub_response(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "data": {"book": {"__typename": "Book", "id": "1", "rating": None}},
                "errors": [{"message": "title resolver failed"}],
            },
        ),
    )

    results = execute_attack_suite(
        AttackSuite(source="unit", attacks=[_graphql_attack_case()]),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "graphql_response_shape_mismatch"
    assert "missing selected field 'title'" in (result.graphql_response_error or "")


def test_execute_attack_suite_adds_graphql_federation_hint(monkeypatch) -> None:
    _install_stub_response(
        monkeypatch,
        httpx.Response(200, json={"data": {"book": {"__typename": "Book", "id": "1"}}}),
    )

    results = execute_attack_suite(
        AttackSuite(
            source="unit",
            attacks=[_graphql_attack_case(federated=True, entity_types=["Book"])],
        ),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.graphql_response_valid is False
    assert result.graphql_response_hint is not None
    assert "federated" in result.graphql_response_hint.lower()


def test_execute_attack_suite_validates_graphql_union_typename(monkeypatch) -> None:
    _install_stub_response(
        monkeypatch,
        httpx.Response(
            200,
            json={"data": {"node": {"__typename": "Magazine", "id": "1", "title": "Issue 1"}}},
        ),
    )

    union_shape = GraphQLOutputShape(
        kind="interface",
        type_name="Node",
        nullable=True,
        possible_types={"Book": _graphql_shape_book()},
    )
    attack = _graphql_attack_case(output_shape=union_shape)
    attack = attack.model_copy(
        update={
            "operation_id": "node",
            "graphql_root_field_name": "node",
            "body_json": {
                "query": (
                    "query Node($id: ID!) { "
                    "node(id: $id) { __typename ... on Book { id title rating } } "
                    "}"
                ),
                "variables": {"id": "1"},
            },
        }
    )

    results = execute_attack_suite(
        AttackSuite(source="unit", attacks=[attack]),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "graphql_response_shape_mismatch"
    assert "expected one of ['Book']" in (result.graphql_response_error or "")


def test_execute_attack_suite_accepts_valid_graphql_interface_runtime_type(monkeypatch) -> None:
    _install_stub_response(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "data": {
                    "node": {
                        "__typename": "Magazine",
                        "id": "1",
                        "title": "Issue 1",
                        "issue": 7,
                    }
                }
            },
        ),
    )

    attack = _graphql_attack_case(
        output_shape=GraphQLOutputShape(
            kind="interface",
            type_name="Node",
            nullable=True,
            possible_types={
                "Book": _graphql_shape_book(),
                "Magazine": _graphql_shape_magazine(),
            },
        )
    ).model_copy(
        update={
            "operation_id": "node",
            "graphql_root_field_name": "node",
            "body_json": {
                "query": (
                    "query Node($id: ID!) { "
                    "node(id: $id) { __typename ... on Book { id title rating } "
                    "... on Magazine { id title issue } } }"
                ),
                "variables": {"id": "1"},
            },
        }
    )

    results = execute_attack_suite(
        AttackSuite(source="unit", attacks=[attack]),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "unexpected_success"
    assert result.graphql_response_valid is True


def test_execute_attack_suite_flags_missing_graphql_fragment_field(monkeypatch) -> None:
    _install_stub_response(
        monkeypatch,
        httpx.Response(
            200,
            json={"data": {"node": {"__typename": "Book", "id": "1", "rating": 5}}},
        ),
    )

    attack = _graphql_attack_case(
        output_shape=GraphQLOutputShape(
            kind="interface",
            type_name="Node",
            nullable=True,
            possible_types={"Book": _graphql_shape_book()},
        )
    ).model_copy(
        update={
            "operation_id": "node",
            "graphql_root_field_name": "node",
            "body_json": {
                "query": (
                    "query Node($id: ID!) { "
                    "node(id: $id) { __typename ... on Book { id title rating } } "
                    "}"
                ),
                "variables": {"id": "1"},
            },
        }
    )

    results = execute_attack_suite(
        AttackSuite(source="unit", attacks=[attack]),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "graphql_response_shape_mismatch"
    assert result.graphql_response_error == "$.data.node: missing selected field 'title'"


def test_execute_attack_suite_flags_partial_graphql_fragment_data_when_shape_is_invalid(
    monkeypatch,
) -> None:
    _install_stub_response(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "data": {
                    "book": {
                        "__typename": "Book",
                        "id": "1",
                        "title": "Dune",
                        "author": {"__typename": "Author", "id": "a1"},
                    }
                },
                "errors": [{"message": "author.name resolver failed"}],
            },
        ),
    )

    results = execute_attack_suite(
        AttackSuite(
            source="unit",
            attacks=[
                _graphql_attack_case(
                    output_shape=_graphql_shape_book_with_author(),
                )
            ],
        ),
        base_url="https://example.com",
    )

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "graphql_response_shape_mismatch"
    assert result.graphql_response_error == "$.data.book.author: missing selected field 'name'"


def test_execute_attack_suite_runs_graphql_subscription_over_websocket() -> None:
    def _handler(websocket) -> None:
        init_frame = json.loads(websocket.recv())
        assert init_frame == {"type": "connection_init"}
        websocket.send(json.dumps({"type": "connection_ack"}))

        subscribe_frame = json.loads(websocket.recv())
        assert subscribe_frame["type"] == "subscribe"
        assert subscribe_frame["payload"]["variables"] == {"id": "1"}
        websocket.send(
            json.dumps(
                {
                    "id": subscribe_frame["id"],
                    "type": "next",
                    "payload": {
                        "data": {
                            "bookEvents": {
                                "__typename": "Book",
                                "id": "1",
                                "title": "Dune",
                                "rating": 5,
                            }
                        }
                    },
                }
            )
        )

    with _graphql_subscription_server(_handler) as base_url:
        results = execute_attack_suite(
            AttackSuite(source="unit", attacks=[_graphql_subscription_attack_case()]),
            base_url=base_url,
            timeout_seconds=0.5,
        )

    result = results.results[0]
    assert result.flagged is False
    assert result.issue is None
    assert result.status_code == 200
    assert result.graphql_response_valid is True
    assert result.url.endswith("/graphql")


def test_execute_attack_suite_validates_nested_graphql_subscription_payload() -> None:
    def _handler(websocket) -> None:
        init_frame = json.loads(websocket.recv())
        assert init_frame == {"type": "connection_init"}
        websocket.send(json.dumps({"type": "connection_ack"}))

        subscribe_frame = json.loads(websocket.recv())
        assert subscribe_frame["type"] == "subscribe"
        websocket.send(
            json.dumps(
                {
                    "type": "next",
                    "id": subscribe_frame["id"],
                    "payload": {
                        "data": {
                            "bookEvents": {
                                "__typename": "Book",
                                "id": "1",
                                "title": "Dune",
                                "author": {
                                    "__typename": "Author",
                                    "id": "a1",
                                    "name": "Frank Herbert",
                                },
                            }
                        }
                    },
                }
            )
        )

    attack = _graphql_subscription_attack_case(
        body_json={
            "query": (
                "subscription BookEvents($id: ID!) { "
                "bookEvents(id: $id) { __typename id title author { __typename id name } } "
                "}"
            ),
            "variables": {"id": "1"},
        },
        output_shape=_graphql_shape_book_with_author(nullable=False),
    )

    with _graphql_subscription_server(_handler) as base_url:
        results = execute_attack_suite(
            AttackSuite(source="unit", attacks=[attack]),
            base_url=base_url,
        )

    result = results.results[0]
    assert result.flagged is False
    assert result.issue is None
    assert result.graphql_response_valid is True


def test_execute_attack_suite_handles_graphql_subscription_ping_frames() -> None:
    def _handler(websocket) -> None:
        assert json.loads(websocket.recv()) == {"type": "connection_init"}
        websocket.send(json.dumps({"type": "connection_ack"}))

        subscribe_frame = json.loads(websocket.recv())
        websocket.send(json.dumps({"type": "ping", "payload": {"cursor": "1"}}))
        assert json.loads(websocket.recv()) == {"type": "pong", "payload": {"cursor": "1"}}
        websocket.send(
            json.dumps(
                {
                    "id": subscribe_frame["id"],
                    "type": "next",
                    "payload": {
                        "data": {
                            "bookEvents": {
                                "__typename": "Book",
                                "id": "1",
                                "title": "Dune",
                                "rating": 5,
                            }
                        }
                    },
                }
            )
        )

    with _graphql_subscription_server(_handler) as base_url:
        results = execute_attack_suite(
            AttackSuite(source="unit", attacks=[_graphql_subscription_attack_case()]),
            base_url=base_url,
            timeout_seconds=0.5,
        )

    result = results.results[0]
    assert result.flagged is False
    assert result.issue is None
    assert result.status_code == 200


def test_execute_attack_suite_accepts_graphql_subscription_error_frames() -> None:
    def _handler(websocket) -> None:
        assert json.loads(websocket.recv()) == {"type": "connection_init"}
        websocket.send(json.dumps({"type": "connection_ack"}))

        subscribe_frame = json.loads(websocket.recv())
        websocket.send(
            json.dumps(
                {
                    "id": subscribe_frame["id"],
                    "type": "error",
                    "payload": [{"message": "Variable '$id' must be an ID."}],
                }
            )
        )

    with _graphql_subscription_server(_handler) as base_url:
        results = execute_attack_suite(
            AttackSuite(
                source="unit",
                attacks=[
                    _graphql_subscription_attack_case(
                        body_json={
                            "query": (
                                "subscription BookEvents($id: ID!) { bookEvents(id: $id) { id } }"
                            ),
                            "variables": {"id": 123},
                        },
                        expected_outcomes=["graphql_error"],
                    )
                ],
            ),
            base_url=base_url,
            timeout_seconds=0.5,
        )

    result = results.results[0]
    assert result.flagged is False
    assert result.issue is None
    assert result.graphql_response_valid is None
    assert result.response_excerpt is not None
    assert "Variable '$id' must be an ID." in result.response_excerpt


def test_execute_attack_suite_accepts_graphql_subscription_error_object_frames() -> None:
    def _handler(websocket) -> None:
        assert json.loads(websocket.recv()) == {"type": "connection_init"}
        websocket.send(json.dumps({"type": "connection_ack"}))

        subscribe_frame = json.loads(websocket.recv())
        websocket.send(
            json.dumps(
                {
                    "id": subscribe_frame["id"],
                    "type": "error",
                    "payload": {"message": "Subscription denied."},
                }
            )
        )

    with _graphql_subscription_server(_handler) as base_url:
        results = execute_attack_suite(
            AttackSuite(
                source="unit",
                attacks=[_graphql_subscription_attack_case(expected_outcomes=["graphql_error"])],
            ),
            base_url=base_url,
            timeout_seconds=0.5,
        )

    result = results.results[0]
    assert result.flagged is False
    assert result.issue is None
    assert result.response_excerpt is not None
    assert "Subscription denied." in result.response_excerpt


def test_execute_attack_suite_flags_graphql_subscription_protocol_errors() -> None:
    def _handler(websocket) -> None:
        assert json.loads(websocket.recv()) == {"type": "connection_init"}
        websocket.send(json.dumps({"type": "pong"}))

    with _graphql_subscription_server(_handler) as base_url:
        results = execute_attack_suite(
            AttackSuite(source="unit", attacks=[_graphql_subscription_attack_case()]),
            base_url=base_url,
            timeout_seconds=0.5,
        )

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "graphql_subscription_protocol_error"
    assert result.graphql_response_valid is None
    assert result.error is not None
    assert "connection_ack" in result.error


def test_execute_attack_suite_flags_graphql_subscription_completion_without_result() -> None:
    def _handler(websocket) -> None:
        assert json.loads(websocket.recv()) == {"type": "connection_init"}
        websocket.send(json.dumps({"type": "connection_ack"}))

        subscribe_frame = json.loads(websocket.recv())
        websocket.send(
            json.dumps(
                {
                    "id": subscribe_frame["id"],
                    "type": "complete",
                }
            )
        )

    with _graphql_subscription_server(_handler) as base_url:
        results = execute_attack_suite(
            AttackSuite(source="unit", attacks=[_graphql_subscription_attack_case()]),
            base_url=base_url,
            timeout_seconds=0.5,
        )

    result = results.results[0]
    assert result.flagged is True
    assert result.issue == "graphql_subscription_protocol_error"
    assert result.error is not None
    assert "completed without a result payload" in result.error


def test_render_markdown_report_shows_workflow_sections() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                type="workflow",
                attack_id="wf_lookup",
                operation_id="getPet",
                kind="wrong_type_param",
                name="Workflow lookup",
                method="GET",
                url="https://example.com/pets/42",
                status_code=500,
                flagged=False,
                severity="none",
                confidence="none",
                error="Workflow setup failed during 'List pets': unexpected status 500",
                workflow_steps=[
                    WorkflowStepResult(
                        name="List pets",
                        operation_id="listPets",
                        method="GET",
                        url="https://example.com/pets",
                        status_code=500,
                        error="upstream unavailable",
                    )
                ],
            )
        ],
    )

    report = render_markdown_report(results)

    assert "- Type: `workflow`" in report
    assert "- Workflow phase: `setup`" in report
    assert "| Step | Operation | Method | Status | URL |" in report
    assert "List pets" in report


def test_render_markdown_summary_shows_empty_baseline_and_profiles() -> None:
    current = AttackResults(
        source="unit",
        base_url="https://example.com",
        profiles=["user|team"],
        results=[],
    )
    baseline = AttackResults(
        source="baseline",
        base_url="https://example.com",
        results=[],
    )

    report = render_markdown_summary(summarize_results(current, baseline=baseline))

    assert "- Baseline used: **yes**" in report
    assert "- Baseline executed at:" in report
    assert "- Profiles: `user\\|team`" in report
    assert "No protocol counts recorded." in report
    assert "No active findings in the current summary." in report
    assert "No auth diagnostics recorded." in report


def test_render_html_report_shows_artifact_index_and_profile_outcomes(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    (artifact_root / "wf_lookup.json").write_text("{}", encoding="utf-8")
    (artifact_root / "wf_lookup-step-01.json").write_text("{}", encoding="utf-8")
    profile_root = artifact_root / "anonymous"
    profile_root.mkdir()
    (profile_root / "wf_lookup.json").write_text("{}", encoding="utf-8")
    (profile_root / "wf_lookup-step-01.json").write_text("{}", encoding="utf-8")

    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        profiles=["anonymous"],
        results=[
            AttackResult(
                type="workflow",
                attack_id="wf_lookup",
                operation_id="getPet",
                kind="wrong_type_param",
                name="Workflow lookup",
                method="GET",
                url="https://example.com/pets/42",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
                response_excerpt='{"error":"boom"}',
                profile_results=[
                    ProfileAttackResult(
                        profile="anonymous",
                        level=0,
                        anonymous=True,
                        url="https://example.com/pets/42",
                        status_code=500,
                        issue="server_error",
                        severity="high",
                        confidence="high",
                        workflow_steps=[
                            WorkflowStepResult(
                                name="List pets",
                                operation_id="listPets",
                                method="GET",
                                url="https://example.com/pets",
                                status_code=200,
                            )
                        ],
                    )
                ],
                workflow_steps=[
                    WorkflowStepResult(
                        name="List pets",
                        operation_id="listPets",
                        method="GET",
                        url="https://example.com/pets",
                        status_code=200,
                    )
                ],
            )
        ],
    )

    report = render_html_report(results, artifact_root=artifact_root)

    assert "<!DOCTYPE html>" in report
    assert "<h2>Artifact index</h2>" in report
    assert "wf_lookup-step-01.json" in report
    assert "<h4>Profile outcomes</h4>" in report
    assert "anonymous (anonymous)" in report
    assert "anonymous step 1" in report


def test_render_html_report_links_workflow_step_artifacts_without_profiles(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    (artifact_root / "wf_lookup-step-01.json").write_text("{}", encoding="utf-8")

    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                type="workflow",
                attack_id="wf_lookup",
                operation_id="getPet",
                kind="wrong_type_param",
                name="Workflow lookup",
                method="GET",
                url="https://example.com/pets/42",
                workflow_steps=[
                    WorkflowStepResult(
                        name="List pets",
                        operation_id="listPets",
                        method="GET",
                        url="https://example.com/pets",
                        status_code=200,
                    )
                ],
            )
        ],
    )

    report = render_html_report(results, artifact_root=artifact_root)

    assert "step 1" in report
    assert "wf_lookup-step-01.json" in report


def test_render_html_report_shows_error_graphql_details_and_suppression_expiry() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_graphql",
                operation_id="book",
                kind="wrong_type_variable",
                name="GraphQL mismatch",
                protocol="graphql",
                method="POST",
                path="/graphql",
                url="https://example.com/graphql",
                status_code=200,
                flagged=True,
                issue="graphql_response_shape_mismatch",
                severity="medium",
                confidence="high",
                error="GraphQL response validation failed.",
                graphql_response_error="$.data.book.title: expected String, got integer",
                graphql_response_hint="Schema appears federated.",
            )
        ],
    )

    report = render_html_report(
        results,
        suppressions=[
            SuppressionRule(
                attack_id="atk_graphql",
                issue="graphql_response_shape_mismatch",
                reason="known schema drift",
                owner="api-team",
                expires_on=date(2099, 1, 1),
            )
        ],
    )

    assert "GraphQL response validation failed." in report
    assert "<h4>GraphQL validation</h4>" in report
    assert "$.data.book.title: expected String, got integer" in report
    assert "Schema appears federated." in report
    assert "known schema drift" in report
    assert "2099-01-01" in report


def test_render_html_report_shows_persisting_deltas() -> None:
    current = AttackResults(
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
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
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
                status_code=401,
                flagged=True,
                issue="server_error",
                severity="medium",
                confidence="low",
            )
        ],
    )

    report = render_html_report(current, baseline=baseline)

    assert "Persisting with deltas" in report
    assert "<h2>Persisting deltas</h2>" in report
    assert "severity medium -&gt; high" in report
    assert "confidence low -&gt; high" in report
    assert "status 401 -&gt; 500" in report


def test_render_html_report_shows_auth_summary() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        auth_events=[
            {
                "profile": "admin",
                "name": "service",
                "strategy": "client_credentials",
                "phase": "acquire",
                "success": False,
                "trigger": "suite",
                "error": "bad secret",
            },
            {
                "profile": "admin",
                "name": "service",
                "strategy": "client_credentials",
                "phase": "refresh",
                "success": True,
                "trigger": "401",
            },
        ],
        results=[],
    )

    report = render_html_report(results)

    assert "<h2>Auth summary</h2>" in report
    assert "<td>admin</td>" in report
    assert "<td>service</td>" in report
    assert "<td>client_credentials</td>" in report
    assert "<td>1</td>" in report
    assert "Refresh attempts" in report
    assert "401, suite" in report


def test_render_html_report_shows_grouped_flagged_findings() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_one",
                operation_id="listPets",
                kind="missing_auth",
                name="Server failure",
                method="GET",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            ),
            AttackResult(
                attack_id="atk_two",
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
                attack_id="atk_three",
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
            ),
        ],
    )

    report = render_html_report(results)

    assert "<h3>By issue</h3>" in report
    assert "<h3>By attack kind</h3>" in report
    assert "<td>server_error</td>" in report
    assert "<td>unexpected_success</td>" in report
    assert "<td>missing_auth</td>" in report
    assert "<td>wrong_type_param</td>" in report


def test_summarize_results_builds_machine_readable_regression_summary() -> None:
    current = AttackResults(
        source="unit",
        base_url="https://example.com",
        auth_events=[
            {
                "profile": "user",
                "name": "user",
                "strategy": "static_bearer",
                "phase": "acquire",
                "success": True,
            },
            {
                "profile": "user",
                "name": "user",
                "strategy": "static_bearer",
                "phase": "refresh",
                "success": False,
                "trigger": "401",
            },
        ],
        results=[
            AttackResult(
                attack_id="atk_new",
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
            AttackResult(
                attack_id="atk_shared",
                operation_id="book",
                kind="wrong_type_variable",
                name="GraphQL mismatch",
                protocol="graphql",
                method="POST",
                path="/graphql",
                url="https://example.com/graphql",
                status_code=200,
                flagged=True,
                issue="graphql_response_shape_mismatch",
                severity="medium",
                confidence="high",
                graphql_response_valid=False,
            ),
        ],
    )
    baseline = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_shared",
                operation_id="book",
                kind="wrong_type_variable",
                name="GraphQL mismatch",
                protocol="graphql",
                method="POST",
                path="/graphql",
                url="https://example.com/graphql",
                status_code=500,
                flagged=True,
                issue="graphql_response_shape_mismatch",
                severity="medium",
                confidence="high",
                graphql_response_valid=False,
            )
        ],
    )

    summary = summarize_results(current, baseline=baseline, top_limit=1)

    assert summary.baseline_used is True
    assert summary.new_findings_count == 1
    assert summary.persisting_findings_count == 1
    assert summary.persisting_deltas_count == 1
    assert summary.auth_failures == 1
    assert summary.refresh_attempts == 1
    assert summary.protocol_counts == {"graphql": 1, "rest": 1}
    assert summary.finding_severity_counts == {"high": 1, "medium": 1}
    assert summary.top_findings[0].attack_id == "atk_new"
