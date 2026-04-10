from __future__ import annotations

import json

import httpx

from knives_out.auth_plugins import RuntimePlugin
from knives_out.models import (
    AttackCase,
    AttackResult,
    AttackResults,
    AttackSuite,
    ExtractRule,
    WorkflowAttackCase,
    WorkflowStep,
    WorkflowStepResult,
)
from knives_out.reporting import render_markdown_report
from knives_out.runner import execute_attack_suite
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
