from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta
from textwrap import dedent

import httpx
import pytest
from fastapi.testclient import TestClient

from knives_out.api import create_app
from knives_out.api_models import ApiJobStatus, JobRecord
from knives_out.api_store import JobStore
from knives_out.models import (
    AttackCase,
    AttackResult,
    AttackResults,
    AttackSuite,
    AuthEvent,
    LearnedModel,
    ProfileAttackResult,
    WorkflowStepResult,
)

OPENAPI_SPEC = dedent(
    """
    openapi: 3.0.3
    info:
      title: Demo API
      version: "1.0"
    paths:
      /pets:
        get:
          operationId: listPets
          parameters:
            - in: query
              name: limit
              required: true
              schema:
                type: integer
                minimum: 1
          responses:
            "200":
              description: ok
    """
)

GRAPHQL_SCHEMA = dedent(
    """
    type Query {
      book(id: ID!): Book
    }

    type Mutation {
      updateBook(id: ID!, title: String!): Book
    }

    type Book {
      id: ID!
      title: String!
    }
    """
)


class _StubClient:
    def __init__(self, response: httpx.Response) -> None:
        self._response = response

    def __enter__(self) -> _StubClient:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def request(self, *_: object, **__: object) -> httpx.Response:
        return self._response


def _install_stub_response(monkeypatch, response: httpx.Response) -> None:
    monkeypatch.setattr(
        "knives_out.runner.httpx.Client",
        lambda **_: _StubClient(response),
    )


def _attack_suite() -> AttackSuite:
    return AttackSuite(
        source="unit",
        attacks=[
            AttackCase(
                id="atk_api",
                name="Missing auth",
                kind="missing_auth",
                operation_id="getSecret",
                method="GET",
                path="/secrets",
                description="Missing auth attack",
            )
        ],
    )


def _flagged_results() -> AttackResults:
    return AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_api",
                operation_id="getSecret",
                kind="missing_auth",
                name="Server failure",
                method="GET",
                path="/secrets",
                url="https://example.com/secrets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ],
    )


def _baseline_results() -> AttackResults:
    return AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_api",
                operation_id="getSecret",
                kind="missing_auth",
                name="Server failure",
                method="GET",
                path="/secrets",
                url="https://example.com/secrets",
                status_code=401,
                flagged=True,
                issue="server_error",
                severity="medium",
                confidence="medium",
            )
        ],
    )


def _workflow_profile_results() -> AttackResults:
    return AttackResults(
        source="unit",
        base_url="https://example.com",
        profiles=["member", "anonymous"],
        auth_events=[
            AuthEvent(
                name="member-login",
                strategy="cookie",
                phase="acquire",
                success=True,
                profile="member",
                endpoint="/login",
                status_code=200,
            ),
            AuthEvent(
                name="anonymous-fallback",
                strategy="header",
                phase="refresh",
                success=False,
                profile="anonymous",
                endpoint="/graphql",
                status_code=401,
                error="expired token",
            ),
            AuthEvent(
                name="admin-session",
                strategy="cookie",
                phase="acquire",
                success=True,
                profile="admin",
                endpoint="/admin",
                status_code=200,
            ),
        ],
        results=[
            AttackResult(
                type="workflow",
                attack_id="wf_checkout",
                operation_id="checkout",
                kind="authorization_inversion",
                name="Checkout workflow",
                method="POST",
                path="/checkout",
                url="https://example.com/checkout",
                status_code=500,
                flagged=True,
                issue="authorization_inversion",
                severity="high",
                confidence="medium",
                workflow_steps=[
                    WorkflowStepResult(
                        name="Create cart",
                        operation_id="createCart",
                        method="POST",
                        url="https://example.com/cart",
                        status_code=201,
                        duration_ms=12.4,
                        response_excerpt='{"id":"cart-1"}',
                    )
                ],
                profile_results=[
                    ProfileAttackResult(
                        profile="member",
                        level=1,
                        anonymous=False,
                        url="https://example.com/checkout",
                        status_code=403,
                        flagged=True,
                        issue="authorization_inversion",
                        severity="high",
                        confidence="high",
                        workflow_steps=[
                            WorkflowStepResult(
                                name="Create cart",
                                operation_id="createCart",
                                method="POST",
                                url="https://example.com/cart",
                                status_code=201,
                            )
                        ],
                    ),
                    ProfileAttackResult(
                        profile="anonymous",
                        level=0,
                        anonymous=True,
                        url="https://example.com/checkout",
                        status_code=200,
                        flagged=False,
                        severity="none",
                        confidence="none",
                    ),
                ],
            )
        ],
    )


def _stored_job(
    store: JobStore,
    *,
    status: ApiJobStatus,
    created_at: datetime,
    completed_at: datetime | None = None,
    base_url: str = "https://example.com",
    attack_count: int = 1,
    project_id: str | None = None,
    error: str | None = None,
    with_result: bool = False,
    with_artifact: bool = False,
) -> JobRecord:
    record = store.create_job(
        JobRecord(base_url=base_url, attack_count=attack_count, project_id=project_id).model_copy(
            update={
                "status": status,
                "created_at": created_at,
                "started_at": created_at,
                "completed_at": completed_at,
                "project_id": project_id,
                "error": error,
            }
        )
    )
    if with_result:
        store.write_result(record.id, _flagged_results().model_copy(update={"base_url": base_url}))
    if with_artifact:
        artifact_path = store.artifact_dir(record.id) / "atk_api.json"
        artifact_path.write_text('{"attack":{"id":"atk_api"}}', encoding="utf-8")
    return record


def test_create_app_uses_env_data_dir_and_healthz_endpoint(tmp_path, monkeypatch) -> None:
    configured = tmp_path / "api-data"
    monkeypatch.setenv("KNIVES_OUT_API_DATA_DIR", str(configured))
    app = create_app()
    client = TestClient(app)

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert app.state.job_store.root == configured


def test_edition_endpoint_defaults_to_free_without_extensions(tmp_path) -> None:
    client = TestClient(create_app(data_dir=tmp_path))

    response = client.get("/v1/edition")

    assert response.status_code == 200
    payload = response.json()
    assert payload["edition"] == "free"
    assert payload["plan"] == "Free"
    assert payload["license_state"] == "missing"
    assert payload["enabled_capabilities"] == []
    assert "ci_reviewops" in payload["locked_capabilities"]


def test_api_extension_can_register_routes_and_edition_status(tmp_path, monkeypatch) -> None:
    class FakeExtension:
        name = "fake-pro"

        def edition_status(self):
            return {
                "edition": "pro",
                "plan": "Team",
                "license_state": "valid",
                "enabled_capabilities": ["ci_reviewops"],
                "locked_capabilities": [],
                "customer": "Example Co",
                "message": "Pro enabled.",
            }

        def register_api(self, app):
            @app.get("/v1/pro/ping")
            def ping():
                return {"status": "pro"}

    class FakeEntryPoint:
        name = "fake-pro"

        def load(self):
            return FakeExtension

    monkeypatch.setattr(
        "knives_out.extensions._iter_extension_entry_points",
        lambda: [FakeEntryPoint()],
    )
    client = TestClient(create_app(data_dir=tmp_path))

    edition_response = client.get("/v1/edition")
    pro_response = client.get("/v1/pro/ping")

    assert edition_response.status_code == 200
    assert edition_response.json()["edition"] == "pro"
    assert edition_response.json()["enabled_capabilities"] == ["ci_reviewops"]
    assert pro_response.status_code == 200
    assert pro_response.json() == {"status": "pro"}


def test_create_app_requires_complete_basic_auth_configuration(monkeypatch) -> None:
    monkeypatch.setenv("KNIVES_OUT_BASIC_AUTH_USERNAME", "demo")
    monkeypatch.delenv("KNIVES_OUT_BASIC_AUTH_PASSWORD", raising=False)

    with pytest.raises(
        ValueError,
        match=(
            "Set both KNIVES_OUT_BASIC_AUTH_USERNAME and "
            "KNIVES_OUT_BASIC_AUTH_PASSWORD or leave both unset."
        ),
    ):
        create_app()


def test_inspect_endpoint_supports_inline_graphql_schema(tmp_path) -> None:
    client = TestClient(create_app(data_dir=tmp_path))

    response = client.post(
        "/v1/inspect",
        json={
            "source": {
                "name": "library.graphql",
                "content": GRAPHQL_SCHEMA,
            }
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["source_kind"] == "graphql"
    assert {operation["operation_id"] for operation in payload["operations"]} == {
        "book",
        "updateBook",
    }
    assert payload["learned_workflow_count"] == 0


def test_generate_endpoint_supports_inline_openapi_source(tmp_path) -> None:
    client = TestClient(create_app(data_dir=tmp_path))

    response = client.post(
        "/v1/generate",
        json={
            "source": {
                "name": "demo.yaml",
                "content": OPENAPI_SPEC,
            }
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["source_kind"] == "openapi"
    assert payload["suite"]["attacks"]
    assert {attack["operation_id"] for attack in payload["suite"]["attacks"]} == {"listPets"}


def test_run_job_lifecycle_and_artifacts(tmp_path, monkeypatch) -> None:
    _install_stub_response(monkeypatch, httpx.Response(422, text="missing auth"))
    client = TestClient(create_app(data_dir=tmp_path))

    response = client.post(
        "/v1/runs",
        json={
            "suite": _attack_suite().model_dump(mode="json"),
            "base_url": "https://example.com",
            "store_artifacts": True,
        },
    )

    assert response.status_code == 200
    job_id = response.json()["id"]

    status_payload = None
    for _ in range(50):
        status_response = client.get(f"/v1/jobs/{job_id}")
        assert status_response.status_code == 200
        status_payload = status_response.json()
        if status_payload["status"] == "completed":
            break
        time.sleep(0.02)

    assert status_payload is not None
    assert status_payload["status"] == "completed"
    assert status_payload["result_available"] is True
    assert status_payload["artifact_names"] == ["atk_api.json"]
    assert status_payload["result_summary"] is not None
    assert status_payload["result_summary"]["total_results"] == 1

    result_response = client.get(f"/v1/jobs/{job_id}/result")
    assert result_response.status_code == 200
    assert result_response.json()["results"][0]["attack_id"] == "atk_api"

    artifact_list_response = client.get(f"/v1/jobs/{job_id}/artifacts")
    assert artifact_list_response.status_code == 200
    assert artifact_list_response.json()["artifacts"] == ["atk_api.json"]

    artifact_response = client.get(f"/v1/jobs/{job_id}/artifacts/atk_api.json")
    assert artifact_response.status_code == 200
    assert artifact_response.json()["attack"]["id"] == "atk_api"


def test_job_finding_evidence_endpoint_returns_request_artifact_context(tmp_path) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store
    record = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=datetime(2026, 4, 13, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 4, 13, 12, 1, tzinfo=UTC),
        with_result=True,
        with_artifact=True,
    )

    response = client.get(f"/v1/jobs/{record.id}/findings/atk_api/evidence")

    assert response.status_code == 200
    payload = response.json()
    assert payload["job_id"] == record.id
    assert payload["attack_id"] == "atk_api"
    assert payload["result"]["attack_id"] == "atk_api"
    assert payload["artifacts"] == [
        {
            "label": "Request artifact",
            "kind": "request",
            "artifact_name": "atk_api.json",
            "available": True,
            "profile": None,
            "step_index": None,
        }
    ]
    assert payload["auth_events"] == []
    assert payload["highlighted_auth_events"] == []


def test_job_finding_evidence_endpoint_returns_workflow_and_profile_artifacts(tmp_path) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store
    record = store.create_job(
        JobRecord(base_url="https://example.com", attack_count=1).model_copy(
            update={
                "status": ApiJobStatus.completed,
                "created_at": datetime(2026, 4, 13, 12, 0, tzinfo=UTC),
                "started_at": datetime(2026, 4, 13, 12, 0, tzinfo=UTC),
                "completed_at": datetime(2026, 4, 13, 12, 1, tzinfo=UTC),
            }
        )
    )
    store.write_result(record.id, _workflow_profile_results())
    artifact_root = store.artifact_dir(record.id)
    (artifact_root / "wf_checkout.json").write_text(
        '{"attack":{"id":"wf_checkout"}}',
        encoding="utf-8",
    )
    (artifact_root / "wf_checkout-step-01.json").write_text(
        '{"attack":{"id":"wf_checkout-step-01"}}',
        encoding="utf-8",
    )
    member_root = artifact_root / "member"
    member_root.mkdir(parents=True, exist_ok=True)
    (member_root / "wf_checkout.json").write_text(
        '{"attack":{"id":"wf_checkout","profile":"member"}}',
        encoding="utf-8",
    )
    (member_root / "wf_checkout-step-01.json").write_text(
        '{"attack":{"id":"wf_checkout-step-01","profile":"member"}}',
        encoding="utf-8",
    )

    response = client.get(f"/v1/jobs/{record.id}/findings/wf_checkout/evidence")

    assert response.status_code == 200
    payload = response.json()
    assert payload["result"]["type"] == "workflow"
    assert payload["result"]["workflow_steps"][0]["name"] == "Create cart"
    assert [artifact["artifact_name"] for artifact in payload["artifacts"]] == [
        "wf_checkout.json",
        "wf_checkout-step-01.json",
        "member/wf_checkout.json",
        "member/wf_checkout-step-01.json",
        "anonymous/wf_checkout.json",
    ]
    assert [artifact["available"] for artifact in payload["artifacts"]] == [
        True,
        True,
        True,
        True,
        False,
    ]
    assert [artifact["kind"] for artifact in payload["artifacts"]] == [
        "workflow_terminal",
        "workflow_step",
        "profile_request",
        "profile_workflow_step",
        "profile_request",
    ]
    assert [event["profile"] for event in payload["highlighted_auth_events"]] == [
        "member",
        "anonymous",
    ]
    assert len(payload["auth_events"]) == 3


def test_job_finding_evidence_endpoint_handles_missing_results_attacks_and_artifacts(
    tmp_path,
) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store
    missing_result = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=datetime(2026, 4, 13, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 4, 13, 12, 1, tzinfo=UTC),
    )
    no_artifact = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=datetime(2026, 4, 13, 13, 0, tzinfo=UTC),
        completed_at=datetime(2026, 4, 13, 13, 1, tzinfo=UTC),
        with_result=True,
    )

    assert client.get("/v1/jobs/missing/findings/atk_api/evidence").status_code == 404

    missing_result_response = client.get(f"/v1/jobs/{missing_result.id}/findings/atk_api/evidence")
    assert missing_result_response.status_code == 404
    assert missing_result_response.json()["detail"] == "Job result not available."

    missing_finding_response = client.get(f"/v1/jobs/{no_artifact.id}/findings/missing/evidence")
    assert missing_finding_response.status_code == 404
    assert missing_finding_response.json()["detail"] == "Finding not found for job."

    no_artifact_response = client.get(f"/v1/jobs/{no_artifact.id}/findings/atk_api/evidence")
    assert no_artifact_response.status_code == 200
    assert no_artifact_response.json()["artifacts"][0]["available"] is False


def test_run_job_status_endpoints_404_for_missing_job(tmp_path) -> None:
    client = TestClient(create_app(data_dir=tmp_path))

    response = client.get("/v1/jobs/missing")
    assert response.status_code == 404

    response = client.get("/v1/jobs/missing/result")
    assert response.status_code == 404

    response = client.get("/v1/jobs/missing/artifacts")
    assert response.status_code == 404

    response = client.get("/v1/jobs/missing/artifacts/missing.json")
    assert response.status_code == 404


def test_run_job_failure_is_reported(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "knives_out.api.run_suite_from_inline",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("runner exploded")),
    )
    client = TestClient(create_app(data_dir=tmp_path))

    response = client.post(
        "/v1/runs",
        json={
            "suite": _attack_suite().model_dump(mode="json"),
            "base_url": "https://example.com",
            "store_artifacts": False,
        },
    )

    assert response.status_code == 200
    job_id = response.json()["id"]

    status_payload = None
    for _ in range(50):
        status_response = client.get(f"/v1/jobs/{job_id}")
        assert status_response.status_code == 200
        status_payload = status_response.json()
        if status_payload["status"] == "failed":
            break
        time.sleep(0.02)

    assert status_payload is not None
    assert status_payload["status"] == "failed"
    assert status_payload["result_available"] is False
    assert status_payload["artifact_names"] == []
    assert status_payload["error"] == "runner exploded"
    assert status_payload["result_summary"] is None

    result_response = client.get(f"/v1/jobs/{job_id}/result")
    assert result_response.status_code == 404


def test_delete_job_removes_completed_job_and_related_artifacts(tmp_path) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store
    completed_at = datetime(2026, 4, 13, 12, 0, tzinfo=UTC)
    record = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=completed_at - timedelta(minutes=1),
        completed_at=completed_at,
        with_result=True,
        with_artifact=True,
    )

    response = client.delete(f"/v1/jobs/{record.id}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["deleted"]["id"] == record.id
    assert payload["deleted"]["status"] == "completed"
    assert payload["deleted"]["result_available"] is True
    assert payload["deleted"]["artifact_names"] == ["atk_api.json"]
    assert not store.job_dir(record.id).exists()

    assert client.get(f"/v1/jobs/{record.id}").status_code == 404
    assert client.get(f"/v1/jobs/{record.id}/result").status_code == 404
    assert client.get(f"/v1/jobs/{record.id}/artifacts").status_code == 404


def test_delete_job_rejects_active_jobs(tmp_path) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store
    record = _stored_job(
        store,
        status=ApiJobStatus.running,
        created_at=datetime(2026, 4, 13, 12, 0, tzinfo=UTC),
    )

    response = client.delete(f"/v1/jobs/{record.id}")

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "Active jobs cannot be deleted; wait for completion or failure first."
    )
    assert store.job_dir(record.id).exists()


def test_project_job_delete_endpoint_removes_only_matching_project_job(tmp_path) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store
    project_id = client.post("/v1/projects", json={"name": "Workbench demo"}).json()["id"]
    other_project_id = client.post("/v1/projects", json={"name": "Other demo"}).json()["id"]
    completed_at = datetime(2026, 4, 13, 12, 0, tzinfo=UTC)
    record = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=completed_at - timedelta(minutes=1),
        completed_at=completed_at,
        project_id=project_id,
        with_result=True,
        with_artifact=True,
    )
    other_record = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=completed_at - timedelta(minutes=2),
        completed_at=completed_at - timedelta(minutes=1),
        project_id=other_project_id,
        with_result=True,
    )

    response = client.delete(f"/v1/projects/{project_id}/jobs/{record.id}")

    assert response.status_code == 200
    assert response.json()["deleted"]["id"] == record.id
    assert not store.job_dir(record.id).exists()
    assert store.job_dir(other_record.id).exists()

    missing_response = client.delete(f"/v1/projects/{project_id}/jobs/{other_record.id}")
    assert missing_response.status_code == 404
    assert missing_response.json()["detail"] == "Job not found."


def test_prune_jobs_supports_dry_run_and_completed_before_filter(tmp_path) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store
    cutoff = datetime(2026, 4, 13, 12, 0, tzinfo=UTC)
    old_completed = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=cutoff - timedelta(hours=2),
        completed_at=cutoff - timedelta(hours=1),
        with_result=True,
    )
    old_failed = _stored_job(
        store,
        status=ApiJobStatus.failed,
        created_at=cutoff - timedelta(hours=3),
        completed_at=cutoff - timedelta(hours=2),
        error="boom",
        with_artifact=True,
    )
    _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=cutoff - timedelta(minutes=10),
        completed_at=cutoff + timedelta(minutes=5),
        with_result=True,
    )
    _stored_job(
        store,
        status=ApiJobStatus.running,
        created_at=cutoff - timedelta(minutes=2),
    )

    dry_run = client.post(
        "/v1/jobs/prune",
        json={
            "statuses": ["completed", "failed"],
            "completed_before": cutoff.isoformat(),
            "limit": 10,
            "dry_run": True,
        },
    )

    assert dry_run.status_code == 200
    dry_payload = dry_run.json()
    assert dry_payload["dry_run"] is True
    assert dry_payload["matched_count"] == 2
    assert dry_payload["deleted_count"] == 0
    assert [job["id"] for job in dry_payload["jobs"]] == [old_completed.id, old_failed.id]
    assert store.job_dir(old_completed.id).exists()
    assert store.job_dir(old_failed.id).exists()

    response = client.post(
        "/v1/jobs/prune",
        json={
            "statuses": ["completed", "failed"],
            "completed_before": cutoff.isoformat(),
            "limit": 10,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["dry_run"] is False
    assert payload["matched_count"] == 2
    assert payload["deleted_count"] == 2
    assert [job["id"] for job in payload["jobs"]] == [old_completed.id, old_failed.id]
    assert not store.job_dir(old_completed.id).exists()
    assert not store.job_dir(old_failed.id).exists()


def test_project_prune_jobs_only_matches_runs_for_that_project(tmp_path) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store
    project_id = client.post("/v1/projects", json={"name": "Workbench demo"}).json()["id"]
    other_project_id = client.post("/v1/projects", json={"name": "Other demo"}).json()["id"]
    cutoff = datetime(2026, 4, 13, 12, 0, tzinfo=UTC)
    old_completed = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=cutoff - timedelta(hours=2),
        completed_at=cutoff - timedelta(hours=1),
        project_id=project_id,
        with_result=True,
    )
    old_failed = _stored_job(
        store,
        status=ApiJobStatus.failed,
        created_at=cutoff - timedelta(hours=3),
        completed_at=cutoff - timedelta(hours=2),
        project_id=project_id,
        error="boom",
        with_artifact=True,
    )
    other_project_job = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=cutoff - timedelta(hours=4),
        completed_at=cutoff - timedelta(hours=3),
        project_id=other_project_id,
        with_result=True,
    )
    global_job = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=cutoff - timedelta(hours=5),
        completed_at=cutoff - timedelta(hours=4),
        with_result=True,
    )

    dry_run = client.post(
        f"/v1/projects/{project_id}/jobs/prune",
        json={
            "statuses": ["completed", "failed"],
            "completed_before": cutoff.isoformat(),
            "limit": 10,
            "dry_run": True,
        },
    )

    assert dry_run.status_code == 200
    dry_payload = dry_run.json()
    assert dry_payload["dry_run"] is True
    assert dry_payload["matched_count"] == 2
    assert [job["id"] for job in dry_payload["jobs"]] == [old_completed.id, old_failed.id]
    assert store.job_dir(other_project_job.id).exists()
    assert store.job_dir(global_job.id).exists()

    response = client.post(
        f"/v1/projects/{project_id}/jobs/prune",
        json={
            "statuses": ["completed", "failed"],
            "completed_before": cutoff.isoformat(),
            "limit": 10,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["matched_count"] == 2
    assert payload["deleted_count"] == 2
    assert [job["id"] for job in payload["jobs"]] == [old_completed.id, old_failed.id]
    assert not store.job_dir(old_completed.id).exists()
    assert not store.job_dir(old_failed.id).exists()
    assert store.job_dir(other_project_job.id).exists()
    assert store.job_dir(global_job.id).exists()


def test_prune_jobs_rejects_active_status_filters(tmp_path) -> None:
    client = TestClient(create_app(data_dir=tmp_path))

    response = client.post("/v1/jobs/prune", json={"statuses": ["running"]})

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Only completed and failed jobs can be pruned. Received unsupported statuses: running."
    )


def test_job_list_endpoint_returns_recent_jobs_and_filters_status(tmp_path) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store

    base_time = datetime(2026, 4, 13, 12, 0, tzinfo=UTC)
    completed_record = store.create_job(
        JobRecord(base_url="https://completed.example", attack_count=1).model_copy(
            update={
                "status": ApiJobStatus.completed,
                "created_at": base_time,
                "started_at": base_time,
                "completed_at": base_time + timedelta(seconds=1),
            }
        )
    )
    store.write_result(
        completed_record.id,
        _flagged_results().model_copy(update={"base_url": "https://completed.example"}),
    )

    failed_record = store.create_job(
        JobRecord(base_url="https://failed.example", attack_count=2).model_copy(
            update={
                "status": ApiJobStatus.failed,
                "created_at": base_time + timedelta(minutes=5),
                "started_at": base_time + timedelta(minutes=5),
                "completed_at": base_time + timedelta(minutes=5, seconds=1),
                "error": "boom",
            }
        )
    )

    response = client.get("/v1/jobs")

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 2
    assert [job["id"] for job in payload["jobs"]] == [failed_record.id, completed_record.id]
    assert payload["jobs"][0]["result_summary"] is None
    assert payload["jobs"][1]["result_summary"]["active_flagged_count"] == 1
    assert payload["jobs"][1]["result_summary"]["top_findings"][0]["attack_id"] == "atk_api"

    filtered_response = client.get("/v1/jobs", params=[("status", "completed"), ("limit", "1")])

    assert filtered_response.status_code == 200
    filtered_payload = filtered_response.json()
    assert filtered_payload["count"] == 1
    assert [job["id"] for job in filtered_payload["jobs"]] == [completed_record.id]


def test_project_review_endpoint_uses_latest_completed_run_and_selected_baseline(tmp_path) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store
    project_id = client.post("/v1/projects", json={"name": "Review demo"}).json()["id"]

    baseline_job = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=datetime(2026, 4, 13, 11, 0, tzinfo=UTC),
        completed_at=datetime(2026, 4, 13, 11, 1, tzinfo=UTC),
        project_id=project_id,
    )
    current_job = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=datetime(2026, 4, 13, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 4, 13, 12, 1, tzinfo=UTC),
        project_id=project_id,
    )
    store.write_result(
        baseline_job.id,
        _baseline_results().model_copy(update={"base_url": "https://example.com"}),
    )
    store.write_result(
        current_job.id,
        _flagged_results().model_copy(update={"base_url": "https://example.com"}),
    )

    response = client.post(
        f"/v1/projects/{project_id}/review",
        json={"baseline_mode": "job", "baseline_job_id": baseline_job.id},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["project_id"] == project_id
    assert payload["current_job_id"] == current_job.id
    assert payload["baseline_job_id"] == baseline_job.id
    assert payload["baseline_mode"] == "job"
    assert payload["baseline_used"] is True
    assert payload["waiting_for_new_run"] is False
    assert payload["summary"]["baseline_used"] is True
    assert payload["verification"]["baseline_used"] is True
    assert payload["verification"]["persisting_findings_count"] == 1
    assert payload["verification"]["persisting_findings"][0]["delta_changes"][0]["field"] == (
        "severity"
    )


def test_project_review_endpoint_rejects_invalid_baseline_jobs(tmp_path) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store
    project_id = client.post("/v1/projects", json={"name": "Review demo"}).json()["id"]
    other_project_id = client.post("/v1/projects", json={"name": "Other"}).json()["id"]

    current_job = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=datetime(2026, 4, 13, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 4, 13, 12, 1, tzinfo=UTC),
        project_id=project_id,
    )
    store.write_result(current_job.id, _flagged_results())

    other_project_job = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=datetime(2026, 4, 13, 11, 0, tzinfo=UTC),
        completed_at=datetime(2026, 4, 13, 11, 1, tzinfo=UTC),
        project_id=other_project_id,
        with_result=True,
    )
    no_result_job = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=datetime(2026, 4, 13, 10, 0, tzinfo=UTC),
        completed_at=datetime(2026, 4, 13, 10, 1, tzinfo=UTC),
        project_id=project_id,
    )

    missing_response = client.post(
        f"/v1/projects/{project_id}/review",
        json={"baseline_mode": "job", "baseline_job_id": "missing"},
    )
    assert missing_response.status_code == 404
    assert missing_response.json()["detail"] == "Baseline job not found."

    cross_project_response = client.post(
        f"/v1/projects/{project_id}/review",
        json={"baseline_mode": "job", "baseline_job_id": other_project_job.id},
    )
    assert cross_project_response.status_code == 400
    assert cross_project_response.json()["detail"] == (
        "Baseline job must belong to the same project."
    )

    no_result_response = client.post(
        f"/v1/projects/{project_id}/review",
        json={"baseline_mode": "job", "baseline_job_id": no_result_job.id},
    )
    assert no_result_response.status_code == 400
    assert no_result_response.json()["detail"] == (
        "Baseline job must be completed and have stored results."
    )


def test_project_review_endpoint_rejects_invalid_external_baseline_json(tmp_path) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store
    project_id = client.post("/v1/projects", json={"name": "Review demo"}).json()["id"]

    current_job = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=datetime(2026, 4, 13, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 4, 13, 12, 1, tzinfo=UTC),
        project_id=project_id,
        with_result=True,
    )

    assert current_job.project_id == project_id

    response = client.post(
        f"/v1/projects/{project_id}/review",
        json={"baseline_mode": "external", "baseline": {"unexpected": "shape"}},
    )

    assert response.status_code == 422


def test_project_review_endpoint_waits_when_latest_run_is_pinned_as_baseline(tmp_path) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store
    project_id = client.post("/v1/projects", json={"name": "Review demo"}).json()["id"]

    current_job = _stored_job(
        store,
        status=ApiJobStatus.completed,
        created_at=datetime(2026, 4, 13, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 4, 13, 12, 1, tzinfo=UTC),
        project_id=project_id,
        with_result=True,
    )

    response = client.post(
        f"/v1/projects/{project_id}/review",
        json={"baseline_mode": "job", "baseline_job_id": current_job.id},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["current_job_id"] == current_job.id
    assert payload["baseline_job_id"] == current_job.id
    assert payload["baseline_used"] is False
    assert payload["waiting_for_new_run"] is True


def test_project_update_persists_review_baseline_selection(tmp_path) -> None:
    client = TestClient(create_app(data_dir=tmp_path))
    project_id = client.post("/v1/projects", json={"name": "Review demo"}).json()["id"]

    response = client.patch(
        f"/v1/projects/{project_id}",
        json={
            "review_draft": {
                "baseline_mode": "job",
                "baseline_job_id": "job-baseline",
                "baseline": None,
                "suppressions_yaml": None,
                "min_severity": "medium",
                "min_confidence": "low",
            }
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["review_draft"]["baseline_mode"] == "job"
    assert payload["review_draft"]["baseline_job_id"] == "job-baseline"
    assert payload["review_draft"]["min_severity"] == "medium"
    assert payload["review_draft"]["min_confidence"] == "low"


def test_job_store_lists_nested_artifacts_and_rejects_path_traversal(tmp_path) -> None:
    store = JobStore(tmp_path)
    record = store.create_job(JobRecord(base_url="https://example.com", attack_count=1))
    artifact_path = store.artifact_dir(record.id) / "profiles" / "atk_api.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text('{"attack":{"id":"atk_api"}}', encoding="utf-8")

    assert store.list_artifacts(record.id) == ["profiles/atk_api.json"]
    assert store.artifact_list_response(record.id).artifacts == ["profiles/atk_api.json"]
    assert (
        store.artifact_path_for_name(record.id, "profiles/atk_api.json") == artifact_path.resolve()
    )

    with pytest.raises(FileNotFoundError):
        store.artifact_path_for_name(record.id, "../job.json")

    with pytest.raises(FileNotFoundError):
        store.artifact_path_for_name(record.id, "missing.json")


def test_job_store_delete_rejects_path_traversal(tmp_path) -> None:
    store = JobStore(tmp_path)

    with pytest.raises(FileNotFoundError):
        store.delete_job("../job.json")


def test_discover_endpoint_supports_inline_inputs(tmp_path, monkeypatch) -> None:
    discovered = {}

    def _fake_discover(inputs):
        discovered["names"] = [current.name for current in inputs]
        discovered["contents"] = [current.content for current in inputs]
        return LearnedModel(source_inputs=discovered["names"])

    monkeypatch.setattr("knives_out.api.discover_model_inline", _fake_discover)
    client = TestClient(create_app(data_dir=tmp_path))

    response = client.post(
        "/v1/discover",
        json={
            "inputs": [{"name": "capture.ndjson", "content": '{"artifact_type":"capture-event"}'}]
        },
    )

    assert response.status_code == 200
    assert discovered["names"] == ["capture.ndjson"]
    assert discovered["contents"] == ['{"artifact_type":"capture-event"}']
    assert response.json()["learned_model"]["source_inputs"] == ["capture.ndjson"]


def test_job_store_retries_transient_empty_job_records(tmp_path) -> None:
    store = JobStore(tmp_path)
    record = JobRecord(base_url="https://example.com", attack_count=1)
    store.job_dir(record.id).mkdir(parents=True, exist_ok=True)
    store.record_path(record.id).write_text("", encoding="utf-8")

    def _repair_record() -> None:
        # Give the loader enough time to exercise the retry path on slower CI workers.
        time.sleep(0.06)
        store.update_job(record)

    repair_thread = threading.Thread(target=_repair_record)
    repair_thread.start()
    loaded = store.load_job(record.id)
    repair_thread.join()

    assert loaded.id == record.id
    assert loaded.base_url == "https://example.com"


def test_report_verify_promote_and_triage_endpoints(tmp_path) -> None:
    client = TestClient(create_app(data_dir=tmp_path))
    results = _flagged_results()
    suite = _attack_suite()

    export_response = client.post(
        "/v1/export",
        json={
            "results": results.model_dump(mode="json"),
            "format": "sarif",
        },
    )
    assert export_response.status_code == 200
    export_payload = export_response.json()
    assert export_payload["format"] == "sarif"
    assert export_payload["content"]["version"] == "2.1.0"
    assert export_payload["content"]["runs"][0]["results"][0]["ruleId"] == "knives-out/server_error"

    summary_response = client.post(
        "/v1/summary",
        json={"results": results.model_dump(mode="json"), "top_limit": 5},
    )
    assert summary_response.status_code == 200
    assert summary_response.json()["active_flagged_count"] == 1
    assert summary_response.json()["top_findings"][0]["attack_id"] == "atk_api"

    verify_response = client.post(
        "/v1/verify",
        json={"results": results.model_dump(mode="json")},
    )
    assert verify_response.status_code == 200
    assert verify_response.json()["passed"] is False
    assert verify_response.json()["current_findings_count"] == 1

    report_response = client.post(
        "/v1/report",
        json={
            "results": results.model_dump(mode="json"),
            "format": "markdown",
        },
    )
    assert report_response.status_code == 200
    assert "Server failure" in report_response.json()["content"]

    triage_response = client.post(
        "/v1/triage",
        json={"results": results.model_dump(mode="json")},
    )
    assert triage_response.status_code == 200
    assert triage_response.json()["added_count"] == 1
    assert triage_response.json()["suppressions"]["suppressions"][0]["attack_id"] == "atk_api"

    promote_response = client.post(
        "/v1/promote",
        json={
            "results": results.model_dump(mode="json"),
            "attacks": suite.model_dump(mode="json"),
        },
    )
    assert promote_response.status_code == 200
    assert promote_response.json()["promoted_attack_ids"] == ["atk_api"]


def test_verify_endpoint_reports_delta_changes_and_report_supports_html(tmp_path) -> None:
    client = TestClient(create_app(data_dir=tmp_path))
    current = _flagged_results()
    baseline = _baseline_results()

    verify_response = client.post(
        "/v1/verify",
        json={
            "results": current.model_dump(mode="json"),
            "baseline": baseline.model_dump(mode="json"),
            "min_severity": "medium",
            "min_confidence": "medium",
        },
    )

    assert verify_response.status_code == 200
    verify_payload = verify_response.json()
    assert verify_payload["baseline_used"] is True
    assert verify_payload["persisting_findings_count"] == 1
    assert verify_payload["persisting_findings"][0]["protocol"] == "rest"
    assert [
        change["field"] for change in verify_payload["persisting_findings"][0]["delta_changes"]
    ] == [
        "severity",
        "confidence",
        "status",
    ]

    report_response = client.post(
        "/v1/report",
        json={
            "results": current.model_dump(mode="json"),
            "baseline": baseline.model_dump(mode="json"),
            "format": "html",
        },
    )

    assert report_response.status_code == 200
    report_payload = report_response.json()
    assert report_payload["format"] == "html"
    assert "<!DOCTYPE html>" in report_payload["content"]


def test_export_endpoint_reports_baseline_changes_and_applies_suppressions(tmp_path) -> None:
    client = TestClient(create_app(data_dir=tmp_path))
    current = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_api",
                operation_id="getSecret",
                kind="missing_auth",
                name="Server failure",
                method="GET",
                path="/secrets",
                url="https://example.com/secrets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="medium",
            ),
            AttackResult(
                attack_id="atk_suppressed",
                operation_id="listPets",
                kind="wrong_type_param",
                name="Suppressed failure",
                method="GET",
                path="/pets",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            ),
        ],
    )
    baseline = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_api",
                operation_id="getSecret",
                kind="missing_auth",
                name="Server failure",
                method="GET",
                path="/secrets",
                url="https://example.com/secrets",
                status_code=401,
                flagged=True,
                issue="server_error",
                severity="medium",
                confidence="high",
            )
        ],
    )

    export_response = client.post(
        "/v1/export",
        json={
            "results": current.model_dump(mode="json"),
            "baseline": baseline.model_dump(mode="json"),
            "format": "sarif",
            "suppressions_yaml": (
                "suppressions:\n"
                "  - attack_id: atk_suppressed\n"
                "    reason: Known issue\n"
                "    owner: api-team\n"
            ),
        },
    )

    assert export_response.status_code == 200
    export_payload = export_response.json()
    sarif_results = export_payload["content"]["runs"][0]["results"]
    assert len(sarif_results) == 1
    assert sarif_results[0]["properties"]["attack_id"] == "atk_api"
    assert sarif_results[0]["properties"]["change"] == "persisting"
    assert {change["field"] for change in sarif_results[0]["properties"]["delta_changes"]} == {
        "confidence",
        "severity",
        "status",
    }
