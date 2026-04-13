from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from textwrap import dedent

import httpx
import pytest
from fastapi.testclient import TestClient

from knives_out.api import create_app
from knives_out.api_models import ApiJobStatus, JobRecord
from knives_out.api_store import JobStore
from knives_out.models import AttackCase, AttackResult, AttackResults, AttackSuite, LearnedModel

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


def test_create_app_uses_env_data_dir_and_healthz_endpoint(tmp_path, monkeypatch) -> None:
    configured = tmp_path / "api-data"
    monkeypatch.setenv("KNIVES_OUT_API_DATA_DIR", str(configured))
    app = create_app()
    client = TestClient(app)

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert app.state.job_store.root == configured


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


def test_job_list_endpoint_returns_recent_jobs_and_filters_status(tmp_path) -> None:
    app = create_app(data_dir=tmp_path)
    client = TestClient(app)
    store = app.state.job_store

    base_time = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
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
