from __future__ import annotations

import threading
import time
from textwrap import dedent

import httpx
from fastapi.testclient import TestClient

from knives_out.api import create_app
from knives_out.api_models import JobRecord
from knives_out.api_store import JobStore
from knives_out.models import AttackCase, AttackResult, AttackResults, AttackSuite

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

    response = client.get("/v1/jobs/missing/artifacts")
    assert response.status_code == 404


def test_job_store_retries_transient_empty_job_records(tmp_path) -> None:
    store = JobStore(tmp_path)
    record = JobRecord(base_url="https://example.com", attack_count=1)
    store.job_dir(record.id).mkdir(parents=True, exist_ok=True)
    store.record_path(record.id).write_text("", encoding="utf-8")

    def _repair_record() -> None:
        time.sleep(0.01)
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
