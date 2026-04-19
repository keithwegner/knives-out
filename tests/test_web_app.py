from __future__ import annotations

import base64
import json
import time
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import httpx
from fastapi.testclient import TestClient

from knives_out.api import create_app
from knives_out.models import AttackCase, AttackResult, AttackResults, AttackSuite
from knives_out.review_bundles import render_review_bundle


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


def _bundle_results(*, base_url: str = "https://example.com") -> AttackResults:
    return AttackResults(
        source="bundle-test",
        base_url=base_url,
        executed_at="2026-04-15T04:00:00Z",
        results=[
            AttackResult(
                attack_id="atk_api",
                operation_id="getSecret",
                kind="missing_auth",
                name="Missing auth",
                protocol="openapi",
                method="GET",
                path="/secrets",
                url=f"{base_url}/secrets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ],
    )


def _zip_bytes(entries: dict[str, bytes | str]) -> bytes:
    raw = BytesIO()
    with ZipFile(raw, "w", compression=ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return raw.getvalue()


def test_project_crud_endpoints_and_project_summaries(tmp_path) -> None:
    client = TestClient(create_app(data_dir=tmp_path))

    create_response = client.post("/v1/projects", json={"name": "Workbench demo"})

    assert create_response.status_code == 200
    created_project = create_response.json()
    assert created_project["source_mode"] == "openapi"
    assert created_project["source"]["name"] == "openapi.yaml"

    project_id = created_project["id"]

    list_response = client.get("/v1/projects")
    assert list_response.status_code == 200
    assert list_response.json()["projects"] == [
        {
            "id": project_id,
            "name": "Workbench demo",
            "source_mode": "openapi",
            "active_step": "source",
            "created_at": created_project["created_at"],
            "updated_at": created_project["updated_at"],
            "source_name": "openapi.yaml",
            "job_count": 0,
            "last_run_job_id": None,
            "last_run_status": None,
            "last_run_at": None,
            "active_flagged_count": None,
        }
    ]

    patch_response = client.patch(
        f"/v1/projects/{project_id}",
        json={
            "name": "GraphQL workbench",
            "source_mode": "graphql",
            "source": {
                "name": "schema.graphql",
                "content": "type Query { ping: String! }",
            },
            "active_step": "generate",
            "review_draft": {
                "baseline_job_id": "job-baseline",
            },
        },
    )

    assert patch_response.status_code == 200
    patched_project = patch_response.json()
    assert patched_project["name"] == "GraphQL workbench"
    assert patched_project["source_mode"] == "graphql"
    assert patched_project["active_step"] == "generate"
    assert patched_project["source"]["name"] == "schema.graphql"
    assert patched_project["review_draft"]["baseline_job_id"] == "job-baseline"

    get_response = client.get(f"/v1/projects/{project_id}")
    assert get_response.status_code == 200
    assert get_response.json()["name"] == "GraphQL workbench"
    assert get_response.json()["review_draft"]["baseline_job_id"] == "job-baseline"

    jobs_response = client.get(f"/v1/projects/{project_id}/jobs")
    assert jobs_response.status_code == 200
    assert jobs_response.json() == {"project_id": project_id, "jobs": []}

    delete_response = client.delete(f"/v1/projects/{project_id}")
    assert delete_response.status_code == 200
    assert delete_response.json() == {"deleted": True}
    assert client.get(f"/v1/projects/{project_id}").status_code == 404


def test_duplicate_project_endpoint_clones_snapshot_without_job_links(tmp_path) -> None:
    client = TestClient(create_app(data_dir=tmp_path))

    create_response = client.post(
        "/v1/projects",
        json={
            "name": "Workbench demo",
            "source_mode": "graphql",
            "active_step": "review",
            "source": {
                "name": "schema.graphql",
                "content": "type Query { ping: String! }",
            },
            "generate_draft": {
                "kind": ["missing_auth"],
            },
            "run_draft": {
                "base_url": "https://example.com",
                "headers": {"Authorization": "Bearer token"},
            },
            "review_draft": {
                "baseline_job_id": "job-baseline",
                "baseline": {
                    "source": "unit",
                    "base_url": "https://baseline.example.com",
                    "executed_at": "2026-04-13T20:06:00Z",
                    "profiles": [],
                    "auth_events": [],
                    "results": [],
                },
            },
            "artifacts": {
                "latest_markdown_report": "# report",
                "latest_results": {
                    "source": "unit",
                    "base_url": "https://example.com",
                    "executed_at": "2026-04-13T20:06:00Z",
                    "profiles": [],
                    "auth_events": [],
                    "results": [],
                },
                "last_run_job_id": "job-current",
            },
        },
    )

    assert create_response.status_code == 200
    original = create_response.json()

    duplicate_response = client.post(f"/v1/projects/{original['id']}/duplicate")

    assert duplicate_response.status_code == 200
    duplicate = duplicate_response.json()
    assert duplicate["id"] != original["id"]
    assert duplicate["name"] == "Workbench demo copy"
    assert duplicate["created_at"] != original["created_at"]
    assert duplicate["updated_at"] != original["updated_at"]
    assert duplicate["source"] == original["source"]
    assert duplicate["generate_draft"] == original["generate_draft"]
    assert duplicate["run_draft"] == original["run_draft"]
    assert duplicate["review_draft"]["baseline_job_id"] is None
    assert duplicate["review_draft"]["baseline"] == original["review_draft"]["baseline"]
    assert duplicate["artifacts"]["last_run_job_id"] is None
    assert duplicate["artifacts"]["latest_markdown_report"] == "# report"
    assert duplicate["artifacts"]["latest_results"] == original["artifacts"]["latest_results"]

    second_duplicate_response = client.post(f"/v1/projects/{original['id']}/duplicate")

    assert second_duplicate_response.status_code == 200
    assert second_duplicate_response.json()["name"] == "Workbench demo copy 2"


def test_import_review_bundle_creates_review_only_project_and_completed_import_job(
    tmp_path,
) -> None:
    client = TestClient(create_app(data_dir=tmp_path))
    current_results = _bundle_results()
    baseline_results = _bundle_results(base_url="https://baseline.example.com")
    artifact_dir = tmp_path / "bundle-artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "atk_api.json").write_text('{"request":"demo"}', encoding="utf-8")
    bundle = render_review_bundle(
        current_results,
        name="Imported bundle review",
        baseline=baseline_results,
        suppressions_yaml=(
            "suppressions:\n  - attack_id: atk_api\n    reason: accepted\n    owner: api-team\n"
        ),
        artifact_dir=artifact_dir,
        min_severity="medium",
        min_confidence="low",
    )

    import_response = client.post(
        "/v1/projects/import-review-bundle",
        files={"bundle": ("review-bundle.zip", bundle, "application/zip")},
    )

    assert import_response.status_code == 200
    project = import_response.json()
    assert project["name"] == "Imported bundle review"
    assert project["source_mode"] == "review_bundle"
    assert project["active_step"] == "review"
    assert project["review_draft"]["baseline_mode"] == "external"
    assert project["review_draft"]["min_severity"] == "medium"
    assert project["review_draft"]["min_confidence"] == "low"
    assert "attack_id: atk_api" in project["review_draft"]["suppressions_yaml"]
    assert project["artifacts"]["last_run_job_id"] is not None
    assert project["artifacts"]["latest_results"]["base_url"] == "https://example.com"
    assert project["artifacts"]["latest_summary"]["baseline_used"] is True
    assert project["artifacts"]["latest_summary"]["total_results"] == 1

    jobs_response = client.get(f"/v1/projects/{project['id']}/jobs")
    assert jobs_response.status_code == 200
    jobs = jobs_response.json()["jobs"]
    assert len(jobs) == 1
    assert jobs[0]["kind"] == "import"
    assert jobs[0]["status"] == "completed"
    assert jobs[0]["attack_count"] == 1
    assert jobs[0]["artifact_names"] == ["atk_api.json"]

    artifact_response = client.get(f"/v1/jobs/{jobs[0]['id']}/artifacts/atk_api.json")
    assert artifact_response.status_code == 200
    assert artifact_response.text == '{"request":"demo"}'


def test_import_review_bundle_rejects_invalid_archives(tmp_path) -> None:
    client = TestClient(create_app(data_dir=tmp_path))
    manifest = {
        "bundle_kind": "review",
        "bundle_version": 1,
        "name": "Broken import",
        "created_at": "2026-04-15T04:00:00Z",
        "base_url": "https://example.com",
        "executed_at": "2026-04-15T04:00:00Z",
        "result_count": 1,
        "includes_baseline": False,
        "includes_suppressions": False,
        "includes_artifacts": False,
        "min_severity": "high",
        "min_confidence": "medium",
    }
    current_results = _bundle_results().model_dump_json(indent=2, exclude_none=True)

    cases = [
        (b"not-a-zip", "zip archive"),
        (_zip_bytes({"current/results.json": current_results}), "manifest.json"),
        (_zip_bytes({"manifest.json": '{"bundle_kind":"review","bundle_version":2}'}), "invalid"),
        (_zip_bytes({"manifest.json": json.dumps(manifest)}), "current/results.json"),
        (
            _zip_bytes(
                {
                    "manifest.json": json.dumps(manifest),
                    "current/results.json": current_results,
                    "../escape.txt": "boom",
                }
            ),
            "unsafe path",
        ),
    ]

    for raw_bundle, expected_detail in cases:
        response = client.post(
            "/v1/projects/import-review-bundle",
            files={"bundle": ("review-bundle.zip", raw_bundle, "application/zip")},
        )

        assert response.status_code == 400
        assert expected_detail in response.json()["detail"]


def test_run_jobs_are_attached_to_projects_and_removed_on_project_delete(
    tmp_path,
    monkeypatch,
) -> None:
    _install_stub_response(monkeypatch, httpx.Response(422, text="missing auth"))
    client = TestClient(create_app(data_dir=tmp_path))
    create_response = client.post("/v1/projects", json={"name": "Run demo"})
    project_id = create_response.json()["id"]

    run_response = client.post(
        "/v1/runs",
        json={
            "project_id": project_id,
            "suite": _attack_suite().model_dump(mode="json"),
            "base_url": "https://example.com",
            "store_artifacts": False,
        },
    )

    assert run_response.status_code == 200
    job_id = run_response.json()["id"]
    assert run_response.json()["project_id"] == project_id

    jobs_payload = None
    for _ in range(50):
        jobs_response = client.get(f"/v1/projects/{project_id}/jobs")
        assert jobs_response.status_code == 200
        jobs_payload = jobs_response.json()
        if jobs_payload["jobs"] and jobs_payload["jobs"][0]["status"] == "completed":
            break
        time.sleep(0.02)

    assert jobs_payload is not None
    assert jobs_payload["jobs"][0]["id"] == job_id
    assert jobs_payload["jobs"][0]["project_id"] == project_id
    assert jobs_payload["jobs"][0]["completed_at"] is not None
    assert jobs_payload["jobs"][0]["result_available"] is True
    assert jobs_payload["jobs"][0]["result_summary"]["total_results"] == 1
    assert client.get(f"/v1/jobs/{job_id}").json()["project_id"] == project_id

    delete_response = client.delete(f"/v1/projects/{project_id}")
    assert delete_response.status_code == 200
    assert client.get(f"/v1/jobs/{job_id}").status_code == 404


def test_project_review_artifact_evidence_endpoint_supports_current_run_drilldown(
    tmp_path,
    monkeypatch,
) -> None:
    _install_stub_response(monkeypatch, httpx.Response(422, text="missing auth"))
    client = TestClient(create_app(data_dir=tmp_path))
    project_id = client.post("/v1/projects", json={"name": "Review demo"}).json()["id"]

    run_response = client.post(
        "/v1/runs",
        json={
            "project_id": project_id,
            "suite": _attack_suite().model_dump(mode="json"),
            "base_url": "https://example.com",
            "store_artifacts": True,
        },
    )
    assert run_response.status_code == 200

    job_id = run_response.json()["id"]
    for _ in range(50):
        job_response = client.get(f"/v1/jobs/{job_id}")
        assert job_response.status_code == 200
        if job_response.json()["status"] == "completed":
            break
        time.sleep(0.02)

    review_response = client.post(f"/v1/projects/{project_id}/review", json={})
    assert review_response.status_code == 200
    assert review_response.json()["current_job_id"] == job_id

    evidence_response = client.get(f"/v1/jobs/{job_id}/findings/atk_api/evidence")
    assert evidence_response.status_code == 200
    payload = evidence_response.json()
    assert payload["job_id"] == job_id
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


def test_frontend_routes_serve_index_assets_and_spa_fallback(tmp_path) -> None:
    frontend_dir = tmp_path / "frontend-dist"
    asset_dir = frontend_dir / "assets"
    asset_dir.mkdir(parents=True)
    (frontend_dir / "index.html").write_text(
        "<!doctype html><div>Workbench</div>", encoding="utf-8"
    )
    (asset_dir / "main.js").write_text("console.log('ready')", encoding="utf-8")

    client = TestClient(create_app(data_dir=tmp_path / "api-data", frontend_dir=frontend_dir))

    root_response = client.get("/", follow_redirects=False)
    assert root_response.status_code == 307
    assert root_response.headers["location"] == "/app/"

    index_response = client.get("/app")
    assert index_response.status_code == 200
    assert "Workbench" in index_response.text

    slash_index_response = client.get("/app/")
    assert slash_index_response.status_code == 200
    assert "Workbench" in slash_index_response.text

    asset_response = client.get("/app/assets/main.js")
    assert asset_response.status_code == 200
    assert "ready" in asset_response.text

    fallback_response = client.get("/app/projects/demo")
    assert fallback_response.status_code == 200
    assert "Workbench" in fallback_response.text

    missing_asset_response = client.get("/app/assets/missing.js")
    assert missing_asset_response.status_code == 404


def test_create_app_applies_configured_cors_origins(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("KNIVES_OUT_CORS_ALLOW_ORIGINS", "https://keithwegner.github.io")
    client = TestClient(create_app(data_dir=tmp_path))

    response = client.options(
        "/healthz",
        headers={
            "Origin": "https://keithwegner.github.io",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://keithwegner.github.io"


def test_basic_auth_protects_app_api_and_docs_but_not_healthcheck(tmp_path, monkeypatch) -> None:
    frontend_dir = tmp_path / "frontend-dist"
    asset_dir = frontend_dir / "assets"
    asset_dir.mkdir(parents=True)
    (frontend_dir / "index.html").write_text(
        "<!doctype html><div>Workbench</div>", encoding="utf-8"
    )
    (asset_dir / "main.js").write_text("console.log('ready')", encoding="utf-8")

    monkeypatch.setenv("KNIVES_OUT_BASIC_AUTH_USERNAME", "demo")
    monkeypatch.setenv("KNIVES_OUT_BASIC_AUTH_PASSWORD", "s3cret")
    client = TestClient(create_app(data_dir=tmp_path / "api-data", frontend_dir=frontend_dir))
    valid_header = {"Authorization": "Basic " + base64.b64encode(b"demo:s3cret").decode("ascii")}
    invalid_header = {"Authorization": "Basic " + base64.b64encode(b"demo:wrong").decode("ascii")}

    health_response = client.get("/healthz")
    assert health_response.status_code == 200

    root_response = client.get("/", follow_redirects=False)
    assert root_response.status_code == 401
    assert root_response.headers["www-authenticate"] == 'Basic realm="knives-out"'

    app_response = client.get("/app/")
    assert app_response.status_code == 401

    api_response = client.get("/v1/projects")
    assert api_response.status_code == 401

    docs_response = client.get("/docs")
    assert docs_response.status_code == 401

    schema_response = client.get("/openapi.json")
    assert schema_response.status_code == 401

    invalid_response = client.get("/v1/projects", headers=invalid_header)
    assert invalid_response.status_code == 401
    assert invalid_response.headers["www-authenticate"] == 'Basic realm="knives-out"'

    authorized_root = client.get("/", headers=valid_header, follow_redirects=False)
    assert authorized_root.status_code == 307
    assert authorized_root.headers["location"] == "/app/"

    authorized_app = client.get("/app/", headers=valid_header)
    assert authorized_app.status_code == 200
    assert "Workbench" in authorized_app.text

    authorized_api = client.get("/v1/projects", headers=valid_header)
    assert authorized_api.status_code == 200
    assert authorized_api.json() == {"projects": []}

    authorized_docs = client.get("/docs", headers=valid_header)
    assert authorized_docs.status_code == 200
    assert "Swagger UI" in authorized_docs.text

    authorized_schema = client.get("/openapi.json", headers=valid_header)
    assert authorized_schema.status_code == 200
    assert authorized_schema.json()["info"]["title"] == "knives-out API"


def test_basic_auth_allows_unauthenticated_options_requests(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("KNIVES_OUT_BASIC_AUTH_USERNAME", "demo")
    monkeypatch.setenv("KNIVES_OUT_BASIC_AUTH_PASSWORD", "s3cret")
    monkeypatch.setenv("KNIVES_OUT_CORS_ALLOW_ORIGINS", "https://example.com")
    client = TestClient(create_app(data_dir=tmp_path))

    response = client.options(
        "/v1/projects",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://example.com"
