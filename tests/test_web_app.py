from __future__ import annotations

import time

import httpx
from fastapi.testclient import TestClient

from knives_out.api import create_app
from knives_out.models import AttackCase, AttackSuite


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
        },
    )

    assert patch_response.status_code == 200
    patched_project = patch_response.json()
    assert patched_project["name"] == "GraphQL workbench"
    assert patched_project["source_mode"] == "graphql"
    assert patched_project["active_step"] == "generate"
    assert patched_project["source"]["name"] == "schema.graphql"

    get_response = client.get(f"/v1/projects/{project_id}")
    assert get_response.status_code == 200
    assert get_response.json()["name"] == "GraphQL workbench"

    jobs_response = client.get(f"/v1/projects/{project_id}/jobs")
    assert jobs_response.status_code == 200
    assert jobs_response.json() == {"project_id": project_id, "jobs": []}

    delete_response = client.delete(f"/v1/projects/{project_id}")
    assert delete_response.status_code == 200
    assert delete_response.json() == {"deleted": True}
    assert client.get(f"/v1/projects/{project_id}").status_code == 404


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
    assert client.get(f"/v1/jobs/{job_id}").json()["project_id"] == project_id

    delete_response = client.delete(f"/v1/projects/{project_id}")
    assert delete_response.status_code == 200
    assert client.get(f"/v1/jobs/{job_id}").status_code == 404


def test_frontend_routes_serve_index_assets_and_spa_fallback(tmp_path) -> None:
    frontend_dir = tmp_path / "frontend-dist"
    asset_dir = frontend_dir / "assets"
    asset_dir.mkdir(parents=True)
    (frontend_dir / "index.html").write_text(
        "<!doctype html><div>Workbench</div>", encoding="utf-8"
    )
    (asset_dir / "main.js").write_text("console.log('ready')", encoding="utf-8")

    client = TestClient(create_app(data_dir=tmp_path / "api-data", frontend_dir=frontend_dir))

    index_response = client.get("/app")
    assert index_response.status_code == 200
    assert "Workbench" in index_response.text

    asset_response = client.get("/app/assets/main.js")
    assert asset_response.status_code == 200
    assert "ready" in asset_response.text

    fallback_response = client.get("/app/projects/demo")
    assert fallback_response.status_code == 200
    assert "Workbench" in fallback_response.text

    missing_asset_response = client.get("/app/assets/missing.js")
    assert missing_asset_response.status_code == 404
