from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from textwrap import dedent
from urllib.parse import urlparse

import httpx
import pytest
import uvicorn

from knives_out.api import create_app

OPENAPI_SOURCE = {
    "name": "live-fixture-openapi.yaml",
    "content": dedent(
        """
        openapi: 3.0.3
        info:
          title: Live Fixture API
          version: "1.0"
        paths:
          /widgets:
            get:
              operationId: listWidgets
              security:
                - bearerAuth: []
              responses:
                "200":
                  description: ok
                  content:
                    application/json:
                      schema:
                        type: object
                        required: [items]
                        properties:
                          items:
                            type: array
                            items:
                              type: object
                              required: [id]
                              properties:
                                id:
                                  type: string
        components:
          securitySchemes:
            bearerAuth:
              type: http
              scheme: bearer
        """
    ).strip(),
}


@dataclass(frozen=True)
class _CompletedRun:
    project_id: str
    job_id: str
    suite: dict[str, object]
    results: dict[str, object]
    artifacts: list[str]


class _BaseHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return


class _PermissiveWidgetsHandler(_BaseHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/widgets":
            _write_json_response(self, 200, {"items": [{"id": "widget-1"}]})
            return
        _write_json_response(self, 404, {"detail": "not found"})


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _write_json_response(
    handler: BaseHTTPRequestHandler,
    status_code: int,
    payload: object,
) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status_code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _wait_for_port(port: int, *, timeout_seconds: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise AssertionError(f"Timed out waiting for port {port} to accept connections.")


def _wait_for_healthz(base_url: str, *, timeout_seconds: float = 8.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"{base_url}/healthz", timeout=0.5, trust_env=False)
            if response.status_code == 200 and response.json() == {"status": "ok"}:
                return
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            last_error = exc
        time.sleep(0.05)
    raise AssertionError(f"Timed out waiting for {base_url}/healthz.") from last_error


def _wait_for_job(
    client: httpx.Client,
    job_id: str,
    *,
    timeout_seconds: float = 10.0,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    last_payload: dict[str, object] | None = None
    while time.monotonic() < deadline:
        response = client.get(f"/v1/jobs/{job_id}")
        assert response.status_code == 200, response.text
        payload = response.json()
        last_payload = payload
        status = payload["status"]
        if status == "completed":
            return payload
        if status == "failed":
            raise AssertionError(f"Job {job_id} failed: {payload.get('error')}")
        time.sleep(0.1)
    raise AssertionError(f"Timed out waiting for job {job_id}: {last_payload}")


@contextmanager
def _serve_fixture_target() -> Iterator[str]:
    port = _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), _PermissiveWidgetsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _wait_for_port(port)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@contextmanager
def _serve_live_api(data_dir: Path, frontend_dir: Path) -> Iterator[str]:
    port = _free_port()
    app = create_app(data_dir=data_dir, frontend_dir=frontend_dir)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            lifespan="off",
            access_log=False,
            log_level="warning",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    _wait_for_healthz(base_url)
    try:
        yield base_url
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        if thread.is_alive():
            raise AssertionError(f"Timed out stopping live API server on port {port}.")


@pytest.fixture
def free_port() -> int:
    return _free_port()


@pytest.fixture
def fixture_frontend_dir(tmp_path: Path) -> Path:
    frontend_dir = tmp_path / "frontend-dist"
    assets_dir = frontend_dir / "assets"
    assets_dir.mkdir(parents=True)
    (frontend_dir / "index.html").write_text(
        "<!doctype html><html><body><main>Workbench</main></body></html>",
        encoding="utf-8",
    )
    (assets_dir / "main.js").write_text("console.log('workbench ready')", encoding="utf-8")
    return frontend_dir


@pytest.fixture
def target_api_url() -> Iterator[str]:
    with _serve_fixture_target() as base_url:
        yield base_url


@pytest.fixture
def live_api_server(
    fixture_frontend_dir: Path,
) -> Callable[[Path], AbstractContextManager[str]]:
    @contextmanager
    def start(data_dir: Path) -> Iterator[str]:
        with _serve_live_api(data_dir, fixture_frontend_dir) as base_url:
            yield base_url

    return start


@pytest.fixture(autouse=True)
def clear_auth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KNIVES_OUT_BASIC_AUTH_USERNAME", raising=False)
    monkeypatch.delenv("KNIVES_OUT_BASIC_AUTH_PASSWORD", raising=False)


def _client(base_url: str, *, auth: tuple[str, str] | None = None) -> httpx.Client:
    return httpx.Client(
        base_url=base_url,
        timeout=5.0,
        follow_redirects=False,
        trust_env=False,
        auth=auth,
    )


def _create_completed_project_run(client: httpx.Client, target_base_url: str) -> _CompletedRun:
    project_response = client.post(
        "/v1/projects",
        json={
            "name": "Live API integration",
            "source_mode": "openapi",
            "active_step": "run",
            "source": OPENAPI_SOURCE,
        },
    )
    assert project_response.status_code == 200, project_response.text
    project_id = project_response.json()["id"]

    generate_response = client.post(
        "/v1/generate",
        json={"source": OPENAPI_SOURCE, "kind": ["missing_auth"]},
    )
    assert generate_response.status_code == 200, generate_response.text
    suite = generate_response.json()["suite"]
    attacks = suite["attacks"]
    assert len(attacks) == 1
    assert attacks[0]["kind"] == "missing_auth"
    assert attacks[0]["method"] == "GET"
    assert attacks[0]["path"] == "/widgets"

    run_response = client.post(
        "/v1/runs",
        json={
            "project_id": project_id,
            "suite": suite,
            "base_url": target_base_url,
            "store_artifacts": True,
            "timeout": 5.0,
        },
    )
    assert run_response.status_code == 200, run_response.text
    job_id = run_response.json()["id"]
    completed_job = _wait_for_job(client, job_id)
    assert completed_job["result_available"] is True
    assert completed_job["artifact_names"]

    result_response = client.get(f"/v1/jobs/{job_id}/result")
    assert result_response.status_code == 200, result_response.text
    results = result_response.json()

    artifact_response = client.get(f"/v1/jobs/{job_id}/artifacts")
    assert artifact_response.status_code == 200, artifact_response.text
    artifacts = artifact_response.json()["artifacts"]
    assert artifacts == completed_job["artifact_names"]

    return _CompletedRun(
        project_id=project_id,
        job_id=job_id,
        suite=suite,
        results=results,
        artifacts=artifacts,
    )


def _assert_results_have_active_finding(results: dict[str, object]) -> dict[str, object]:
    findings = results["results"]
    assert isinstance(findings, list)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["flagged"] is True
    assert finding["issue"] == "unexpected_success"
    assert finding["severity"] == "high"
    assert finding["confidence"] == "medium"
    assert finding["method"] == "GET"
    assert finding["path"] == "/widgets"
    assert finding["status_code"] == 200
    return finding


def test_live_api_project_run_review_and_artifact_flow(
    tmp_path: Path,
    live_api_server: Callable[[Path], AbstractContextManager[str]],
    target_api_url: str,
) -> None:
    with live_api_server(tmp_path / "api-data") as api_url:
        with _client(api_url) as client:
            completed = _create_completed_project_run(client, target_api_url)
            finding = _assert_results_have_active_finding(completed.results)

            jobs_response = client.get("/v1/jobs")
            assert jobs_response.status_code == 200, jobs_response.text
            jobs = jobs_response.json()["jobs"]
            assert jobs[0]["id"] == completed.job_id
            assert jobs[0]["project_id"] == completed.project_id
            assert jobs[0]["result_available"] is True
            assert jobs[0]["artifact_names"] == completed.artifacts

            artifact_name = completed.artifacts[0]
            raw_artifact_response = client.get(
                f"/v1/jobs/{completed.job_id}/artifacts/{artifact_name}"
            )
            assert raw_artifact_response.status_code == 200, raw_artifact_response.text
            artifact = raw_artifact_response.json()
            assert artifact["attack"]["id"] == finding["attack_id"]
            assert artifact["request"]["method"] == "GET"
            assert artifact["request"]["url"] == f"{target_api_url}/widgets"
            assert artifact["response"]["status_code"] == 200
            assert "widget-1" in artifact["response"]["body_excerpt"]

            review_response = client.post(
                f"/v1/projects/{completed.project_id}/review",
                json={},
            )
            assert review_response.status_code == 200, review_response.text
            review = review_response.json()
            assert review["current_job_id"] == completed.job_id
            assert review["results"]["results"][0]["attack_id"] == finding["attack_id"]
            assert review["summary"]["active_flagged_count"] == 1
            assert review["summary"]["issue_counts"] == {"unexpected_success": 1}
            assert review["verification"]["passed"] is False
            assert (
                review["verification"]["failing_findings"][0]["attack_id"] == finding["attack_id"]
            )
            assert "Missing auth" in review["markdown_report"]
            assert "<html" in review["html_report"]
            assert "Missing auth" in review["html_report"]


def test_live_api_export_and_report_from_completed_job(
    tmp_path: Path,
    live_api_server: Callable[[Path], AbstractContextManager[str]],
    target_api_url: str,
) -> None:
    with live_api_server(tmp_path / "api-data") as api_url:
        with _client(api_url) as client:
            completed = _create_completed_project_run(client, target_api_url)
            finding = _assert_results_have_active_finding(completed.results)

            export_response = client.post(
                "/v1/export",
                json={"results": completed.results, "format": "sarif"},
            )
            assert export_response.status_code == 200, export_response.text
            export_payload = export_response.json()
            sarif = export_payload["content"]
            assert export_payload["format"] == "sarif"
            assert sarif["version"] == "2.1.0"
            assert sarif["runs"][0]["tool"]["driver"]["name"] == "knives-out"
            sarif_result = sarif["runs"][0]["results"][0]
            assert sarif_result["ruleId"] == "knives-out/unexpected_success"
            assert sarif_result["level"] == "error"
            assert "Missing auth" in sarif_result["message"]["text"]
            assert "locations" not in sarif_result
            assert sarif_result["properties"]["attack_id"] == finding["attack_id"]
            assert sarif_result["properties"]["protocol"] == "rest"
            assert sarif_result["properties"]["kind"] == "missing_auth"
            assert sarif_result["properties"]["path"] == "/widgets"
            assert sarif_result["properties"]["status_code"] == 200

            report_response = client.post(
                "/v1/report",
                json={"results": completed.results, "format": "markdown"},
            )
            assert report_response.status_code == 200, report_response.text
            report_payload = report_response.json()
            assert report_payload["format"] == "markdown"
            assert "Missing auth" in report_payload["content"]
            assert "unexpected_success" in report_payload["content"]
            assert "/widgets" in report_payload["content"]


def test_live_api_basic_auth_protects_app_api_and_docs(
    tmp_path: Path,
    live_api_server: Callable[[Path], AbstractContextManager[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KNIVES_OUT_BASIC_AUTH_USERNAME", "demo")
    monkeypatch.setenv("KNIVES_OUT_BASIC_AUTH_PASSWORD", "s3cret")

    with live_api_server(tmp_path / "api-data") as api_url:
        with _client(api_url) as anonymous_client:
            health_response = anonymous_client.get("/healthz")
            assert health_response.status_code == 200
            assert health_response.json() == {"status": "ok"}

            for path in ["/", "/app/", "/v1/projects", "/docs", "/openapi.json"]:
                response = anonymous_client.get(path)
                assert response.status_code == 401, f"{path}: {response.text}"
                assert response.headers["www-authenticate"] == 'Basic realm="knives-out"'

            invalid_response = anonymous_client.get(
                "/v1/projects",
                auth=("demo", "wrong"),
            )
            assert invalid_response.status_code == 401
            assert invalid_response.headers["www-authenticate"] == 'Basic realm="knives-out"'

        with _client(api_url, auth=("demo", "s3cret")) as authenticated_client:
            root_response = authenticated_client.get("/")
            assert root_response.status_code == 307
            assert root_response.headers["location"] == "/app/"

            app_response = authenticated_client.get("/app/")
            assert app_response.status_code == 200
            assert "Workbench" in app_response.text

            projects_response = authenticated_client.get("/v1/projects")
            assert projects_response.status_code == 200
            assert projects_response.json() == {"projects": []}

            docs_response = authenticated_client.get("/docs")
            assert docs_response.status_code == 200
            assert "Swagger UI" in docs_response.text

            schema_response = authenticated_client.get("/openapi.json")
            assert schema_response.status_code == 200
            assert schema_response.json()["info"]["title"] == "knives-out API"


def test_live_api_persists_projects_jobs_results_and_artifacts_across_restart(
    tmp_path: Path,
    live_api_server: Callable[[Path], AbstractContextManager[str]],
    target_api_url: str,
) -> None:
    data_dir = tmp_path / "api-data"

    with live_api_server(data_dir) as api_url:
        with _client(api_url) as client:
            completed = _create_completed_project_run(client, target_api_url)
            finding = _assert_results_have_active_finding(completed.results)

    with live_api_server(data_dir) as api_url:
        with _client(api_url) as client:
            projects_response = client.get("/v1/projects")
            assert projects_response.status_code == 200, projects_response.text
            projects = projects_response.json()["projects"]
            assert [project["id"] for project in projects] == [completed.project_id]
            assert projects[0]["job_count"] == 1
            assert projects[0]["last_run_job_id"] == completed.job_id
            assert projects[0]["last_run_status"] == "completed"

            job_response = client.get(f"/v1/jobs/{completed.job_id}")
            assert job_response.status_code == 200, job_response.text
            job = job_response.json()
            assert job["project_id"] == completed.project_id
            assert job["result_available"] is True
            assert job["artifact_names"] == completed.artifacts

            result_response = client.get(f"/v1/jobs/{completed.job_id}/result")
            assert result_response.status_code == 200, result_response.text
            persisted_results = result_response.json()
            assert persisted_results["results"][0]["attack_id"] == finding["attack_id"]
            _assert_results_have_active_finding(persisted_results)

            artifact_response = client.get(f"/v1/jobs/{completed.job_id}/artifacts")
            assert artifact_response.status_code == 200, artifact_response.text
            assert artifact_response.json()["artifacts"] == completed.artifacts

            raw_artifact_response = client.get(
                f"/v1/jobs/{completed.job_id}/artifacts/{completed.artifacts[0]}"
            )
            assert raw_artifact_response.status_code == 200, raw_artifact_response.text
            assert raw_artifact_response.json()["attack"]["id"] == finding["attack_id"]
