from __future__ import annotations

import json
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from knives_out.api import create_app
from knives_out.capture import read_capture_events, serve_capture_proxy
from knives_out.cli import app
from knives_out.generator import generate_attack_suite
from knives_out.models import AttackCase, AttackResults, AttackSuite, LearnedModel
from knives_out.runner import execute_attack_suite
from knives_out.spec_loader import load_operations

ROOT = Path(__file__).resolve().parents[1]
STOREFRONT_SPEC = ROOT / "examples" / "openapi" / "storefront.yaml"
CLIENT_CREDENTIALS_CONFIG = ROOT / "examples" / "auth_configs" / "client-credentials.yml"
PROFILE_FILE = ROOT / "examples" / "auth_profiles" / "anonymous-user-admin.yml"
runner = CliRunner()

_FIXED_DRAFT_ID = "00000000-0000-4000-8000-000000000000"
_FIXED_EMAIL = "smoke@example.com"
_FIXED_SKU = "00000000-0000-4000-8000-000000000001"
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class _StatefulHTTPServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: type[BaseHTTPRequestHandler],
        *,
        state: dict[str, object] | None = None,
    ) -> None:
        super().__init__(server_address, request_handler_class)
        self.state: dict[str, object] = {} if state is None else state


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start_server(
    handler: type[BaseHTTPRequestHandler],
    *,
    state: dict[str, object] | None = None,
) -> tuple[_StatefulHTTPServer, threading.Thread]:
    server = _StatefulHTTPServer(("127.0.0.1", _free_port()), handler, state=state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _wait_for_port(port: int, *, timeout_seconds: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise AssertionError(f"Timed out waiting for port {port} to accept connections.")


def _shutdown_server(
    server: ThreadingHTTPServer,
    thread: threading.Thread,
    *,
    timeout_seconds: float = 5.0,
) -> None:
    server.shutdown()
    thread.join(timeout=timeout_seconds)


def _json_request(handler: BaseHTTPRequestHandler) -> object | None:
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0:
        return None
    body = handler.rfile.read(length).decode("utf-8")
    return json.loads(body)


def _write_json_response(
    handler: BaseHTTPRequestHandler,
    status_code: int,
    payload: object,
    *,
    headers: dict[str, str] | None = None,
) -> None:
    raw = json.dumps(payload).encode("utf-8")
    handler.send_response(status_code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    for name, value in (headers or {}).items():
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(raw)


def _write_empty_response(handler: BaseHTTPRequestHandler, status_code: int) -> None:
    handler.send_response(status_code)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


def _is_uuid(value: object) -> bool:
    return isinstance(value, str) and bool(_UUID_RE.fullmatch(value))


def _valid_draft_order_payload(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    if set(payload) != {"customerEmail", "note", "lineItems"}:
        return False

    customer_email = payload.get("customerEmail")
    note = payload.get("note")
    line_items = payload.get("lineItems")

    if not isinstance(customer_email, str) or "@" not in customer_email:
        return False
    if not isinstance(note, str) or not 5 <= len(note) <= 40:
        return False
    if not isinstance(line_items, list) or not 1 <= len(line_items) <= 3:
        return False

    for item in line_items:
        if not isinstance(item, dict):
            return False
        if set(item) != {"sku", "quantity"}:
            return False
        if not _is_uuid(item.get("sku")):
            return False
        quantity = item.get("quantity")
        if not isinstance(quantity, int) or not 1 <= quantity <= 5:
            return False
    return True


class _BaseHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return


class _PermissiveStorefrontHandler(_BaseHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.startswith("/draft-orders/"):
            draft_id = parsed.path.rsplit("/", 1)[-1]
            _write_json_response(
                self,
                200,
                {"draftId": draft_id, "customerEmail": _FIXED_EMAIL},
            )
            return
        _write_json_response(self, 404, {"detail": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/draft-orders":
            _json_request(self)
            _write_json_response(
                self,
                201,
                {"draftId": _FIXED_DRAFT_ID, "customerEmail": _FIXED_EMAIL},
            )
            return
        _write_json_response(self, 404, {"detail": "not found"})


class _ValidatingStorefrontHandler(_BaseHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == f"/draft-orders/{_FIXED_DRAFT_ID}":
            _write_json_response(
                self,
                200,
                {"draftId": _FIXED_DRAFT_ID, "customerEmail": _FIXED_EMAIL},
            )
            return
        _write_json_response(self, 404, {"detail": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/draft-orders":
            _write_json_response(self, 404, {"detail": "not found"})
            return

        payload = _json_request(self)
        if _valid_draft_order_payload(payload):
            _write_json_response(
                self,
                201,
                {"draftId": _FIXED_DRAFT_ID, "customerEmail": _FIXED_EMAIL},
            )
            return
        _write_json_response(self, 422, {"detail": "invalid payload"})


class _ProfileComparisonHandler(_BaseHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        authorization = self.headers.get("Authorization")
        query = parse_qs(parsed.query)

        if parsed.path == "/secret-records":
            if authorization is None:
                _write_json_response(self, 200, {"ok": True})
                return
            _write_json_response(self, 403, {"detail": "forbidden"})
            return

        if parsed.path == "/admin-reports":
            if authorization == "Bearer user-token":
                _write_json_response(self, 200, {"ok": True})
                return
            if authorization == "Bearer admin-token" and query.get("audit") == ["1"]:
                _write_json_response(self, 403, {"detail": "forbidden"})
                return
            _write_json_response(self, 401, {"detail": "unauthorized"})
            return

        _write_json_response(self, 404, {"detail": "not found"})


class _BuiltInAuthHandler(_BaseHandler):
    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        server = self.server
        if not isinstance(server, _StatefulHTTPServer):
            raise AssertionError("Expected stateful server.")

        if parsed.path == "/oauth/token":
            token_requests = int(server.state.get("token_requests", 0))
            server.state["token_requests"] = token_requests + 1
            token = "expired-token" if token_requests == 0 else "fresh-token"
            _write_json_response(self, 200, {"access_token": token, "expires_in": 3600})
            return

        if parsed.path == "/draft-orders":
            authorization = self.headers.get("Authorization")
            if authorization == "Bearer expired-token":
                _write_json_response(self, 401, {"detail": "expired"})
                return
            if authorization == "Bearer fresh-token":
                _write_json_response(self, 422, {"detail": "invalid payload"})
                return
            _write_json_response(self, 401, {"detail": "unauthorized"})
            return

        _write_json_response(self, 404, {"detail": "not found"})


class _ShadowTwinTargetHandler(_BaseHandler):
    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/draft-orders":
            _write_json_response(self, 404, {"detail": "not found"})
            return
        payload = _json_request(self)
        customer_email = _FIXED_EMAIL
        if isinstance(payload, dict) and isinstance(payload.get("customerEmail"), str):
            customer_email = payload["customerEmail"]
        _write_json_response(
            self,
            201,
            {"draftId": "ord_123", "customerEmail": customer_email},
        )

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/draft-orders/ord_123":
            _write_json_response(
                self,
                200,
                {"draftId": "ord_123", "customerEmail": _FIXED_EMAIL},
            )
            return
        _write_json_response(self, 404, {"detail": "not found"})

    def do_DELETE(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/draft-orders/ord_123":
            _write_empty_response(self, 204)
            return
        _write_json_response(self, 404, {"detail": "not found"})


def test_cli_happy_path_smoke_against_local_api(tmp_path: Path) -> None:
    server, thread = _start_server(_PermissiveStorefrontHandler)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        attacks_path = tmp_path / "attacks.json"
        results_path = tmp_path / "results.json"
        report_path = tmp_path / "report.md"
        artifact_dir = tmp_path / "artifacts"

        inspect_result = runner.invoke(app, ["inspect", str(STOREFRONT_SPEC), "--tag", "orders"])
        generate_result = runner.invoke(
            app,
            ["generate", str(STOREFRONT_SPEC), "--tag", "orders", "--out", str(attacks_path)],
        )
        run_result = runner.invoke(
            app,
            [
                "run",
                str(attacks_path),
                "--base-url",
                base_url,
                "--artifact-dir",
                str(artifact_dir),
                "--out",
                str(results_path),
            ],
        )
        report_result = runner.invoke(app, ["report", str(results_path), "--out", str(report_path)])
        verify_fail = runner.invoke(app, ["verify", str(results_path)])
        verify_pass = runner.invoke(
            app,
            ["verify", str(results_path), "--min-severity", "critical"],
        )

        assert inspect_result.exit_code == 0
        assert "Found 2 operations." in inspect_result.stdout
        assert generate_result.exit_code == 0
        assert run_result.exit_code == 0
        assert report_result.exit_code == 0
        assert verify_fail.exit_code == 1
        assert verify_pass.exit_code == 0

        results = AttackResults.model_validate_json(results_path.read_text(encoding="utf-8"))
        assert any(result.flagged for result in results.results)
        assert report_path.exists()
        assert list(artifact_dir.glob("*.json"))
    finally:
        _shutdown_server(server, thread)


def test_workflow_attack_smoke_against_local_stateful_api(tmp_path: Path) -> None:
    server, thread = _start_server(_ValidatingStorefrontHandler)
    try:
        suite = generate_attack_suite(
            load_operations(STOREFRONT_SPEC),
            source=str(STOREFRONT_SPEC),
            auto_workflows=True,
        )
        workflow_attack = next(attack for attack in suite.attacks if attack.type == "workflow")
        workflow_suite = AttackSuite(source=suite.source, attacks=[workflow_attack])
        artifact_dir = tmp_path / "artifacts"

        results = execute_attack_suite(
            workflow_suite,
            base_url=f"http://127.0.0.1:{server.server_port}",
            artifact_dir=artifact_dir,
        )

        [result] = results.results
        assert result.type == "workflow"
        assert result.status_code == 422
        assert result.flagged is False
        assert result.workflow_steps is not None
        assert result.workflow_steps[0].status_code == 200
        assert (artifact_dir / f"{workflow_attack.id}.json").exists()
        assert (artifact_dir / f"{workflow_attack.id}-step-01.json").exists()
    finally:
        _shutdown_server(server, thread)


def test_review_bundle_round_trip_smoke(tmp_path: Path) -> None:
    server, thread = _start_server(_PermissiveStorefrontHandler)
    try:
        attacks_path = tmp_path / "attacks.json"
        results_path = tmp_path / "results.json"
        artifact_dir = tmp_path / "artifacts"
        bundle_path = tmp_path / "review-bundle.zip"
        base_url = f"http://127.0.0.1:{server.server_port}"

        generate_result = runner.invoke(
            app,
            ["generate", str(STOREFRONT_SPEC), "--tag", "orders", "--out", str(attacks_path)],
        )
        run_result = runner.invoke(
            app,
            [
                "run",
                str(attacks_path),
                "--base-url",
                base_url,
                "--artifact-dir",
                str(artifact_dir),
                "--out",
                str(results_path),
            ],
        )
        bundle_result = runner.invoke(
            app,
            [
                "bundle",
                str(results_path),
                "--artifact-dir",
                str(artifact_dir),
                "--name",
                "CI review bundle",
                "--out",
                str(bundle_path),
            ],
        )

        assert generate_result.exit_code == 0
        assert run_result.exit_code == 0
        assert bundle_result.exit_code == 0

        results = AttackResults.model_validate_json(results_path.read_text(encoding="utf-8"))
        client = TestClient(create_app(data_dir=tmp_path / "api-data"))
        import_response = client.post(
            "/v1/projects/import-review-bundle",
            files={
                "bundle": (
                    "review-bundle.zip",
                    bundle_path.read_bytes(),
                    "application/zip",
                )
            },
        )

        assert import_response.status_code == 200
        project = import_response.json()
        assert project["name"] == "CI review bundle"
        assert project["source_mode"] == "review_bundle"
        assert project["artifacts"]["latest_results"]["base_url"] == base_url
        assert len(project["artifacts"]["latest_results"]["results"]) == len(results.results)

        jobs_response = client.get(f"/v1/projects/{project['id']}/jobs")
        assert jobs_response.status_code == 200
        [job] = jobs_response.json()["jobs"]
        assert job["kind"] == "import"
        assert job["artifact_names"]

        artifact_response = client.get(
            f"/v1/jobs/{job['id']}/artifacts/{job['artifact_names'][0]}",
        )
        assert artifact_response.status_code == 200
        assert artifact_response.text
    finally:
        _shutdown_server(server, thread)


def test_multi_profile_authorization_smoke(tmp_path: Path) -> None:
    server, thread = _start_server(_ProfileComparisonHandler)
    try:
        attacks_path = tmp_path / "profile-attacks.json"
        results_path = tmp_path / "profile-results.json"
        suite = AttackSuite(
            source="smoke",
            attacks=[
                AttackCase(
                    id="atk_secret_records",
                    name="Secret records",
                    kind="missing_auth",
                    operation_id="getSecretRecords",
                    method="GET",
                    path="/secret-records",
                    auth_required=True,
                    description="Anonymous access smoke test",
                    expected_outcomes=["401", "403"],
                ),
                AttackCase(
                    id="atk_admin_reports",
                    name="Admin reports",
                    kind="missing_auth",
                    operation_id="getAdminReports",
                    method="GET",
                    path="/admin-reports",
                    auth_required=True,
                    description="Authorization inversion smoke test",
                    expected_outcomes=["401", "403"],
                ),
            ],
        )
        attacks_path.write_text(
            suite.model_dump_json(indent=2, exclude_none=True),
            encoding="utf-8",
        )

        run_result = runner.invoke(
            app,
            [
                "run",
                str(attacks_path),
                "--base-url",
                f"http://127.0.0.1:{server.server_port}",
                "--profile-file",
                str(PROFILE_FILE),
                "--out",
                str(results_path),
            ],
        )

        assert run_result.exit_code == 0

        results = AttackResults.model_validate_json(results_path.read_text(encoding="utf-8"))
        flagged_issues = {result.issue for result in results.results if result.flagged}
        assert results.profiles == ["anonymous", "user", "admin"]
        assert "anonymous_access" in flagged_issues
        assert "authorization_inversion" in flagged_issues
        assert any(
            result.profile_results and len(result.profile_results) == 3
            for result in results.results
        )
    finally:
        _shutdown_server(server, thread)


def test_built_in_auth_acquisition_smoke(tmp_path: Path) -> None:
    server, thread = _start_server(_BuiltInAuthHandler, state={"token_requests": 0})
    try:
        attacks_path = tmp_path / "auth-attacks.json"
        results_path = tmp_path / "auth-results.json"
        suite = AttackSuite(
            source="smoke",
            attacks=[
                AttackCase(
                    id="atk_auth_refresh",
                    name="Protected draft order",
                    kind="missing_request_body",
                    operation_id="createDraftOrder",
                    method="POST",
                    path="/draft-orders",
                    auth_required=True,
                    description="Built-in auth acquisition smoke test",
                    omit_body=True,
                    expected_outcomes=["4xx"],
                )
            ],
        )
        attacks_path.write_text(
            suite.model_dump_json(indent=2, exclude_none=True),
            encoding="utf-8",
        )

        run_result = runner.invoke(
            app,
            [
                "run",
                str(attacks_path),
                "--base-url",
                f"http://127.0.0.1:{server.server_port}",
                "--auth-config",
                str(CLIENT_CREDENTIALS_CONFIG),
                "--out",
                str(results_path),
            ],
            env={
                "KNIVES_OUT_CLIENT_ID": "smoke-client",
                "KNIVES_OUT_CLIENT_SECRET": "smoke-secret",
                "KNIVES_OUT_CLIENT_AUDIENCE": "smoke-audience",
            },
        )

        assert run_result.exit_code == 0

        results = AttackResults.model_validate_json(results_path.read_text(encoding="utf-8"))
        [result] = results.results
        assert result.status_code == 422
        assert result.flagged is False
        assert [event.phase for event in results.auth_events] == ["acquire", "refresh"]
        assert all(event.success for event in results.auth_events)
    finally:
        _shutdown_server(server, thread)


def test_shadow_twin_capture_discover_generate_smoke(tmp_path: Path) -> None:
    target_server, target_thread = _start_server(_ShadowTwinTargetHandler)
    capture_path = tmp_path / "capture.ndjson"
    learned_path = tmp_path / "learned-model.json"
    attacks_path = tmp_path / "learned-attacks.json"
    proxy_port = _free_port()
    proxy_thread = threading.Thread(
        target=serve_capture_proxy,
        kwargs={
            "listen_host": "127.0.0.1",
            "listen_port": proxy_port,
            "target_base_url": f"http://127.0.0.1:{target_server.server_port}",
            "output_path": capture_path,
            "max_events": 3,
        },
        daemon=True,
    )
    proxy_thread.start()
    _wait_for_port(proxy_port)

    try:
        response = httpx.post(
            f"http://127.0.0.1:{proxy_port}/draft-orders",
            json={
                "customerEmail": _FIXED_EMAIL,
                "note": "example note",
                "lineItems": [{"sku": _FIXED_SKU, "quantity": 1}],
            },
            timeout=5.0,
        )
        assert response.status_code == 201

        get_response = httpx.get(
            f"http://127.0.0.1:{proxy_port}/draft-orders/ord_123",
            timeout=5.0,
        )
        assert get_response.status_code == 200

        delete_response = httpx.delete(
            f"http://127.0.0.1:{proxy_port}/draft-orders/ord_123",
            timeout=5.0,
        )
        assert delete_response.status_code == 204

        proxy_thread.join(timeout=5.0)

        [*_events] = read_capture_events(capture_path)
        assert len(_events) == 3

        discover_result = runner.invoke(
            app,
            ["discover", str(capture_path), "--out", str(learned_path)],
        )
        generate_result = runner.invoke(
            app,
            ["generate", str(learned_path), "--out", str(attacks_path)],
        )

        assert discover_result.exit_code == 0
        assert generate_result.exit_code == 0

        learned_model = LearnedModel.model_validate_json(learned_path.read_text(encoding="utf-8"))
        suite = AttackSuite.model_validate_json(attacks_path.read_text(encoding="utf-8"))
        assert learned_model.workflows
        assert any(
            attack.kind in {"missing_learned_setup", "stale_resource_reference"}
            for attack in suite.attacks
        )
    finally:
        _shutdown_server(target_server, target_thread)
