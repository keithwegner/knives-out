from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from textwrap import dedent

import httpx
from typer.testing import CliRunner

from knives_out.capture import read_capture_events, serve_capture_proxy
from knives_out.cli import app
from knives_out.generator import generate_attack_suite
from knives_out.learned_discovery import discover_learned_model
from knives_out.models import CapturedRequest, CapturedResponse, CaptureEvent
from knives_out.spec_loader import is_learned_model_path, load_operations_with_warnings

runner = CliRunner()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start_server(
    handler: type[BaseHTTPRequestHandler],
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", _free_port()), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _write_capture_ndjson(path: Path, events: list[CaptureEvent]) -> None:
    path.write_text(
        "\n".join(event.model_dump_json(exclude_none=True) for event in events) + "\n",
        encoding="utf-8",
    )


def _workflow_capture_events() -> list[CaptureEvent]:
    return [
        CaptureEvent(
            request=CapturedRequest(
                method="POST",
                url="https://shadow.example.test/draft-orders",
                headers={"Authorization": "<redacted:authorization>"},
                query={},
                body_json={"sku": "book-1"},
                content_type="application/json",
            ),
            response=CapturedResponse(
                status_code=201,
                headers={"Content-Type": "application/json"},
                body_json={"id": "ord_123", "status": "draft"},
                content_type="application/json",
            ),
            identity_context="authctx_user",
        ),
        CaptureEvent(
            request=CapturedRequest(
                method="GET",
                url="https://shadow.example.test/draft-orders/ord_123",
                headers={"Authorization": "<redacted:authorization>"},
                query={},
            ),
            response=CapturedResponse(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body_json={"id": "ord_123", "status": "draft"},
                content_type="application/json",
            ),
            identity_context="authctx_user",
        ),
        CaptureEvent(
            request=CapturedRequest(
                method="DELETE",
                url="https://shadow.example.test/draft-orders/ord_123",
                headers={"Authorization": "<redacted:authorization>"},
                query={},
            ),
            response=CapturedResponse(
                status_code=204,
                headers={},
            ),
            identity_context="authctx_user",
        ),
        CaptureEvent(
            request=CapturedRequest(
                method="POST",
                url="https://shadow.example.test/draft-orders",
                headers={"Authorization": "<redacted:authorization>"},
                query={},
                body_json={"sku": "book-2"},
                content_type="application/json",
            ),
            response=CapturedResponse(
                status_code=201,
                headers={"Content-Type": "application/json"},
                body_json={"id": "ord_456", "status": "draft"},
                content_type="application/json",
            ),
            identity_context="authctx_admin",
        ),
        CaptureEvent(
            request=CapturedRequest(
                method="GET",
                url="https://shadow.example.test/draft-orders/ord_456",
                headers={"Authorization": "<redacted:authorization>"},
                query={},
            ),
            response=CapturedResponse(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body_json={"id": "ord_456", "status": "draft"},
                content_type="application/json",
            ),
            identity_context="authctx_admin",
        ),
        CaptureEvent(
            request=CapturedRequest(
                method="DELETE",
                url="https://shadow.example.test/draft-orders/ord_456",
                headers={"Authorization": "<redacted:authorization>"},
                query={},
            ),
            response=CapturedResponse(
                status_code=204,
                headers={},
            ),
            identity_context="authctx_admin",
        ),
    ]


def _workflow_har_text() -> str:
    return dedent(
        """
        {
          "log": {
            "version": "1.2",
            "creator": {"name": "pytest", "version": "1"},
            "entries": [
              {
                "startedDateTime": "2026-04-10T12:00:00.000Z",
                "time": 12.0,
                "request": {
                  "method": "GET",
                  "url": "https://shadow.example.test/pets/101",
                  "headers": [{"name": "Authorization", "value": "Bearer secret-a"}],
                  "queryString": [],
                  "postData": {}
                },
                "response": {
                  "status": 200,
                  "headers": [{"name": "Content-Type", "value": "application/json"}],
                  "content": {
                    "mimeType": "application/json",
                    "text": "{\\"id\\": 101, \\"name\\": \\"Alpha\\"}"
                  }
                }
              },
              {
                "startedDateTime": "2026-04-10T12:00:01.000Z",
                "time": 13.0,
                "request": {
                  "method": "GET",
                  "url": "https://shadow.example.test/pets/202",
                  "headers": [{"name": "Authorization", "value": "Bearer secret-b"}],
                  "queryString": [],
                  "postData": {}
                },
                "response": {
                  "status": 200,
                  "headers": [{"name": "Content-Type", "value": "application/json"}],
                  "content": {
                    "mimeType": "application/json",
                    "text": "{\\"id\\": 202, \\"name\\": \\"Beta\\"}"
                  }
                }
              }
            ]
          }
        }
        """
    ).strip()


def test_capture_proxy_records_redacted_events(tmp_path: Path) -> None:
    class TargetHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            payload = json.dumps({"received": json.loads(body), "id": "ord_123"}).encode("utf-8")
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    target_server, target_thread = _start_server(TargetHandler)
    capture_path = tmp_path / "capture.ndjson"
    proxy_port = _free_port()
    proxy_thread = threading.Thread(
        target=serve_capture_proxy,
        kwargs={
            "listen_host": "127.0.0.1",
            "listen_port": proxy_port,
            "target_base_url": f"http://127.0.0.1:{target_server.server_port}",
            "output_path": capture_path,
            "max_events": 1,
        },
        daemon=True,
    )
    proxy_thread.start()

    response = httpx.post(
        f"http://127.0.0.1:{proxy_port}/draft-orders?api_key=shadow-secret",
        headers={"Authorization": "Bearer real-token"},
        json={
            "password": "top-secret",
            "token": {"access": "nested-secret"},
            "sku": "book-1",
        },
        timeout=5.0,
    )

    proxy_thread.join(timeout=5.0)
    target_server.shutdown()
    target_thread.join(timeout=5.0)

    assert response.status_code == 201
    [event] = read_capture_events(capture_path)
    assert event.identity_context is not None
    assert event.request.headers["Authorization"].startswith("<redacted:")
    assert event.request.query["api_key"].startswith("<redacted:")
    assert event.request.body_json == {
        "password": "<redacted:password>",
        "token": "<redacted:token>",
        "sku": "book-1",
    }


def test_discover_learned_model_matches_har_and_ndjson_inputs(tmp_path: Path) -> None:
    capture_path = tmp_path / "capture.ndjson"
    har_path = tmp_path / "capture.har"
    _write_capture_ndjson(
        capture_path,
        [
            CaptureEvent(
                request=CapturedRequest(
                    method="GET",
                    url="https://shadow.example.test/pets/101",
                    headers={"Authorization": "<redacted:authorization>"},
                    query={},
                ),
                response=CapturedResponse(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    body_json={"id": 101, "name": "Alpha"},
                    content_type="application/json",
                ),
                identity_context="authctx_a",
            ),
            CaptureEvent(
                request=CapturedRequest(
                    method="GET",
                    url="https://shadow.example.test/pets/202",
                    headers={"Authorization": "<redacted:authorization>"},
                    query={},
                ),
                response=CapturedResponse(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    body_json={"id": 202, "name": "Beta"},
                    content_type="application/json",
                ),
                identity_context="authctx_b",
            ),
        ],
    )
    har_path.write_text(_workflow_har_text(), encoding="utf-8")

    ndjson_model = discover_learned_model([capture_path])
    har_model = discover_learned_model([har_path])

    assert [operation.path for operation in ndjson_model.operations] == ["/pets/{pet_id}"]
    assert [operation.path for operation in har_model.operations] == ["/pets/{pet_id}"]
    assert ndjson_model.operations[0].parameters[0].schema_def == {"type": "integer"}
    assert har_model.operations[0].parameters[0].schema_def == {"type": "integer"}
    assert ndjson_model.operations[0].auth_required is True
    assert har_model.operations[0].auth_required is True


def test_discover_learned_model_keeps_distinct_resource_families_separate(tmp_path: Path) -> None:
    capture_path = tmp_path / "capture.ndjson"
    _write_capture_ndjson(
        capture_path,
        [
            CaptureEvent(
                request=CapturedRequest(
                    method="GET",
                    url="https://shadow.example.test/pets/101",
                    headers={},
                    query={},
                ),
                response=CapturedResponse(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    body_json={"id": 101, "name": "Alpha"},
                    content_type="application/json",
                ),
            ),
            CaptureEvent(
                request=CapturedRequest(
                    method="GET",
                    url="https://shadow.example.test/users/202",
                    headers={},
                    query={},
                ),
                response=CapturedResponse(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    body_json={"id": 202, "name": "Beta"},
                    content_type="application/json",
                ),
            ),
        ],
    )

    learned_model = discover_learned_model([capture_path])

    assert {operation.path for operation in learned_model.operations} == {
        "/pets/{pet_id}",
        "/users/{user_id}",
    }


def test_discover_learned_model_infers_workflows_and_lifecycle(tmp_path: Path) -> None:
    capture_path = tmp_path / "capture.ndjson"
    _write_capture_ndjson(capture_path, _workflow_capture_events())

    learned_model = discover_learned_model([capture_path])

    assert {operation.method for operation in learned_model.operations} == {"POST", "GET", "DELETE"}
    get_operation = next(
        operation for operation in learned_model.operations if operation.method == "GET"
    )
    assert get_operation.path == "/draft-orders/{draft_order_id}"
    assert get_operation.learned_confidence is not None

    workflow = next(
        workflow
        for workflow in learned_model.workflows
        if workflow.consumer_operation_id == get_operation.operation_id
    )
    assert workflow.delete_operation_id is not None
    assert workflow.bindings[0].target == "path"
    assert workflow.bindings[0].target_name == "draft_order_id"


def test_learned_model_load_and_generation_emit_shadow_twin_attacks(tmp_path: Path) -> None:
    capture_path = tmp_path / "capture.ndjson"
    learned_path = tmp_path / "learned-model.json"
    _write_capture_ndjson(capture_path, _workflow_capture_events())
    learned_model = discover_learned_model([capture_path])
    learned_path.write_text(
        learned_model.model_dump_json(indent=2, exclude_none=True),
        encoding="utf-8",
    )

    loaded = load_operations_with_warnings(learned_path)
    suite = generate_attack_suite(
        loaded.operations,
        source=str(learned_path),
        learned_model=loaded.learned_model,
    )

    assert is_learned_model_path(learned_path) is True
    assert loaded.source_kind == "learned"
    assert any(attack.kind == "missing_learned_setup" for attack in suite.attacks)
    assert any(attack.type == "workflow" for attack in suite.attacks)
    assert any(attack.kind == "stale_resource_reference" for attack in suite.attacks)


def test_discover_and_generate_commands_support_learned_models(tmp_path: Path) -> None:
    capture_path = tmp_path / "capture.ndjson"
    learned_path = tmp_path / "learned-model.json"
    attacks_path = tmp_path / "attacks.json"
    _write_capture_ndjson(capture_path, _workflow_capture_events())

    discover_result = runner.invoke(
        app,
        ["discover", str(capture_path), "--out", str(learned_path)],
    )
    inspect_result = runner.invoke(app, ["inspect", str(learned_path)])
    generate_result = runner.invoke(
        app,
        ["generate", str(learned_path), "--out", str(attacks_path)],
    )

    assert discover_result.exit_code == 0
    assert "Wrote learned model" in discover_result.stdout
    assert inspect_result.exit_code == 0
    assert "Learned workflows:" in inspect_result.stdout
    assert generate_result.exit_code == 0

    suite = json.loads(attacks_path.read_text(encoding="utf-8"))
    assert any(attack["kind"] == "missing_learned_setup" for attack in suite["attacks"])
