from __future__ import annotations

import httpx
import pytest

from knives_out.auth_config import BuiltInAuthConfig
from knives_out.auth_plugins import PreparedRequest, RequestExecution, RuntimeContext
from knives_out.builtin_auth import BuiltInAuthPlugin, _status_matches_expected


class _Client:
    def __init__(self, responses: list[httpx.Response] | None = None) -> None:
        self.responses = list(responses or [])
        self.requests: list[dict[str, object]] = []

    def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        self.requests.append({"method": method, "url": url, **kwargs})
        if not self.responses:
            raise AssertionError("No response queued.")
        return self.responses.pop(0)


def _context(*, client: _Client | None = None) -> RuntimeContext:
    return RuntimeContext(
        client=client or _Client(),
        base_url="https://example.com/",
        scope="suite",
    )


def _request() -> PreparedRequest:
    return PreparedRequest(
        phase="request",
        attack_id="atk_test",
        name="Test attack",
        kind="missing_auth",
        operation_id="listPets",
        method="GET",
        path="/pets",
        description="Test attack",
    )


def test_status_matches_expected_accepts_ranges_and_exact_codes() -> None:
    assert _status_matches_expected(204, ["", "2xx"]) is True
    assert _status_matches_expected(401, ["200", "401"]) is True
    assert _status_matches_expected(None, ["2xx"]) is False
    assert _status_matches_expected(500, ["2xx", "401"]) is False


def test_static_bearer_templates_can_resolve_env_and_nested_values(monkeypatch) -> None:
    monkeypatch.setenv("KNIVES_OUT_TOKEN", "env-token")
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="user",
            strategy="static_bearer",
            token="{{env.KNIVES_OUT_TOKEN}}",
            query_name="access_token",
        )
    )
    context = _context()
    request = _request()

    plugin.before_suite(context)
    plugin.before_request(request, context)

    assert request.headers["Authorization"] == "Bearer env-token"
    assert request.query["access_token"] == "env-token"
    assert context.auth_events[0].success is True


def test_static_bearer_records_failure_for_missing_env(monkeypatch) -> None:
    monkeypatch.delenv("KNIVES_OUT_TOKEN", raising=False)
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="user",
            strategy="static_bearer",
            token="{{env.KNIVES_OUT_TOKEN}}",
        )
    )
    context = _context()

    plugin.before_suite(context)

    bundle = context.state[plugin._state_key]
    assert bundle["last_error"] == "Missing environment variable 'KNIVES_OUT_TOKEN'."
    assert context.auth_events[0].success is False


def test_auth_request_kwargs_support_json_headers_query_and_form_templating() -> None:
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="client_credentials",
            endpoint="/oauth/token",
            request_headers={"X-Trace": "{{token}}"},
            request_query={"tenant": "{{tenant}}"},
            request_json={"refresh_token": "{{token}}"},
            token_pointer="/access_token",
        )
    )
    bundle = {"values": {"token": "abc123", "tenant": "acme"}}

    request_kwargs = plugin._auth_request_kwargs(bundle)

    assert request_kwargs == {
        "params": {"tenant": "acme"},
        "headers": {"X-Trace": "abc123"},
        "json": {"refresh_token": "abc123"},
    }


def test_login_form_cookie_reuses_existing_session_for_same_client() -> None:
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="session",
            strategy="login_form_cookie",
            endpoint="/login",
            request_form={"username": "demo"},
        )
    )
    context = _context()
    context.state[plugin._state_key] = {"session_ready": True, "client_id": id(context.client)}

    assert plugin._ensure_ready(context, trigger="workflow") is True
    assert context.auth_events == []


def test_bundle_replaces_non_mapping_state_and_before_workflow_prepares_auth() -> None:
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="user",
            strategy="static_bearer",
            token="workflow-token",
        )
    )
    context = _context()
    context.state[plugin._state_key] = "broken"

    plugin.before_workflow(None, context)

    bundle = context.state[plugin._state_key]
    assert bundle["token"] == "workflow-token"
    assert context.auth_events[0].success is True


def test_before_request_skips_reacquire_after_failed_request_for_same_client() -> None:
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="client_credentials",
            endpoint="/oauth/token",
            request_form={"grant_type": "client_credentials"},
            token_pointer="/access_token",
        )
    )
    context = _context()
    context.state[plugin._state_key] = {"last_error": "boom", "client_id": id(context.client)}
    request = _request()

    plugin.before_request(request, context)

    assert request.headers == {}
    assert context.auth_events == []


def test_after_request_avoids_retry_when_refresh_disabled() -> None:
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="client_credentials",
            endpoint="/oauth/token",
            request_form={"grant_type": "client_credentials"},
            token_pointer="/access_token",
            refresh_on_401=False,
        )
    )
    context = _context()
    request = _request()
    execution = RequestExecution(
        url="https://example.com/pets",
        headers={},
        query={},
        response=httpx.Response(401),
        error=None,
        duration_ms=1.0,
    )

    plugin.after_request(request, context, execution)

    assert execution.retry_requested is False
    assert context.auth_events == []


def test_after_request_marks_retry_when_refresh_succeeds() -> None:
    client = _Client(
        [
            httpx.Response(200, json={"access_token": "fresh-token", "expires_in": 60}),
        ]
    )
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="client_credentials",
            endpoint="/oauth/token",
            request_form={"grant_type": "client_credentials"},
            token_pointer="/access_token",
            expires_in_pointer="/expires_in",
        )
    )
    context = _context(client=client)
    context.state[plugin._state_key] = {"token": "expired-token"}
    request = _request()
    execution = RequestExecution(
        url="https://example.com/pets",
        headers={},
        query={},
        response=httpx.Response(401),
        error=None,
        duration_ms=1.0,
    )

    plugin.after_request(request, context, execution)

    bundle = context.state[plugin._state_key]
    assert execution.retry_requested is True
    assert bundle["token"] == "fresh-token"
    assert bundle["retried_request_key"] == "request:atk_test"
    assert context.auth_events[0].phase == "refresh"


def test_after_request_does_not_retry_same_request_twice() -> None:
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="client_credentials",
            endpoint="/oauth/token",
            request_form={"grant_type": "client_credentials"},
            token_pointer="/access_token",
        )
    )
    context = _context()
    request = _request()
    context.state[plugin._state_key] = {"retried_request_key": "request:atk_test"}
    execution = RequestExecution(
        url="https://example.com/pets",
        headers={},
        query={},
        response=httpx.Response(401),
        error=None,
        duration_ms=1.0,
    )

    plugin.after_request(request, context, execution)

    assert execution.retry_requested is False
    assert context.auth_events == []


def test_after_request_does_not_retry_when_previous_refresh_failed() -> None:
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="client_credentials",
            endpoint="/oauth/token",
            request_form={"grant_type": "client_credentials"},
            token_pointer="/access_token",
        )
    )
    context = _context()
    request = _request()
    context.state[plugin._state_key] = {
        "last_error": "invalid credentials",
        "client_id": id(context.client),
    }
    execution = RequestExecution(
        url="https://example.com/pets",
        headers={},
        query={},
        response=httpx.Response(401),
        error=None,
        duration_ms=1.0,
    )

    plugin.after_request(request, context, execution)

    assert execution.retry_requested is False
    assert context.auth_events == []


def test_template_resolution_preserves_non_string_types() -> None:
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="static_bearer",
            token="dev-token",
        )
    )

    rendered = plugin._resolve_templates(
        {
            "count": "{{count}}",
            "items": ["{{count}}", "prefix-{{token}}"],
            "enabled": True,
        },
        {"count": 3, "token": "abc"},
    )

    assert rendered == {"count": 3, "items": [3, "prefix-abc"], "enabled": True}


def test_exact_placeholder_errors_when_value_missing() -> None:
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="static_bearer",
            token="dev-token",
        )
    )

    with pytest.raises(RuntimeError, match="Missing auth template value 'missing'"):
        plugin._resolve_templates("{{missing}}", {})


def test_before_request_injects_raw_token_when_header_scheme_disabled() -> None:
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="static_bearer",
            token="dev-token",
            header_scheme=None,
            header_name="X-Token",
        )
    )
    context = _context()
    request = _request()

    plugin.before_request(request, context)

    assert request.headers["X-Token"] == "dev-token"


def test_acquire_fails_when_endpoint_missing_after_configuration_change() -> None:
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="client_credentials",
            endpoint="/oauth/token",
            request_form={"grant_type": "client_credentials"},
            token_pointer="/access_token",
        )
    )
    plugin.config.endpoint = None
    context = _context()

    assert plugin._acquire(context, phase="acquire", trigger="suite") is False
    assert "missing an endpoint" in context.state[plugin._state_key]["last_error"]


def test_acquire_fails_for_non_json_auth_response() -> None:
    client = _Client([httpx.Response(200, text="not-json")])
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="client_credentials",
            endpoint="/oauth/token",
            request_form={"grant_type": "client_credentials"},
            token_pointer="/access_token",
        )
    )
    context = _context(client=client)

    assert plugin._acquire(context, phase="acquire", trigger="suite") is False
    assert "not valid JSON" in context.state[plugin._state_key]["last_error"]


def test_acquire_fails_when_token_pointer_missing_after_configuration_change() -> None:
    client = _Client([httpx.Response(200, json={"access_token": "token"})])
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="client_credentials",
            endpoint="/oauth/token",
            request_form={"grant_type": "client_credentials"},
            token_pointer="/access_token",
        )
    )
    plugin.config.token_pointer = None
    context = _context(client=client)

    assert plugin._acquire(context, phase="acquire", trigger="suite") is False
    assert "missing token_pointer" in context.state[plugin._state_key]["last_error"]


def test_expired_token_triggers_refresh_even_when_expiry_pointer_is_missing() -> None:
    client = _Client([httpx.Response(200, json={"access_token": "fresh-token"})])
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="client_credentials",
            endpoint="/oauth/token",
            request_form={"grant_type": "client_credentials"},
            token_pointer="/access_token",
            expires_in_pointer="/missing",
        )
    )
    context = _context(client=client)
    context.state[plugin._state_key] = {"token": "expired-token", "expires_at": 0}

    assert plugin._ensure_ready(context, trigger="workflow") is True
    assert context.state[plugin._state_key]["token"] == "fresh-token"
    assert context.auth_events[0].phase == "refresh"


def test_after_request_skips_when_refresh_already_in_progress() -> None:
    plugin = BuiltInAuthPlugin(
        BuiltInAuthConfig(
            name="service",
            strategy="client_credentials",
            endpoint="/oauth/token",
            request_form={"grant_type": "client_credentials"},
            token_pointer="/access_token",
        )
    )
    context = _context()
    context.state[plugin._state_key] = {"retry_in_progress": True}
    execution = RequestExecution(
        url="https://example.com/pets",
        headers={},
        query={},
        response=httpx.Response(401),
        error=None,
        duration_ms=1.0,
    )

    plugin.after_request(_request(), context, execution)

    assert execution.retry_requested is False
