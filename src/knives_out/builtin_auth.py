from __future__ import annotations

import os
import time
from typing import Any

import httpx

from knives_out.auth_config import BuiltInAuthConfig
from knives_out.auth_plugins import (
    LoadedAuthPlugin,
    PreparedRequest,
    RequestExecution,
    RuntimeContext,
    RuntimePlugin,
    extract_json_pointer,
    make_auth_plugin,
)
from knives_out.models import AuthEvent

_EXACT_PLACEHOLDER = "{{"


def _status_matches_expected(status_code: int | None, expected_statuses: list[str]) -> bool:
    if status_code is None:
        return False
    for expected in expected_statuses:
        normalized = expected.strip().lower()
        if not normalized:
            continue
        if normalized.endswith("xx") and len(normalized) == 3 and normalized[0].isdigit():
            if status_code // 100 == int(normalized[0]):
                return True
            continue
        if normalized.isdigit() and status_code == int(normalized):
            return True
    return False


class BuiltInAuthPlugin(RuntimePlugin):
    def __init__(self, config: BuiltInAuthConfig) -> None:
        self.config = config

    @property
    def _state_key(self) -> str:
        return f"built_in_auth:{self.config.name}"

    def _bundle(self, context: RuntimeContext) -> dict[str, Any]:
        bundle = context.state.setdefault(self._state_key, {})
        if not isinstance(bundle, dict):
            bundle = {}
            context.state[self._state_key] = bundle
        return bundle

    def _template_values(self, bundle: dict[str, Any]) -> dict[str, Any]:
        return dict(bundle.get("values") or {})

    def _resolve_placeholder(self, placeholder: str, values: dict[str, Any]) -> Any:
        if placeholder.startswith("env."):
            env_name = placeholder[4:]
            env_value = os.environ.get(env_name)
            if env_value is None:
                raise RuntimeError(f"Missing environment variable {env_name!r}.")
            return env_value
        if placeholder not in values:
            raise RuntimeError(f"Missing auth template value {placeholder!r}.")
        return values[placeholder]

    def _resolve_templates(self, value: Any, values: dict[str, Any]) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith(_EXACT_PLACEHOLDER) and stripped.endswith("}}"):
                placeholder = stripped[2:-2].strip()
                if stripped == f"{{{{{placeholder}}}}}":
                    return self._resolve_placeholder(placeholder, values)

            rendered = value
            while "{{" in rendered and "}}" in rendered:
                start = rendered.find("{{")
                end = rendered.find("}}", start + 2)
                if start == -1 or end == -1:
                    break
                placeholder = rendered[start + 2 : end].strip()
                replacement = str(self._resolve_placeholder(placeholder, values))
                rendered = rendered[:start] + replacement + rendered[end + 2 :]
            return rendered
        if isinstance(value, list):
            return [self._resolve_templates(item, values) for item in value]
        if isinstance(value, dict):
            return {str(key): self._resolve_templates(item, values) for key, item in value.items()}
        return value

    def _record_event(
        self,
        context: RuntimeContext,
        *,
        phase: str,
        success: bool,
        trigger: str,
        endpoint: str | None = None,
        status_code: int | None = None,
        error: str | None = None,
    ) -> None:
        context.auth_events.append(
            AuthEvent(
                name=self.config.name,
                strategy=self.config.strategy,
                phase=phase,  # type: ignore[arg-type]
                success=success,
                profile=context.profile_name,
                trigger=trigger,
                endpoint=endpoint,
                status_code=status_code,
                error=error,
            )
        )

    def _token_expired(self, bundle: dict[str, Any]) -> bool:
        expires_at = bundle.get("expires_at")
        if not isinstance(expires_at, (int, float)):
            return False
        return time.time() + self.config.refresh_window_seconds >= float(expires_at)

    def _set_token_state(
        self,
        bundle: dict[str, Any],
        *,
        token: Any,
        expires_in: Any | None,
        context: RuntimeContext,
    ) -> None:
        bundle["token"] = token
        values = self._template_values(bundle)
        values["token"] = token
        values["access_token"] = token
        bundle["values"] = values
        if expires_in is None:
            bundle.pop("expires_at", None)
        else:
            bundle["expires_at"] = time.time() + float(expires_in)
        bundle["client_id"] = id(context.client)

    def _inject_token(self, request: PreparedRequest, bundle: dict[str, Any]) -> None:
        token = bundle.get("token")
        if token is None:
            return
        if self.config.header_name:
            if self.config.header_scheme:
                request.headers[self.config.header_name] = f"{self.config.header_scheme} {token}"
            else:
                request.headers[self.config.header_name] = str(token)
        if self.config.query_name:
            request.query[self.config.query_name] = token

    def _auth_request_kwargs(self, bundle: dict[str, Any]) -> dict[str, Any]:
        values = self._template_values(bundle)
        request_headers = self._resolve_templates(self.config.request_headers, values)
        request_query = self._resolve_templates(self.config.request_query, values)
        request_kwargs: dict[str, Any] = {
            "params": request_query,
            "headers": {name: str(value) for name, value in request_headers.items()},
        }
        if self.config.request_json is not None:
            request_kwargs["json"] = self._resolve_templates(self.config.request_json, values)
        elif self.config.request_form:
            request_kwargs["data"] = self._resolve_templates(self.config.request_form, values)
        return request_kwargs

    def _acquire(self, context: RuntimeContext, *, phase: str, trigger: str) -> bool:
        bundle = self._bundle(context)
        if self.config.strategy == "static_bearer":
            try:
                token = self._resolve_templates(self.config.token, self._template_values(bundle))
            except RuntimeError as exc:
                bundle["last_error"] = str(exc)
                self._record_event(
                    context, phase=phase, success=False, trigger=trigger, error=str(exc)
                )
                return False
            self._set_token_state(bundle, token=token, expires_in=None, context=context)
            bundle.pop("last_error", None)
            self._record_event(context, phase=phase, success=True, trigger=trigger)
            return True

        endpoint = self.config.endpoint
        if endpoint is None:
            message = f"Auth config '{self.config.name}' is missing an endpoint."
            bundle["last_error"] = message
            self._record_event(context, phase=phase, success=False, trigger=trigger, error=message)
            return False

        url = context.build_url(endpoint)
        try:
            response = context.client.request(
                self.config.method,
                url,
                **self._auth_request_kwargs(bundle),
            )
            if not _status_matches_expected(response.status_code, self.config.expected_statuses):
                raise RuntimeError(
                    f"Auth request returned status {response.status_code}; "
                    f"expected one of {', '.join(self.config.expected_statuses)}."
                )

            if self.config.strategy == "login_form_cookie":
                bundle["session_ready"] = True
                bundle["client_id"] = id(context.client)
                bundle.pop("last_error", None)
                self._record_event(
                    context,
                    phase=phase,
                    success=True,
                    trigger=trigger,
                    endpoint=endpoint,
                    status_code=response.status_code,
                )
                return True

            try:
                payload = response.json()
            except ValueError as exc:
                raise RuntimeError(f"Auth response was not valid JSON: {exc}") from exc

            token_pointer = self.config.token_pointer
            if token_pointer is None:
                raise RuntimeError("Token-based auth config is missing token_pointer.")
            token = extract_json_pointer(payload, token_pointer)
            expires_in = None
            if self.config.expires_in_pointer:
                try:
                    expires_in = extract_json_pointer(payload, self.config.expires_in_pointer)
                except ValueError:
                    expires_in = None
            self._set_token_state(bundle, token=token, expires_in=expires_in, context=context)
            bundle.pop("last_error", None)
            self._record_event(
                context,
                phase=phase,
                success=True,
                trigger=trigger,
                endpoint=endpoint,
                status_code=response.status_code,
            )
            return True
        except (RuntimeError, ValueError, httpx.HTTPError) as exc:
            bundle["last_error"] = str(exc)
            bundle.pop("session_ready", None)
            bundle.pop("token", None)
            bundle.pop("expires_at", None)
            self._record_event(
                context,
                phase=phase,
                success=False,
                trigger=trigger,
                endpoint=endpoint,
                error=str(exc),
            )
            return False

    def _ensure_ready(self, context: RuntimeContext, *, trigger: str) -> bool:
        bundle = self._bundle(context)
        if self.config.strategy == "login_form_cookie":
            if bundle.get("session_ready") and bundle.get("client_id") == id(context.client):
                return True
            return self._acquire(context, phase="acquire", trigger=trigger)

        if bundle.get("token") is None:
            return self._acquire(context, phase="acquire", trigger=trigger)
        if self._token_expired(bundle):
            return self._acquire(context, phase="refresh", trigger="expiry")
        return True

    def before_suite(self, context: RuntimeContext) -> None:
        self._ensure_ready(context, trigger="suite")

    def before_workflow(self, workflow, context: RuntimeContext) -> None:
        del workflow
        self._ensure_ready(context, trigger="workflow")

    def before_request(self, request: PreparedRequest, context: RuntimeContext) -> None:
        self._ensure_ready(context, trigger="request")
        if self.config.strategy != "login_form_cookie":
            self._inject_token(request, self._bundle(context))

    def after_request(
        self,
        request: PreparedRequest,
        context: RuntimeContext,
        execution: RequestExecution,
    ) -> None:
        del request
        if (
            execution.response is None
            or execution.response.status_code != 401
            or not self.config.refresh_on_401
        ):
            return

        bundle = self._bundle(context)
        if bundle.get("retry_in_progress"):
            return

        bundle["retry_in_progress"] = True
        try:
            refreshed = self._acquire(context, phase="refresh", trigger="401")
        finally:
            bundle["retry_in_progress"] = False

        if refreshed:
            execution.retry_requested = True


def make_builtin_auth_plugin(config: BuiltInAuthConfig) -> LoadedAuthPlugin:
    return make_auth_plugin(config.name, BuiltInAuthPlugin(config))
