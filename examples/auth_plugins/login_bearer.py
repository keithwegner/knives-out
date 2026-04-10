from __future__ import annotations

import os

from knives_out.auth_plugins import (
    PreparedRequest,
    RuntimeContext,
    RuntimePlugin,
    extract_json_pointer,
    make_auth_plugin,
)


class LoginBearerPlugin(RuntimePlugin):
    def _login(self, context: RuntimeContext) -> None:
        username = os.environ.get("KNIVES_OUT_LOGIN_USERNAME")
        password = os.environ.get("KNIVES_OUT_LOGIN_PASSWORD")
        if not username or not password:
            raise RuntimeError(
                "Set KNIVES_OUT_LOGIN_USERNAME and KNIVES_OUT_LOGIN_PASSWORD "
                "before using the login-bearer auth plugin."
            )

        login_path = os.environ.get("KNIVES_OUT_LOGIN_PATH", "/login")
        token_pointer = os.environ.get("KNIVES_OUT_LOGIN_TOKEN_POINTER", "/token")
        response = context.client.request(
            "POST",
            context.build_url(login_path),
            json={"username": username, "password": password},
        )
        if response.status_code >= 400:
            raise RuntimeError(
                f"Login request to {login_path!r} failed with status {response.status_code}."
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError(f"Login response was not valid JSON: {exc}") from exc

        try:
            token = extract_json_pointer(payload, token_pointer)
        except ValueError as exc:
            raise RuntimeError(
                f"Could not extract bearer token from login response: {exc}"
            ) from exc

        context.state["bearer_token"] = token

    def before_suite(self, context: RuntimeContext) -> None:
        if "bearer_token" not in context.state:
            self._login(context)

    def before_request(self, request: PreparedRequest, context: RuntimeContext) -> None:
        token = context.state.get("bearer_token")
        if token is not None:
            request.headers.setdefault("Authorization", f"Bearer {token}")


auth_plugin = make_auth_plugin("login-bearer", LoginBearerPlugin())
