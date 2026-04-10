from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator

from knives_out.models import AuthProfile

AuthStrategy = Literal[
    "static_bearer",
    "client_credentials",
    "password_json",
    "login_json_bearer",
    "login_form_cookie",
]


class BuiltInAuthConfig(BaseModel):
    name: str
    strategy: AuthStrategy
    description: str | None = None
    level: int = 0
    anonymous: bool = False
    headers: dict[str, str] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
    header_name: str | None = "Authorization"
    header_scheme: str | None = "Bearer"
    query_name: str | None = None
    token: str | None = None
    endpoint: str | None = None
    method: str = "POST"
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_query: dict[str, Any] = Field(default_factory=dict)
    request_json: Any | None = None
    request_form: dict[str, Any] = Field(default_factory=dict)
    token_pointer: str | None = None
    expires_in_pointer: str | None = None
    refresh_on_401: bool = True
    refresh_window_seconds: int = 30
    expected_statuses: list[str] = Field(default_factory=lambda: ["2xx"])

    @model_validator(mode="after")
    def _validate_strategy_requirements(self) -> BuiltInAuthConfig:
        if self.request_json is not None and self.request_form:
            raise ValueError("Use only one of 'request_json' or 'request_form'.")

        if self.strategy == "static_bearer":
            if not self.token:
                raise ValueError("static_bearer auth requires 'token'.")
            return self

        if not self.endpoint:
            raise ValueError(f"{self.strategy} auth requires 'endpoint'.")

        if self.strategy == "login_form_cookie":
            return self

        if not self.token_pointer:
            raise ValueError(f"{self.strategy} auth requires 'token_pointer'.")
        return self


class AuthConfigFile(BaseModel):
    auth: list[BuiltInAuthConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_unique_names(self) -> AuthConfigFile:
        seen: set[str] = set()
        for config in self.auth:
            normalized = config.name.casefold()
            if normalized in seen:
                raise ValueError(f"Duplicate auth config name {config.name!r}.")
            seen.add(normalized)
        return self


def load_auth_configs(path: str | Path) -> AuthConfigFile:
    raw = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise ValueError("Auth config file must contain a top-level mapping.")
    try:
        return AuthConfigFile.model_validate(data)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def select_auth_configs(
    auth_file: AuthConfigFile,
    *,
    include_names: list[str] | None = None,
) -> list[BuiltInAuthConfig]:
    if not include_names:
        return list(auth_file.auth)

    selected: list[BuiltInAuthConfig] = []
    missing = list(include_names)
    for config in auth_file.auth:
        if config.name not in include_names:
            continue
        selected.append(config)
        if config.name in missing:
            missing.remove(config.name)

    if missing:
        raise ValueError("Unknown auth config name(s): " + ", ".join(sorted(missing)))
    return selected


def auth_config_map(configs: list[BuiltInAuthConfig]) -> dict[str, BuiltInAuthConfig]:
    return {config.name: config for config in configs}


def auth_profiles_from_configs(configs: list[BuiltInAuthConfig]) -> list[AuthProfile]:
    return [
        AuthProfile(
            name=config.name,
            level=config.level,
            anonymous=config.anonymous,
            description=config.description,
            headers=dict(config.headers),
            query=dict(config.query),
            auth_config=config.name,
        )
        for config in configs
    ]
