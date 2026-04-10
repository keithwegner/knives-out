from __future__ import annotations

from pathlib import Path

import pytest

from knives_out.auth_config import (
    auth_config_map,
    auth_profiles_from_configs,
    load_auth_configs,
    select_auth_configs,
)


def test_load_auth_configs_reads_named_entries(tmp_path: Path) -> None:
    config_path = tmp_path / "auth.yml"
    config_path.write_text(
        "auth:\n"
        "  - name: user\n"
        "    strategy: static_bearer\n"
        "    token: user-token\n"
        "    level: 10\n"
        "  - name: admin\n"
        "    strategy: client_credentials\n"
        "    endpoint: /oauth/token\n"
        "    request_form:\n"
        "      grant_type: client_credentials\n"
        "    token_pointer: /access_token\n",
        encoding="utf-8",
    )

    auth_file = load_auth_configs(config_path)

    assert [config.name for config in auth_file.auth] == ["user", "admin"]
    assert auth_file.auth[1].endpoint == "/oauth/token"


def test_select_auth_configs_filters_named_entries(tmp_path: Path) -> None:
    config_path = tmp_path / "auth.yml"
    config_path.write_text(
        "auth:\n"
        "  - name: user\n"
        "    strategy: static_bearer\n"
        "    token: user-token\n"
        "  - name: admin\n"
        "    strategy: static_bearer\n"
        "    token: admin-token\n",
        encoding="utf-8",
    )
    auth_file = load_auth_configs(config_path)

    selected = select_auth_configs(auth_file, include_names=["admin"])

    assert [config.name for config in selected] == ["admin"]


def test_auth_profiles_from_configs_preserves_profile_metadata(tmp_path: Path) -> None:
    config_path = tmp_path / "auth.yml"
    config_path.write_text(
        "auth:\n"
        "  - name: anonymous\n"
        "    strategy: login_form_cookie\n"
        "    endpoint: /login\n"
        "    anonymous: true\n"
        "    level: 0\n"
        "    headers:\n"
        "      X-Trace-Id: trace-123\n",
        encoding="utf-8",
    )

    auth_file = load_auth_configs(config_path)
    profiles = auth_profiles_from_configs(auth_file.auth)

    assert profiles[0].name == "anonymous"
    assert profiles[0].auth_config == "anonymous"
    assert profiles[0].anonymous is True
    assert profiles[0].headers["X-Trace-Id"] == "trace-123"
    assert auth_config_map(auth_file.auth)["anonymous"].strategy == "login_form_cookie"


def test_load_auth_configs_validates_required_strategy_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "auth.yml"
    config_path.write_text(
        "auth:\n  - name: broken\n    strategy: static_bearer\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="static_bearer auth requires 'token'"):
        load_auth_configs(config_path)
