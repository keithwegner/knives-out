from __future__ import annotations

from pathlib import Path

import pytest

from knives_out.profiles import (
    load_auth_profiles,
    resolve_auth_profile_modules,
    select_auth_profiles,
)


def test_load_auth_profiles_reads_named_profiles(tmp_path: Path) -> None:
    profile_path = tmp_path / "profiles.yml"
    profile_path.write_text(
        "profiles:\n"
        "  - name: anonymous\n"
        "    anonymous: true\n"
        "    level: 0\n"
        "  - name: admin\n"
        "    level: 20\n"
        "    headers:\n"
        "      Authorization: Bearer admin\n",
        encoding="utf-8",
    )

    profiles_file = load_auth_profiles(profile_path)

    assert [profile.name for profile in profiles_file.profiles] == ["anonymous", "admin"]
    assert profiles_file.profiles[1].headers["Authorization"] == "Bearer admin"


def test_select_auth_profiles_filters_named_profiles(tmp_path: Path) -> None:
    profile_path = tmp_path / "profiles.yml"
    profile_path.write_text(
        "profiles:\n  - name: anonymous\n  - name: user\n  - name: admin\n",
        encoding="utf-8",
    )
    profiles_file = load_auth_profiles(profile_path)

    selected = select_auth_profiles(profiles_file, include_names=["user", "admin"])

    assert [profile.name for profile in selected] == ["user", "admin"]


def test_select_auth_profiles_reports_unknown_names(tmp_path: Path) -> None:
    profile_path = tmp_path / "profiles.yml"
    profile_path.write_text(
        "profiles:\n  - name: user\n",
        encoding="utf-8",
    )
    profiles_file = load_auth_profiles(profile_path)

    with pytest.raises(ValueError, match="Unknown auth profile name"):
        select_auth_profiles(profiles_file, include_names=["admin"])


def test_resolve_auth_profile_modules_uses_file_relative_paths(tmp_path: Path) -> None:
    module_dir = tmp_path / "plugins"
    module_dir.mkdir()
    module_path = module_dir / "auth_plugin.py"
    module_path.write_text("plugin = object()\n", encoding="utf-8")

    profile_path = tmp_path / "profiles.yml"
    profile_path.write_text(
        "profiles:\n  - name: user\n    auth_plugin_modules:\n      - plugins/auth_plugin.py\n",
        encoding="utf-8",
    )
    profiles_file = load_auth_profiles(profile_path)

    resolved = resolve_auth_profile_modules(profiles_file.profiles, relative_to=profile_path)

    assert resolved[0].auth_plugin_modules == [str(module_path.resolve())]
