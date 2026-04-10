from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import httpx
import pytest

from knives_out.auth_plugins import (
    ENTRY_POINT_GROUP,
    PreparedRequest,
    RuntimeContext,
    RuntimePlugin,
    load_auth_plugins,
    load_entry_point_auth_plugins,
    load_module_auth_plugins,
    make_auth_plugin,
)


def test_load_module_auth_plugins_supports_local_modules(tmp_path: Path) -> None:
    module_path = tmp_path / "custom_auth_plugin.py"
    module_path.write_text(
        dedent(
            """
            from knives_out.auth_plugins import RuntimePlugin, make_auth_plugin

            class ModulePlugin(RuntimePlugin):
                def before_request(self, request, context):
                    request.headers["Authorization"] = "Bearer module-token"

            auth_plugin = make_auth_plugin("module-auth-plugin", ModulePlugin())
            """
        ),
        encoding="utf-8",
    )

    plugins = load_module_auth_plugins([module_path])

    assert [plugin.name for plugin in plugins] == ["module-auth-plugin"]


def test_load_module_auth_plugins_reports_import_failures(tmp_path: Path) -> None:
    module_path = tmp_path / "broken_auth_plugin.py"
    module_path.write_text("raise RuntimeError('boom')\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Failed to import auth plugin module"):
        load_module_auth_plugins([module_path])


def test_load_entry_point_auth_plugins_supports_registered_names(monkeypatch) -> None:
    class ExamplePlugin(RuntimePlugin):
        pass

    class _FakeEntryPoint:
        def __init__(self, name: str) -> None:
            self.name = name

        def load(self):
            return make_auth_plugin(self.name, ExamplePlugin())

    class _FakeEntryPoints:
        def select(self, *, group: str):
            assert group == ENTRY_POINT_GROUP
            return [_FakeEntryPoint("example-auth-plugin")]

    monkeypatch.setattr("knives_out.auth_plugins.entry_points", lambda: _FakeEntryPoints())

    plugins = load_entry_point_auth_plugins(["example-auth-plugin"])

    assert [plugin.name for plugin in plugins] == ["example-auth-plugin"]


def test_load_auth_plugins_raises_for_missing_entry_point() -> None:
    with pytest.raises(ValueError, match="Unknown auth plugin entry point"):
        load_auth_plugins(entry_point_names=["missing-auth-plugin"])


def test_load_auth_plugins_supports_project_entry_point(monkeypatch) -> None:
    monkeypatch.setenv("KNIVES_OUT_BEARER_TOKEN", "dev-token")
    plugins = load_auth_plugins(entry_point_names=["env-bearer"])

    request = PreparedRequest(
        phase="request",
        attack_id="atk_test",
        name="Test attack",
        kind="missing_auth",
        operation_id="listPets",
        method="GET",
        path="/pets",
        description="Test attack",
    )

    with httpx.Client() as client:
        context = RuntimeContext(
            client=client,
            base_url="https://example.com",
            scope="suite",
        )
        plugins[0].plugin.before_request(request, context)

    assert request.headers["Authorization"] == "Bearer dev-token"
