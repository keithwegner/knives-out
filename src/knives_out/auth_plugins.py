from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import util
from importlib.metadata import entry_points
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx

from knives_out.models import WorkflowAttackCase

ENTRY_POINT_GROUP = "knives_out.auth_plugins"


@dataclass
class RuntimeContext:
    client: httpx.Client
    base_url: str
    scope: str
    state: dict[str, Any] = field(default_factory=dict)
    extracted_values: dict[str, Any] = field(default_factory=dict)
    workflow_id: str | None = None

    def build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return self.base_url.rstrip("/") + path


@dataclass
class PreparedRequest:
    phase: str
    attack_id: str
    name: str
    kind: str
    operation_id: str
    method: str
    path: str
    description: str
    path_params: dict[str, Any] = field(default_factory=dict)
    query: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body_json: Any | None = None
    raw_body: str | None = None
    content_type: str | None = None
    omit_body: bool = False
    omit_header_names: list[str] = field(default_factory=list)
    omit_query_names: list[str] = field(default_factory=list)


@dataclass
class RequestExecution:
    url: str
    headers: dict[str, str]
    query: dict[str, Any]
    response: httpx.Response | None
    error: str | None
    duration_ms: float
    resolution_error: bool = False


class PluginRuntimeError(RuntimeError):
    pass


class RuntimePlugin:
    def before_suite(self, context: RuntimeContext) -> None:
        return None

    def before_workflow(self, workflow: WorkflowAttackCase, context: RuntimeContext) -> None:
        return None

    def before_request(self, request: PreparedRequest, context: RuntimeContext) -> None:
        return None

    def after_request(
        self,
        request: PreparedRequest,
        context: RuntimeContext,
        execution: RequestExecution,
    ) -> None:
        return None

    def after_workflow(
        self,
        workflow: WorkflowAttackCase,
        context: RuntimeContext,
        result: Any,
    ) -> None:
        return None


WorkflowHook = RuntimePlugin


@dataclass(frozen=True)
class LoadedAuthPlugin:
    name: str
    plugin: RuntimePlugin


def make_auth_plugin(name: str, plugin: RuntimePlugin) -> LoadedAuthPlugin:
    return LoadedAuthPlugin(name=name, plugin=plugin)


def extract_json_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise ValueError(f"Invalid JSON pointer {pointer!r}.")

    current = value
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not token.isdigit():
                raise ValueError(f"Expected array index in JSON pointer {pointer!r}.")
            index = int(token)
            if index >= len(current):
                raise ValueError(f"JSON pointer {pointer!r} did not match the response body.")
            current = current[index]
        elif isinstance(current, dict):
            if token not in current:
                raise ValueError(f"JSON pointer {pointer!r} did not match the response body.")
            current = current[token]
        else:
            raise ValueError(f"JSON pointer {pointer!r} did not match the response body.")
    return current


AuthPluginFactory = Callable[[], RuntimePlugin | LoadedAuthPlugin]


def _module_name_for_path(module_path: Path) -> str:
    resolved = module_path.resolve()
    digest = abs(hash(str(resolved)))
    return f"knives_out_custom_auth_plugin_{digest}"


def _looks_like_runtime_plugin(candidate: object) -> bool:
    return any(
        callable(getattr(candidate, method_name, None))
        for method_name in (
            "before_suite",
            "before_workflow",
            "before_request",
            "after_request",
            "after_workflow",
        )
    )


def _coerce_auth_plugin(candidate: object, *, name_hint: str) -> LoadedAuthPlugin:
    if isinstance(candidate, LoadedAuthPlugin):
        return candidate
    if isinstance(candidate, RuntimePlugin):
        return make_auth_plugin(name_hint, candidate)
    if isinstance(candidate, type) and issubclass(candidate, RuntimePlugin):
        return make_auth_plugin(name_hint, candidate())
    if _looks_like_runtime_plugin(candidate):
        return make_auth_plugin(name_hint, candidate)
    if callable(candidate):
        built = candidate()
        if isinstance(built, LoadedAuthPlugin):
            return built
        if isinstance(built, RuntimePlugin) or _looks_like_runtime_plugin(built):
            return make_auth_plugin(name_hint, built)

    raise ValueError(
        f"Auth plugin {name_hint!r} must be a RuntimePlugin, plugin-like object, "
        "or zero-argument factory returning one."
    )


def _auth_plugin_from_module(module: ModuleType, *, name_hint: str) -> LoadedAuthPlugin:
    if hasattr(module, "auth_plugin"):
        return _coerce_auth_plugin(module.auth_plugin, name_hint=name_hint)
    if hasattr(module, "plugin"):
        return _coerce_auth_plugin(module.plugin, name_hint=name_hint)
    if hasattr(module, "build_plugin"):
        return _coerce_auth_plugin(module.build_plugin, name_hint=name_hint)
    raise ValueError(
        f"Auth plugin module {name_hint!r} must define 'auth_plugin', 'plugin', or 'build_plugin'."
    )


def load_entry_point_auth_plugins(names: list[str] | None) -> list[LoadedAuthPlugin]:
    if not names:
        return []

    selected_entry_points = {
        entry_point.name: entry_point
        for entry_point in entry_points().select(group=ENTRY_POINT_GROUP)
    }
    loaded: list[LoadedAuthPlugin] = []
    for name in names:
        entry_point = selected_entry_points.get(name)
        if entry_point is None:
            raise ValueError(
                f"Unknown auth plugin entry point {name!r}. "
                f"Install a package exposing [{ENTRY_POINT_GROUP}] {name}."
            )
        loaded.append(_coerce_auth_plugin(entry_point.load(), name_hint=name))
    return loaded


def load_module_auth_plugins(module_paths: list[Path] | None) -> list[LoadedAuthPlugin]:
    if not module_paths:
        return []

    loaded: list[LoadedAuthPlugin] = []
    for module_path in module_paths:
        if not module_path.exists():
            raise ValueError(f"Auth plugin module path does not exist: {module_path}")

        spec = util.spec_from_file_location(_module_name_for_path(module_path), module_path)
        if spec is None or spec.loader is None:
            raise ValueError(f"Could not load auth plugin module from: {module_path}")

        module = util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"Failed to import auth plugin module {module_path}: {exc}") from exc

        loaded.append(_auth_plugin_from_module(module, name_hint=module_path.stem))
    return loaded


def load_auth_plugins(
    *,
    entry_point_names: list[str] | None = None,
    module_paths: list[Path] | None = None,
) -> list[LoadedAuthPlugin]:
    return load_entry_point_auth_plugins(entry_point_names) + load_module_auth_plugins(module_paths)
