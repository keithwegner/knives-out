from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points
from inspect import isclass
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from knives_out.api_models import EditionStatus

if TYPE_CHECKING:
    import typer
    from fastapi import FastAPI

EXTENSION_ENTRY_POINT_GROUP = "knives_out.extensions"


@dataclass(frozen=True)
class LoadedExtension:
    name: str
    plugin: Any


@dataclass(frozen=True)
class ExtensionLoadResult:
    extensions: list[LoadedExtension]
    errors: list[str]


def _iter_extension_entry_points() -> list[EntryPoint]:
    discovered = entry_points()
    if hasattr(discovered, "select"):
        return list(discovered.select(group=EXTENSION_ENTRY_POINT_GROUP))
    return list(discovered.get(EXTENSION_ENTRY_POINT_GROUP, []))


def _load_extension(entry_point: EntryPoint) -> LoadedExtension:
    plugin = entry_point.load()
    has_extension_methods = (
        hasattr(plugin, "register_api")
        or hasattr(plugin, "register_cli")
        or hasattr(plugin, "edition_status")
    )
    if isclass(plugin) or (callable(plugin) and not has_extension_methods):
        plugin = plugin()
    return LoadedExtension(name=getattr(plugin, "name", entry_point.name), plugin=plugin)


def load_extensions() -> ExtensionLoadResult:
    extensions: list[LoadedExtension] = []
    errors: list[str] = []
    for entry_point in _iter_extension_entry_points():
        try:
            extensions.append(_load_extension(entry_point))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{entry_point.name}: {exc}")
    return ExtensionLoadResult(extensions=extensions, errors=errors)


def free_edition_status(*, extension_errors: list[str] | None = None) -> EditionStatus:
    message = "Running the MIT Free edition."
    if extension_errors:
        message = "Running the MIT Free edition; one or more extensions failed to load."
    return EditionStatus(extension_errors=extension_errors or [], message=message)


def edition_status_for_extensions(
    extensions: list[LoadedExtension],
    *,
    extension_errors: list[str] | None = None,
) -> EditionStatus:
    for extension in extensions:
        provider = getattr(extension.plugin, "edition_status", None)
        if not callable(provider):
            continue
        try:
            status = provider()
        except Exception as exc:  # noqa: BLE001
            errors = [*(extension_errors or []), f"{extension.name}: {exc}"]
            return free_edition_status(extension_errors=errors)
        if status is None:
            continue
        try:
            parsed = EditionStatus.model_validate(status)
        except ValidationError as exc:
            errors = [*(extension_errors or []), f"{extension.name}: {exc}"]
            return free_edition_status(extension_errors=errors)
        if extension_errors:
            return parsed.model_copy(
                update={"extension_errors": [*parsed.extension_errors, *extension_errors]}
            )
        return parsed
    return free_edition_status(extension_errors=extension_errors)


def register_api_extensions(app: FastAPI) -> ExtensionLoadResult:
    loaded = load_extensions()
    app.state.knives_out_extensions = loaded.extensions
    app.state.knives_out_extension_errors = loaded.errors
    for extension in loaded.extensions:
        register = getattr(extension.plugin, "register_api", None)
        if not callable(register):
            continue
        try:
            register(app)
        except Exception as exc:  # noqa: BLE001
            loaded.errors.append(f"{extension.name}: {exc}")
    return loaded


def register_cli_extensions(app: typer.Typer) -> ExtensionLoadResult:
    loaded = load_extensions()
    for extension in loaded.extensions:
        register = getattr(extension.plugin, "register_cli", None)
        if not callable(register):
            continue
        try:
            register(app)
        except Exception as exc:  # noqa: BLE001
            loaded.errors.append(f"{extension.name}: {exc}")
    return loaded
