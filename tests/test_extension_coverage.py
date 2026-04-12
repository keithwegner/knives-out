from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from knives_out.attack_packs import (
    _attack_pack_from_module,
    _coerce_attack_pack,
    load_module_attack_packs,
)
from knives_out.attack_packs import (
    _module_name_for_path as attack_pack_module_name,
)
from knives_out.auth_plugins import (
    _auth_plugin_from_module,
    _coerce_auth_plugin,
    _looks_like_runtime_plugin,
    extract_json_pointer,
    load_module_auth_plugins,
)
from knives_out.auth_plugins import (
    _module_name_for_path as auth_plugin_module_name,
)
from knives_out.example_packs import generate_unexpected_header_attack
from knives_out.example_workflow_packs import generate_listed_id_lookup_workflows
from knives_out.models import AttackCase, LoadedOperations, OperationSpec
from knives_out.spec_loader import (
    is_graphql_schema_path,
    is_learned_model_path,
    load_operations_with_warnings,
)
from knives_out.workflow_packs import (
    _coerce_workflow_pack,
    _workflow_pack_from_module,
    load_module_workflow_packs,
)
from knives_out.workflow_packs import (
    _module_name_for_path as workflow_pack_module_name,
)


class _PluginLike:
    def before_request(self, request, context) -> None:
        request.headers["Authorization"] = "Bearer plugin-like"


def _operation() -> OperationSpec:
    return OperationSpec(
        operation_id="getPet",
        method="GET",
        path="/pets/{petId}",
        tags=["pets"],
        auth_required=True,
    )


def test_module_name_helpers_are_stable_for_same_path(tmp_path: Path) -> None:
    module_path = tmp_path / "plugin.py"
    module_path.write_text("", encoding="utf-8")

    assert attack_pack_module_name(module_path) == attack_pack_module_name(module_path)
    assert workflow_pack_module_name(module_path) == workflow_pack_module_name(module_path)
    assert auth_plugin_module_name(module_path) == auth_plugin_module_name(module_path)


def test_attack_pack_coercion_supports_callable_and_object_generate() -> None:
    callable_pack = _coerce_attack_pack(
        lambda operation: [
            {
                "id": f"atk_{operation.operation_id}_callable",
                "name": "Callable pack",
                "kind": "callable_probe",
                "operation_id": operation.operation_id,
                "method": operation.method,
                "path": operation.path,
                "description": "Callable pack",
            }
        ],
        name_hint="callable-pack",
    )

    class _ObjectPack:
        name = "object-pack"

        def generate(self, operation: OperationSpec):
            return [
                {
                    "id": f"atk_{operation.operation_id}_object",
                    "name": "Object pack",
                    "kind": "object_probe",
                    "operation_id": operation.operation_id,
                    "method": operation.method,
                    "path": operation.path,
                    "description": "Object pack",
                }
            ]

    object_pack = _coerce_attack_pack(_ObjectPack(), name_hint="fallback-name")

    assert callable_pack.generate(_operation())[0].kind == "callable_probe"
    assert object_pack.name == "object-pack"
    assert object_pack.generate(_operation())[0].kind == "object_probe"


def test_attack_pack_loader_validates_paths_and_module_shape(tmp_path: Path, monkeypatch) -> None:
    missing_path = tmp_path / "missing.py"
    with pytest.raises(ValueError, match="Attack pack module path does not exist"):
        load_module_attack_packs([missing_path])

    invalid_module = tmp_path / "invalid_pack.py"
    invalid_module.write_text("value = 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must define 'attack_pack' or 'generate'"):
        load_module_attack_packs([invalid_module])

    module_path = tmp_path / "pack.py"
    module_path.write_text("attack_pack = 1\n", encoding="utf-8")
    monkeypatch.setattr("knives_out.attack_packs.util.spec_from_file_location", lambda *args: None)
    with pytest.raises(ValueError, match="Could not load attack pack module"):
        load_module_attack_packs([module_path])


def test_attack_pack_module_supports_generate_export_and_invalid_values() -> None:
    module = type(
        "GenerateModule",
        (),
        {
            "generate": lambda operation: [
                {
                    "id": "atk_generate",
                    "name": "Generate export",
                    "kind": "generate_probe",
                    "operation_id": operation.operation_id,
                    "method": operation.method,
                    "path": operation.path,
                    "description": "Generate export",
                }
            ]
        },
    )

    loaded = _attack_pack_from_module(module, name_hint="generate-module")

    assert loaded.generate(_operation())[0].kind == "generate_probe"
    with pytest.raises(ValueError, match="must be a callable"):
        _coerce_attack_pack(1, name_hint="invalid")


def test_workflow_pack_coercion_supports_callable_and_object_generate() -> None:
    request_attack = generate_unexpected_header_attack(_operation())[0]
    callable_pack = _coerce_workflow_pack(
        lambda operations, request_attacks: [
            {
                "id": "wf_callable",
                "name": "Callable workflow",
                "kind": request_attacks[0].kind,
                "operation_id": request_attacks[0].operation_id,
                "method": request_attacks[0].method,
                "path": request_attacks[0].path,
                "description": "Callable workflow",
                "terminal_attack": request_attacks[0],
            }
        ],
        name_hint="callable-workflow",
    )

    class _ObjectWorkflowPack:
        name = "object-workflow"

        def generate(self, operations, request_attacks):
            return [
                {
                    "id": "wf_object",
                    "name": "Object workflow",
                    "kind": request_attacks[0].kind,
                    "operation_id": request_attacks[0].operation_id,
                    "method": request_attacks[0].method,
                    "path": request_attacks[0].path,
                    "description": "Object workflow",
                    "terminal_attack": request_attacks[0],
                }
            ]

    object_pack = _coerce_workflow_pack(_ObjectWorkflowPack(), name_hint="fallback-workflow")

    assert callable_pack.generate([_operation()], [request_attack])[0].type == "workflow"
    assert object_pack.name == "object-workflow"
    assert object_pack.generate([_operation()], [request_attack])[0].type == "workflow"


def test_workflow_pack_loader_validates_paths_and_module_shape(tmp_path: Path, monkeypatch) -> None:
    missing_path = tmp_path / "missing.py"
    with pytest.raises(ValueError, match="Workflow pack module path does not exist"):
        load_module_workflow_packs([missing_path])

    invalid_module = tmp_path / "invalid_pack.py"
    invalid_module.write_text("value = 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must define 'workflow_pack' or 'generate'"):
        load_module_workflow_packs([invalid_module])

    module_path = tmp_path / "pack.py"
    module_path.write_text("workflow_pack = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        "knives_out.workflow_packs.util.spec_from_file_location",
        lambda *args: None,
    )
    with pytest.raises(ValueError, match="Could not load workflow pack module"):
        load_module_workflow_packs([module_path])


def test_workflow_pack_module_supports_generate_export_and_invalid_values() -> None:
    request_attack = generate_unexpected_header_attack(_operation())[0]
    module = type(
        "GenerateWorkflowModule",
        (),
        {
            "generate": lambda operations, request_attacks: [
                {
                    "id": "wf_generate",
                    "name": "Generate workflow export",
                    "kind": request_attacks[0].kind,
                    "operation_id": request_attacks[0].operation_id,
                    "method": request_attacks[0].method,
                    "path": request_attacks[0].path,
                    "description": "Generate workflow export",
                    "terminal_attack": request_attacks[0],
                }
            ]
        },
    )

    loaded = _workflow_pack_from_module(module, name_hint="generate-workflow-module")

    assert loaded.generate([_operation()], [request_attack])[0].type == "workflow"
    with pytest.raises(ValueError, match="must be a callable"):
        _coerce_workflow_pack(1, name_hint="invalid")


def test_auth_plugin_utilities_cover_pointer_and_plugin_coercion() -> None:
    payload = {"a/b": {"~key": 3}, "items": [1, {"id": 7}]}

    assert extract_json_pointer(payload, "") == payload
    assert extract_json_pointer({"a/b": {"~key": 3}}, "/a~1b/~0key") == 3
    assert extract_json_pointer({"items": [1, {"id": 7}]}, "/items/1/id") == 7
    with pytest.raises(ValueError, match="Invalid JSON pointer"):
        extract_json_pointer({}, "id")
    with pytest.raises(ValueError, match="Expected array index"):
        extract_json_pointer(["x"], "/value")
    with pytest.raises(ValueError, match="did not match the response body"):
        extract_json_pointer({"items": []}, "/items/0")
    with pytest.raises(ValueError, match="did not match the response body"):
        extract_json_pointer("x", "/value")

    assert _looks_like_runtime_plugin(_PluginLike()) is True
    loaded = _coerce_auth_plugin(_PluginLike(), name_hint="plugin-like")
    assert loaded.name == "plugin-like"
    assert _coerce_auth_plugin(loaded.plugin, name_hint="runtime-plugin").name == "runtime-plugin"

    class _PluginSubclass(_PluginLike):
        pass

    subclass_loaded = _coerce_auth_plugin(_PluginSubclass, name_hint="plugin-subclass")
    assert subclass_loaded.name == "plugin-subclass"

    def _factory():
        return loaded

    built = _coerce_auth_plugin(_factory, name_hint="factory")
    assert built is loaded

    with pytest.raises(ValueError, match="must be a RuntimePlugin"):
        _coerce_auth_plugin(object(), name_hint="invalid")


def test_auth_plugin_loader_validates_paths_and_module_shape(tmp_path: Path, monkeypatch) -> None:
    missing_path = tmp_path / "missing.py"
    with pytest.raises(ValueError, match="Auth plugin module path does not exist"):
        load_module_auth_plugins([missing_path])

    invalid_module = tmp_path / "invalid_plugin.py"
    invalid_module.write_text("value = 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must define 'auth_plugin', 'plugin', or 'build_plugin'"):
        load_module_auth_plugins([invalid_module])

    module_path = tmp_path / "plugin.py"
    module_path.write_text("plugin = 1\n", encoding="utf-8")
    monkeypatch.setattr("knives_out.auth_plugins.util.spec_from_file_location", lambda *args: None)
    with pytest.raises(ValueError, match="Could not load auth plugin module"):
        load_module_auth_plugins([module_path])


def test_auth_plugin_from_module_supports_plugin_and_factory_exports() -> None:
    plugin_module = type("PluginModule", (), {"plugin": _PluginLike()})
    loaded_plugin = _auth_plugin_from_module(plugin_module, name_hint="plugin-module")
    assert loaded_plugin.name == "plugin-module"

    factory_module = type(
        "FactoryModule",
        (),
        {
            "build_plugin": lambda: _PluginLike(),
        },
    )
    loaded_factory = _auth_plugin_from_module(factory_module, name_hint="factory-module")
    assert loaded_factory.name == "factory-module"


def test_example_attack_pack_adds_probe_header_without_mutating_operation() -> None:
    operation = OperationSpec(
        operation_id="getPet",
        method="GET",
        path="/pets/{petId}",
        observed_examples=[
            {
                "headers": {"Authorization": "Bearer keep-me"},
            }
        ],
    )

    attack = generate_unexpected_header_attack(operation)[0]

    assert attack.headers["X-Knives-Out-Probe"] == "unexpected-header"
    assert operation.observed_examples[0].headers == {"Authorization": "Bearer keep-me"}


def test_example_workflow_pack_generates_lookup_workflow_and_skips_non_matching_attacks() -> None:
    operations = [
        OperationSpec(operation_id="listPets", method="GET", path="/pets"),
        _operation(),
    ]
    matching = AttackCase(
        id="atk_get_pet",
        name="Get pet",
        kind="wrong_type_param",
        operation_id="getPet",
        method="GET",
        path="/pets/{petId}",
        tags=["pets"],
        auth_required=True,
        description="Get pet",
        path_params={"petId": "123"},
    )
    ignored = AttackCase(
        id="atk_other",
        name="Other",
        kind="wrong_type_param",
        operation_id="listPets",
        method="GET",
        path="/pets",
        description="Other",
    )

    workflows = generate_listed_id_lookup_workflows(operations, [matching, ignored])

    assert len(workflows) == 1
    workflow = workflows[0]
    assert workflow.setup_steps[0].extracts[0].json_pointer == "/0/id"
    assert workflow.terminal_attack.path_params["petId"] == "{{id}}"
    assert matching.path_params["petId"] == "123"


def test_example_workflow_pack_returns_empty_when_no_producer_exists() -> None:
    workflows = generate_listed_id_lookup_workflows(
        [_operation()],
        [generate_unexpected_header_attack(_operation())[0]],
    )

    assert workflows == []


def test_spec_loader_detects_known_input_types_and_routes(monkeypatch, tmp_path: Path) -> None:
    learned_path = tmp_path / "learned.json"
    learned_path.write_text(json.dumps({"artifact_type": "learned-model"}), encoding="utf-8")
    graphql_path = tmp_path / "schema.json"
    graphql_path.write_text(json.dumps({"data": {"__schema": {}}}), encoding="utf-8")
    invalid_path = tmp_path / "broken.json"
    invalid_path.write_text("{", encoding="utf-8")

    assert is_learned_model_path(learned_path) is True
    assert is_graphql_schema_path(graphql_path) is True
    assert is_graphql_schema_path(tmp_path / "schema.graphql") is True
    assert is_graphql_schema_path(invalid_path) is False

    learned_result = LoadedOperations(operations=[])
    graphql_result = LoadedOperations(source_kind="graphql", operations=[])
    openapi_result = LoadedOperations(operations=[])

    monkeypatch.setattr(
        "knives_out.spec_loader.load_learned_model_with_warnings",
        lambda path: learned_result,
    )
    monkeypatch.setattr(
        "knives_out.spec_loader.load_graphql_operations_with_warnings",
        lambda path, endpoint: graphql_result,
    )
    monkeypatch.setattr(
        "knives_out.spec_loader.load_openapi_operations",
        lambda path: openapi_result,
    )

    openapi_path = tmp_path / "spec.yaml"
    openapi_path.write_text(
        "openapi: 3.1.0\ninfo:\n  title: Demo\n  version: 1.0.0\npaths: {}\n",
        encoding="utf-8",
    )

    assert load_operations_with_warnings(learned_path) is learned_result
    assert (
        load_operations_with_warnings(graphql_path, graphql_endpoint="/api/graphql")
        is graphql_result
    )
    assert load_operations_with_warnings(openapi_path) is openapi_result


def test_runtime_context_build_url_handles_relative_and_absolute_urls() -> None:
    from knives_out.auth_plugins import RuntimeContext

    context = RuntimeContext(client=httpx.Client(), base_url="https://example.com/", scope="suite")

    assert context.build_url("/pets") == "https://example.com/pets"
    assert context.build_url("https://other.example.com/pets") == "https://other.example.com/pets"
