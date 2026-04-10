from __future__ import annotations

from pathlib import Path

from knives_out.attack_packs import load_module_attack_packs
from knives_out.auth_plugins import load_module_auth_plugins
from knives_out.generator import generate_attack_suite
from knives_out.profiles import load_auth_profiles
from knives_out.spec_loader import load_operations
from knives_out.workflow_packs import load_module_workflow_packs

ROOT = Path(__file__).resolve().parents[1]
PETSTORE_SPEC = ROOT / "examples" / "openapi" / "petstore.yaml"
STOREFRONT_SPEC = ROOT / "examples" / "openapi" / "storefront.yaml"
GRAPHQL_SPEC = ROOT / "examples" / "graphql" / "library.graphql"
ATTACK_PACK_MODULE = ROOT / "examples" / "custom_packs" / "unexpected_header.py"
WORKFLOW_PACK_MODULE = ROOT / "examples" / "workflow_packs" / "listed_pet_lookup.py"
AUTH_PLUGIN_MODULE = ROOT / "examples" / "auth_plugins" / "login_bearer.py"
AUTH_PROFILE_FILE = ROOT / "examples" / "auth_profiles" / "anonymous-user-admin.yml"


def test_checked_in_openapi_examples_load() -> None:
    for spec in (PETSTORE_SPEC, STOREFRONT_SPEC):
        operations = load_operations(spec)
        assert operations


def test_checked_in_graphql_example_loads() -> None:
    operations = load_operations(GRAPHQL_SPEC)

    assert {operation.operation_id for operation in operations} == {
        "book",
        "books",
        "createBook",
        "rateBook",
    }


def test_storefront_example_emits_workflows_and_schema_mutations() -> None:
    suite = generate_attack_suite(
        load_operations(STOREFRONT_SPEC),
        source=str(STOREFRONT_SPEC),
        auto_workflows=True,
    )

    assert any(attack.kind == "too_long" for attack in suite.attacks)
    assert any(attack.kind == "invalid_format" for attack in suite.attacks)
    assert any(
        attack.type == "workflow" and attack.operation_id == "getDraftOrder"
        for attack in suite.attacks
    )


def test_graphql_example_emits_graphql_variable_attacks() -> None:
    suite = generate_attack_suite(
        load_operations(GRAPHQL_SPEC),
        source=str(GRAPHQL_SPEC),
    )

    assert any(attack.kind == "wrong_type_variable" for attack in suite.attacks)
    assert any(attack.kind == "missing_required_variable" for attack in suite.attacks)


def test_checked_in_example_modules_load() -> None:
    attack_packs = load_module_attack_packs([ATTACK_PACK_MODULE])
    workflow_packs = load_module_workflow_packs([WORKFLOW_PACK_MODULE])
    auth_plugins = load_module_auth_plugins([AUTH_PLUGIN_MODULE])

    assert [pack.name for pack in attack_packs] == ["unexpected-header"]
    assert [pack.name for pack in workflow_packs] == ["listed-id-lookup"]
    assert [plugin.name for plugin in auth_plugins] == ["login-bearer"]


def test_checked_in_auth_profile_example_loads() -> None:
    profiles_file = load_auth_profiles(AUTH_PROFILE_FILE)

    assert [profile.name for profile in profiles_file.profiles] == [
        "anonymous",
        "user",
        "admin",
    ]
