from __future__ import annotations

from knives_out.exporting import render_sarif_export
from knives_out.models import (
    AttackResult,
    AttackResults,
    ProfileAttackResult,
    WorkflowStepResult,
)


def test_render_sarif_export_emits_rest_metadata_without_fake_locations() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_rest",
                operation_id="createPet",
                kind="wrong_type_param",
                name="REST schema mismatch",
                method="POST",
                path="/pets",
                url="https://example.com/pets",
                status_code=200,
                flagged=True,
                issue="response_schema_mismatch",
                severity="medium",
                confidence="high",
                response_schema_valid=False,
                response_schema_error="$.id: expected integer, got string",
                workflow_steps=[
                    WorkflowStepResult(
                        name="Create cart",
                        operation_id="createCart",
                        method="POST",
                        url="https://example.com/cart",
                        status_code=201,
                    )
                ],
                profile_results=[
                    ProfileAttackResult(
                        profile="anonymous",
                        anonymous=True,
                        url="https://example.com/pets",
                        status_code=403,
                        flagged=True,
                        issue="anonymous_access",
                        severity="high",
                        confidence="medium",
                    )
                ],
            )
        ],
    )

    sarif = render_sarif_export(results)

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "knives-out"
    assert run["tool"]["driver"]["rules"][0]["id"] == "knives-out/response_schema_mismatch"
    result = run["results"][0]
    assert result["level"] == "warning"
    assert "locations" not in result
    assert result["properties"]["protocol"] == "rest"
    assert result["properties"]["schema_status"] == "mismatch"
    assert result["properties"]["response_schema_error"] == "$.id: expected integer, got string"
    assert result["properties"]["workflow_steps"][0]["name"] == "Create cart"
    assert result["properties"]["profile_results"][0]["profile"] == "anonymous"


def test_render_sarif_export_includes_graphql_metadata() -> None:
    results = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_graphql",
                operation_id="book",
                kind="wrong_type_variable",
                name="GraphQL shape mismatch",
                protocol="graphql",
                method="POST",
                path="/graphql",
                url="https://example.com/graphql",
                status_code=200,
                flagged=True,
                issue="graphql_response_shape_mismatch",
                severity="high",
                confidence="high",
                graphql_response_valid=False,
                graphql_response_error="$.data.book.title: expected String, got integer",
                graphql_response_hint="Schema appears federated.",
            )
        ],
    )

    sarif = render_sarif_export(results)

    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "knives-out/graphql_response_shape_mismatch"
    assert result["level"] == "error"
    assert result["properties"]["protocol"] == "graphql"
    assert result["properties"]["schema_status"] == "graphql-mismatch"
    assert (
        result["properties"]["graphql_response_error"]
        == "$.data.book.title: expected String, got integer"
    )
    assert result["properties"]["graphql_response_hint"] == "Schema appears federated."


def test_render_sarif_export_includes_baseline_change_metadata_for_active_findings() -> None:
    current = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_persisting",
                operation_id="createPet",
                kind="missing_request_body",
                name="Persisting failure",
                method="POST",
                path="/pets",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="critical",
                confidence="medium",
                response_schema_valid=False,
            ),
            AttackResult(
                attack_id="atk_new",
                operation_id="book",
                kind="wrong_type_variable",
                name="New GraphQL issue",
                protocol="graphql",
                method="POST",
                path="/graphql",
                url="https://example.com/graphql",
                status_code=200,
                flagged=True,
                issue="graphql_response_shape_mismatch",
                severity="high",
                confidence="high",
                graphql_response_valid=False,
            ),
        ],
    )
    baseline = AttackResults(
        source="unit",
        base_url="https://example.com",
        results=[
            AttackResult(
                attack_id="atk_persisting",
                operation_id="createPet",
                kind="missing_request_body",
                name="Persisting failure",
                method="POST",
                path="/pets",
                url="https://example.com/pets",
                status_code=401,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
                response_schema_valid=True,
            ),
            AttackResult(
                attack_id="atk_resolved",
                operation_id="deletePet",
                kind="missing_auth",
                name="Resolved issue",
                method="DELETE",
                path="/pets/1",
                url="https://example.com/pets/1",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            ),
        ],
    )

    sarif = render_sarif_export(current, baseline=baseline)

    exported = {result["properties"]["attack_id"]: result for result in sarif["runs"][0]["results"]}
    assert set(exported) == {"atk_new", "atk_persisting"}
    assert exported["atk_new"]["properties"]["change"] == "new"
    assert exported["atk_persisting"]["properties"]["change"] == "persisting"
    assert {
        change["field"] for change in exported["atk_persisting"]["properties"]["delta_changes"]
    } == {"confidence", "schema", "severity", "status"}
