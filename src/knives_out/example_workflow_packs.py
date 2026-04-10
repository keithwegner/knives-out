from __future__ import annotations

from knives_out.generator import attack_id, base_request_context
from knives_out.models import (
    AttackCase,
    ExtractRule,
    OperationSpec,
    WorkflowAttackCase,
    WorkflowStep,
)
from knives_out.workflow_packs import make_workflow_pack


def generate_listed_id_lookup_workflows(
    operations: list[OperationSpec],
    request_attacks: list[AttackCase],
) -> list[WorkflowAttackCase]:
    producer = next(
        (operation for operation in operations if operation.operation_id == "listPets"), None
    )
    if producer is None:
        return []

    path_params, query, headers, body = base_request_context(producer)
    workflows: list[WorkflowAttackCase] = []
    for attack in request_attacks:
        if attack.operation_id != "getPet" or "petId" not in attack.path_params:
            continue

        terminal_attack = attack.model_copy(deep=True)
        terminal_attack.path_params["petId"] = "{{id}}"
        workflows.append(
            WorkflowAttackCase(
                id=attack_id(
                    attack.operation_id,
                    f"workflow_{attack.kind}",
                    f"{producer.operation_id}:{attack.id}",
                ),
                name=f"Listed id lookup workflow: {attack.name}",
                kind=attack.kind,
                operation_id=attack.operation_id,
                method=attack.method,
                path=attack.path,
                description=(
                    "Lists pets, extracts the first item id, then reuses that value "
                    "when executing the terminal attack."
                ),
                setup_steps=[
                    WorkflowStep(
                        name="List pets for setup",
                        operation_id=producer.operation_id,
                        method=producer.method,
                        path=producer.path,
                        path_params=path_params,
                        query=query,
                        headers=headers,
                        body_json=body,
                        extracts=[ExtractRule(name="id", json_pointer="/0/id")],
                    )
                ],
                terminal_attack=terminal_attack,
            )
        )

    return workflows


workflow_pack = make_workflow_pack("listed-id-lookup", generate_listed_id_lookup_workflows)
