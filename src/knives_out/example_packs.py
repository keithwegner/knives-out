from __future__ import annotations

from copy import deepcopy

from knives_out.attack_packs import make_attack_pack
from knives_out.generator import attack_id, base_request_context
from knives_out.models import AttackCase, OperationSpec


def generate_unexpected_header_attack(operation: OperationSpec) -> list[AttackCase]:
    path_params, query, headers, body = base_request_context(operation)
    headers["X-Knives-Out-Probe"] = "unexpected-header"

    return [
        AttackCase(
            id=attack_id(operation.operation_id, "unexpected_header", "header:X-Knives-Out-Probe"),
            name="Unexpected header probe",
            kind="unexpected_header",
            operation_id=operation.operation_id,
            method=operation.method,
            path=operation.path,
            tags=list(operation.tags),
            auth_required=operation.auth_required,
            description="Adds an unexpected header to probe strict header handling.",
            path_params=path_params,
            query=query,
            headers=headers,
            body_json=body,
            response_schemas=deepcopy(operation.response_schemas),
        )
    ]


attack_pack = make_attack_pack("unexpected-header", generate_unexpected_header_attack)
