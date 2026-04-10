from __future__ import annotations

from copy import deepcopy

from knives_out.attack_packs import make_attack_pack
from knives_out.generator import attack_id, base_request_context
from knives_out.models import AttackCase, OperationSpec


def generate(operation: OperationSpec) -> list[AttackCase]:
    path_params, query, headers, body = base_request_context(operation)
    headers["X-Example-Custom-Pack"] = "unexpected-header"

    return [
        AttackCase(
            id=attack_id(
                operation.operation_id,
                "unexpected_header",
                "header:X-Example-Custom-Pack",
            ),
            name="Unexpected header probe",
            kind="unexpected_header",
            operation_id=operation.operation_id,
            method=operation.method,
            path=operation.path,
            description="Adds an unexpected header to probe strict header handling.",
            path_params=path_params,
            query=query,
            headers=headers,
            body_json=body,
            response_schemas=deepcopy(operation.response_schemas),
        )
    ]


attack_pack = make_attack_pack("unexpected-header", generate)
