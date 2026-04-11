from __future__ import annotations

import json
from pathlib import Path

from knives_out.graphql_loader import load_graphql_operations_with_warnings
from knives_out.learned_loader import load_learned_model_with_warnings
from knives_out.models import LoadedOperations
from knives_out.openapi_loader import load_operations_with_warnings as load_openapi_operations


def _looks_like_learned_model(path: Path) -> bool:
    if path.suffix.lower() != ".json":
        return False

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return False

    return isinstance(payload, dict) and payload.get("artifact_type") == "learned-model"


def _looks_like_graphql_introspection(path: Path) -> bool:
    if path.suffix.lower() != ".json":
        return False

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return False

    if not isinstance(payload, dict):
        return False
    if "__schema" in payload:
        return True
    data = payload.get("data")
    return isinstance(data, dict) and "__schema" in data


def is_graphql_schema_path(path: str | Path) -> bool:
    schema_path = Path(path)
    if schema_path.suffix.lower() in {".graphql", ".gql"}:
        return True
    return _looks_like_graphql_introspection(schema_path)


def is_learned_model_path(path: str | Path) -> bool:
    return _looks_like_learned_model(Path(path))


def load_operations_with_warnings(
    path: str | Path,
    *,
    graphql_endpoint: str = "/graphql",
) -> LoadedOperations:
    if is_learned_model_path(path):
        return load_learned_model_with_warnings(path)
    if is_graphql_schema_path(path):
        return load_graphql_operations_with_warnings(path, endpoint=graphql_endpoint)
    return load_openapi_operations(path)


def load_operations(
    path: str | Path,
    *,
    graphql_endpoint: str = "/graphql",
):
    return load_operations_with_warnings(path, graphql_endpoint=graphql_endpoint).operations
