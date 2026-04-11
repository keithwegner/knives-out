from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha1
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from knives_out.capture import (
    read_capture_events,
    redact_body,
    redact_headers,
    redact_query,
)
from knives_out.models import (
    CapturedRequest,
    CapturedResponse,
    CaptureEvent,
    LearnedBinding,
    LearnedModel,
    LearnedWorkflow,
    ObservedRequestExample,
    OperationSpec,
    ParameterSpec,
    PreflightWarning,
    ResponseSpec,
)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATE_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URI_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_GENERIC_VALUES = {"example", "__invalid__", "__invalid_enum__", "true", "false"}
_COMMON_HEADERS = {
    "accept",
    "accept-encoding",
    "connection",
    "content-length",
    "content-type",
    "host",
    "origin",
    "referer",
    "user-agent",
}
_VARIABLE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{2,}$")
_PATH_PARAM_RE = re.compile(r"^\{([^{}]+)\}$")


@dataclass(frozen=True)
class _PreparedEvent:
    index: int
    event: CaptureEvent
    method: str
    raw_path: str
    path_segments: tuple[str, ...]
    query: dict[str, Any]
    headers: dict[str, str]
    body_json: Any | None
    raw_body: str | None
    content_type: str | None
    response_json: Any | None
    response_content_type: str | None
    response_status: int | None
    identity_context: str | None


@dataclass(frozen=True)
class _WorkflowEvidence:
    producer_operation_id: str
    consumer_operation_id: str
    source_name: str
    source_pointer: str
    target: str
    target_name: str
    count: int
    exact_name_matches: int


def _load_har_entries(path: Path) -> list[CaptureEvent]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = payload.get("log", {}).get("entries", [])
    events: list[CaptureEvent] = []
    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        request_headers = {
            item.get("name", ""): item.get("value", "")
            for item in request.get("headers", [])
            if item.get("name")
        }
        query = {
            item.get("name", ""): item.get("value", "")
            for item in request.get("queryString", [])
            if item.get("name")
        }
        post_data = request.get("postData", {})
        raw_request_body = post_data.get("text")
        request_body_json = None
        if raw_request_body:
            try:
                request_body_json = json.loads(raw_request_body)
            except ValueError:
                request_body_json = None
        sanitized_headers, header_identity = redact_headers(request_headers)
        sanitized_query, query_identity = redact_query(query)
        if request_body_json is not None:
            request_body_json = redact_body(request_body_json)

        response_headers = {
            item.get("name", ""): item.get("value", "")
            for item in response.get("headers", [])
            if item.get("name")
        }
        response_content = response.get("content", {})
        raw_response_body = response_content.get("text")
        response_body_json = None
        if raw_response_body:
            try:
                response_body_json = json.loads(raw_response_body)
            except ValueError:
                response_body_json = None
        sanitized_response_headers, _ = redact_headers(response_headers)
        if response_body_json is not None:
            response_body_json = redact_body(response_body_json)

        started_at = entry.get("startedDateTime")
        captured_at = (
            datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            if started_at
            else datetime.now(UTC)
        )
        events.append(
            CaptureEvent(
                source="har",
                captured_at=captured_at,
                identity_context=header_identity or query_identity,
                request=CapturedRequest(
                    method=request.get("method", "GET"),
                    url=request.get("url", ""),
                    headers=sanitized_headers,
                    query=sanitized_query,
                    body_json=request_body_json,
                    raw_body=raw_request_body if request_body_json is None else None,
                    content_type=post_data.get("mimeType"),
                ),
                response=CapturedResponse(
                    status_code=response.get("status"),
                    headers=sanitized_response_headers,
                    body_json=response_body_json,
                    raw_body=raw_response_body if response_body_json is None else None,
                    content_type=response_content.get("mimeType"),
                    duration_ms=entry.get("time"),
                ),
            )
        )
    return events


def load_capture_inputs(paths: list[str | Path]) -> list[CaptureEvent]:
    events: list[CaptureEvent] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.suffix.lower() == ".har":
            events.extend(_load_har_entries(path))
            continue

        text = path.read_text(encoding="utf-8")
        stripped = text.lstrip()
        if stripped.startswith("{"):
            payload = json.loads(text)
            if isinstance(payload, dict) and payload.get("log", {}).get("entries") is not None:
                events.extend(_load_har_entries(path))
                continue
        events.extend(read_capture_events(path))
    return events


def _path_segments(path: str) -> tuple[str, ...]:
    stripped = path.strip("/")
    if not stripped:
        return ()
    return tuple(segment for segment in stripped.split("/") if segment)


def _looks_numeric(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _looks_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _looks_identifierish(segment: str) -> bool:
    if segment.isdigit():
        return True
    if _UUID_RE.fullmatch(segment):
        return True
    if segment.startswith("<redacted:"):
        return True
    return bool(_VARIABLE_SEGMENT_RE.fullmatch(segment) and any(char.isdigit() for char in segment))


def _looks_variable_segment(values: set[str]) -> bool:
    if len(values) <= 1:
        return False
    if all(_looks_identifierish(value) for value in values):
        return True
    return len(values) >= 4


def _singularize(token: str) -> str:
    if token.endswith("ies") and len(token) > 3:
        return token[:-3] + "y"
    if token.endswith("ses") and len(token) > 3:
        return token[:-2]
    if token.endswith("s") and len(token) > 1:
        return token[:-1]
    return token


def _path_param_name(previous_literal: str | None, index: int, used: set[str]) -> str:
    if previous_literal:
        base = re.sub(r"[^a-z0-9]+", "_", _singularize(previous_literal.lower())).strip("_")
    else:
        base = ""
    if not base:
        base = f"segment_{index}"
    candidate = f"{base}_id"
    while candidate in used:
        candidate = f"{candidate}_{len(used) + 1}"
    used.add(candidate)
    return candidate


def _template_segments(prepared_events: list[_PreparedEvent]) -> tuple[str, ...]:
    if not prepared_events:
        return ()
    segment_count = len(prepared_events[0].path_segments)
    used_names: set[str] = set()
    template: list[str] = []
    for index in range(segment_count):
        values = {event.path_segments[index] for event in prepared_events}
        if len(values) == 1:
            template.append(next(iter(values)))
            continue
        if _looks_variable_segment(values):
            previous_literal = next(
                (segment for segment in reversed(template) if not segment.startswith("{")),
                None,
            )
            template.append(f"{{{_path_param_name(previous_literal, index, used_names)}}}")
            continue
        template.append(sorted(values)[0])
    return tuple(template)


def _operation_tag(template_segments: tuple[str, ...]) -> str:
    for segment in template_segments:
        if not segment.startswith("{"):
            return segment
    return "learned"


def _operation_id(method: str, template_segments: tuple[str, ...]) -> str:
    tokens = [method.lower()]
    for segment in template_segments:
        match = _PATH_PARAM_RE.fullmatch(segment)
        if match:
            tokens.extend(("by", match.group(1)))
            continue
        tokens.extend(token for token in re.split(r"[^A-Za-z0-9]+", segment) if token)
    normalized = "_".join(token.lower() for token in tokens if token)
    return re.sub(r"_+", "_", normalized).strip("_")


def _path_from_template(template_segments: tuple[str, ...]) -> str:
    return "/" + "/".join(template_segments) if template_segments else "/"


def _prepare_events(events: list[CaptureEvent]) -> list[_PreparedEvent]:
    prepared: list[_PreparedEvent] = []
    for index, event in enumerate(events):
        parsed_url = urlparse(event.request.url)
        prepared.append(
            _PreparedEvent(
                index=index,
                event=event,
                method=event.request.method.upper(),
                raw_path=parsed_url.path or "/",
                path_segments=_path_segments(parsed_url.path or "/"),
                query=dict(event.request.query),
                headers=dict(event.request.headers),
                body_json=event.request.body_json,
                raw_body=event.request.raw_body,
                content_type=event.request.content_type,
                response_json=event.response.body_json if event.response else None,
                response_content_type=event.response.content_type if event.response else None,
                response_status=event.response.status_code if event.response else None,
                identity_context=event.identity_context,
            )
        )
    return prepared


def _group_signature(path_segments: tuple[str, ...]) -> tuple[str, ...]:
    return tuple("*" if _looks_identifierish(segment) else segment for segment in path_segments)


def _group_events(
    prepared_events: list[_PreparedEvent],
) -> dict[tuple[str, tuple[str, ...]], list[_PreparedEvent]]:
    grouped: dict[tuple[str, tuple[str, ...]], list[_PreparedEvent]] = defaultdict(list)
    for event in prepared_events:
        grouped[(event.method, _group_signature(event.path_segments))].append(event)
    return grouped


def _extract_path_params(
    event: _PreparedEvent,
    template_segments: tuple[str, ...],
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for template, actual in zip(template_segments, event.path_segments, strict=True):
        match = _PATH_PARAM_RE.fullmatch(template)
        if match:
            params[match.group(1)] = actual
    return params


def _json_scalar_leaves(
    value: Any, *, path: tuple[str | int, ...] = ()
) -> list[tuple[str, str, Any]]:
    leaves: list[tuple[str, str, Any]] = []
    if isinstance(value, dict):
        for name, item in value.items():
            leaves.extend(_json_scalar_leaves(item, path=(*path, name)))
        return leaves
    if isinstance(value, list):
        for index, item in enumerate(value):
            leaves.extend(_json_scalar_leaves(item, path=(*path, index)))
        return leaves
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        if not path:
            return leaves
        name = str(path[-1])
        pointer = "/" + "/".join(str(token).replace("~", "~0").replace("/", "~1") for token in path)
        leaves.append((name, pointer, value))
    return leaves


def _request_value_bindings(example: ObservedRequestExample) -> list[tuple[str, str, Any]]:
    bindings: list[tuple[str, str, Any]] = []
    for name, value in example.path_params.items():
        bindings.append(("path", name, value))
    for name, value in example.query.items():
        bindings.append(("query", name, value))
    if isinstance(example.body_json, dict):
        for name, _, value in _json_scalar_leaves(example.body_json):
            bindings.append(("body", name, value))
    return bindings


def _useful_relation_value(value: Any) -> bool:
    if isinstance(value, str):
        if not value or value.lower() in _GENERIC_VALUES:
            return False
        if value.startswith("<redacted:"):
            return False
        return len(value) >= 2
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _name_similarity(source_name: str, target_name: str) -> int:
    normalized_source = tuple(
        token for token in re.split(r"[^A-Za-z0-9]+", source_name.lower()) if token
    )
    normalized_target = tuple(
        token for token in re.split(r"[^A-Za-z0-9]+", target_name.lower()) if token
    )
    if normalized_source == normalized_target:
        return 2
    if normalized_source and normalized_target and normalized_source[-1] == normalized_target[-1]:
        return 1
    if source_name.lower().endswith("id") and target_name.lower().endswith("id"):
        return 1
    return 0


def _infer_scalar_schema(values: list[Any]) -> dict[str, Any]:
    if all(isinstance(value, bool) for value in values):
        return {"type": "boolean"}
    if values and all(_looks_numeric(value) for value in values):
        return {"type": "integer"}
    if values and all(_looks_number(value) for value in values):
        return {"type": "number"}

    strings = [str(value) for value in values]
    schema: dict[str, Any] = {"type": "string"}
    if strings and all(_UUID_RE.fullmatch(value) for value in strings):
        schema["format"] = "uuid"
    elif strings and all(_DATE_TIME_RE.fullmatch(value) for value in strings):
        schema["format"] = "date-time"
    elif strings and all(_DATE_RE.fullmatch(value) for value in strings):
        schema["format"] = "date"
    elif strings and all(_EMAIL_RE.fullmatch(value) for value in strings):
        schema["format"] = "email"
    elif strings and all(_URI_RE.fullmatch(value) for value in strings):
        schema["format"] = "uri"

    unique = sorted({value for value in strings if value})
    if (
        1 < len(unique) <= 5
        and not any(_looks_identifierish(value) for value in unique)
        and max(len(value) for value in unique) <= 32
    ):
        schema["enum"] = unique
    return schema


def _merge_types(values: list[Any]) -> str | None:
    scalar_types = {
        "integer" if _looks_numeric(value) else "number" if _looks_number(value) else "string"
        for value in values
        if isinstance(value, (str, int, float)) and not isinstance(value, bool)
    }
    if len(scalar_types) == 1:
        return next(iter(scalar_types))
    return None


def infer_schema(values: list[Any]) -> dict[str, Any]:
    filtered = [value for value in values if value is not None]
    if not filtered:
        return {}
    if all(isinstance(value, dict) for value in filtered):
        key_union: set[str] = set()
        required_keys: set[str] | None = None
        for item in filtered:
            keys = set(item.keys())
            key_union |= keys
            required_keys = keys if required_keys is None else required_keys & keys
        properties = {
            key: infer_schema([item[key] for item in filtered if key in item])
            for key in sorted(key_union)
        }
        schema: dict[str, Any] = {"type": "object", "properties": properties}
        if required_keys:
            schema["required"] = sorted(required_keys)
        return schema
    if all(isinstance(value, list) for value in filtered):
        items = [item for value in filtered for item in value]
        schema: dict[str, Any] = {"type": "array"}
        if items:
            schema["items"] = infer_schema(items)
        return schema

    scalar_type = _merge_types(filtered)
    if scalar_type is None and any(isinstance(value, dict) for value in filtered):
        return {"type": "object"}
    if scalar_type is None and any(isinstance(value, list) for value in filtered):
        return {"type": "array"}
    return _infer_scalar_schema(filtered)


def _response_schemas(examples: list[ObservedRequestExample]) -> dict[str, ResponseSpec]:
    grouped: dict[tuple[str, str | None], list[Any]] = defaultdict(list)
    for example in examples:
        if example.status_code is None or example.response_json is None:
            continue
        grouped[(str(example.status_code), example.response_content_type)].append(
            example.response_json
        )
    response_schemas: dict[str, ResponseSpec] = {}
    for (status_code, content_type), values in grouped.items():
        response_schemas[status_code] = ResponseSpec(
            content_type=content_type,
            schema_def=infer_schema(values),
        )
    return response_schemas


def _query_parameters(
    examples: list[ObservedRequestExample],
) -> tuple[list[ParameterSpec], list[str]]:
    all_names: set[str] = set()
    auth_names: set[str] = set()
    for example in examples:
        all_names |= set(example.query)
        auth_names |= {
            name
            for name, value in example.query.items()
            if isinstance(value, str) and value.startswith("<redacted:")
        }
    parameters: list[ParameterSpec] = []
    for name in sorted(all_names - auth_names):
        values = [example.query[name] for example in examples if name in example.query]
        parameters.append(
            ParameterSpec(
                name=name,
                location="query",
                required=all(name in example.query for example in examples),
                schema_def=infer_schema(values),
            )
        )
    return parameters, sorted(auth_names)


def _header_parameters(
    examples: list[ObservedRequestExample],
) -> tuple[list[ParameterSpec], list[str]]:
    all_names: set[str] = set()
    auth_names: set[str] = set()
    for example in examples:
        all_names |= set(example.headers)
        auth_names |= {
            name
            for name, value in example.headers.items()
            if isinstance(value, str) and value.startswith("<redacted:")
        }
    parameters: list[ParameterSpec] = []
    for name in sorted(all_names - auth_names):
        normalized_name = name.lower()
        if normalized_name in _COMMON_HEADERS:
            continue
        values = [example.headers[name] for example in examples if name in example.headers]
        parameters.append(
            ParameterSpec(
                name=name,
                location="header",
                required=all(name in example.headers for example in examples),
                schema_def=infer_schema(values),
            )
        )
    return parameters, sorted(auth_names)


def _build_operation(
    method: str,
    template_segments: tuple[str, ...],
    group_events: list[_PreparedEvent],
) -> OperationSpec:
    examples: list[ObservedRequestExample] = []
    for event in group_events:
        examples.append(
            ObservedRequestExample(
                path_params=_extract_path_params(event, template_segments),
                query=event.query,
                headers=event.headers,
                body_json=event.body_json,
                raw_body=event.raw_body,
                content_type=event.content_type,
                status_code=event.response_status,
                response_json=event.response_json,
                response_content_type=event.response_content_type,
                identity_context=event.identity_context,
            )
        )

    path_parameters = [
        ParameterSpec(
            name=match.group(1),
            location="path",
            required=True,
            schema_def=infer_schema(
                [
                    example.path_params[match.group(1)]
                    for example in examples
                    if match.group(1) in example.path_params
                ]
            ),
        )
        for segment in template_segments
        if (match := _PATH_PARAM_RE.fullmatch(segment))
    ]
    query_parameters, auth_query_names = _query_parameters(examples)
    header_parameters, auth_header_names = _header_parameters(examples)
    body_values = [example.body_json for example in examples if example.body_json is not None]
    content_types = Counter(
        example.content_type for example in examples if example.content_type is not None
    )
    identity_contexts = sorted(
        {example.identity_context for example in examples if example.identity_context}
    )
    success_examples = [example for example in examples if (example.status_code or 0) < 400]
    confidence = min(
        0.99,
        0.45
        + min(len(examples), 4) * 0.1
        + (0.1 if body_values else 0.0)
        + (0.1 if success_examples else 0.0),
    )

    return OperationSpec(
        operation_id=_operation_id(method, template_segments),
        method=method,
        path=_path_from_template(template_segments),
        protocol="learned",
        tags=[_operation_tag(template_segments)],
        parameters=[*path_parameters, *query_parameters, *header_parameters],
        request_body_required=bool(body_values) and len(body_values) == len(examples),
        request_body_schema=infer_schema(body_values) if body_values else None,
        request_body_content_type=(content_types.most_common(1)[0][0] if content_types else None),
        auth_required=bool(auth_header_names or auth_query_names or identity_contexts),
        auth_header_names=auth_header_names,
        auth_query_names=auth_query_names,
        response_schemas=_response_schemas(success_examples),
        observed_examples=examples[:3],
        learned_confidence=round(confidence, 2),
        observation_count=len(examples),
        identity_contexts=identity_contexts,
    )


def _workflow_evidence(
    operation_lookup: dict[int, OperationSpec],
    prepared_events: list[_PreparedEvent],
) -> list[_WorkflowEvidence]:
    counts: dict[tuple[str, str, str, str, str, str], tuple[int, int]] = {}
    examples_by_index: dict[int, ObservedRequestExample] = {}
    for event in prepared_events:
        operation = operation_lookup[event.index]
        template_segments = _path_segments(operation.path)
        examples_by_index[event.index] = ObservedRequestExample(
            path_params=_extract_path_params(event, template_segments),
            query=event.query,
            headers=event.headers,
            body_json=event.body_json,
            raw_body=event.raw_body,
            content_type=event.content_type,
            status_code=event.response_status,
            response_json=event.response_json,
            response_content_type=event.response_content_type,
            identity_context=event.identity_context,
        )

    for producer_event in prepared_events:
        producer_operation = operation_lookup[producer_event.index]
        if producer_event.response_status is None or producer_event.response_status >= 400:
            continue
        response_json = producer_event.response_json
        if response_json is None:
            continue

        for source_name, source_pointer, value in _json_scalar_leaves(response_json):
            if not _useful_relation_value(value):
                continue
            for consumer_event in prepared_events[producer_event.index + 1 :]:
                consumer_operation = operation_lookup[consumer_event.index]
                if consumer_operation.operation_id == producer_operation.operation_id:
                    continue
                for target, target_name, request_value in _request_value_bindings(
                    examples_by_index[consumer_event.index]
                ):
                    if str(request_value) != str(value):
                        continue
                    key = (
                        producer_operation.operation_id,
                        consumer_operation.operation_id,
                        source_name,
                        source_pointer,
                        target,
                        target_name,
                    )
                    current_count, current_exact = counts.get(key, (0, 0))
                    counts[key] = (
                        current_count + 1,
                        current_exact
                        + (1 if _name_similarity(source_name, target_name) > 0 else 0),
                    )

    return [
        _WorkflowEvidence(
            producer_operation_id=producer,
            consumer_operation_id=consumer,
            source_name=source_name,
            source_pointer=source_pointer,
            target=target,
            target_name=target_name,
            count=count,
            exact_name_matches=exact_name_matches,
        )
        for (
            producer,
            consumer,
            source_name,
            source_pointer,
            target,
            target_name,
        ), (count, exact_name_matches) in counts.items()
    ]


def _workflow_confidence(evidence: _WorkflowEvidence, consumer_count: int) -> float:
    base = 0.45 + min(evidence.count, 3) * 0.15
    if evidence.exact_name_matches:
        base += 0.15
    if consumer_count > 0:
        base += min(evidence.count / consumer_count, 1.0) * 0.1
    return round(min(base, 0.99), 2)


def _learned_workflows(
    operations: list[OperationSpec], prepared_events: list[_PreparedEvent]
) -> list[LearnedWorkflow]:
    operation_lookup_by_path: dict[tuple[str, str], OperationSpec] = {
        (operation.method.upper(), operation.path): operation for operation in operations
    }
    operation_lookup: dict[int, OperationSpec] = {}
    grouped = _group_events(prepared_events)
    for (method, _), group_events in grouped.items():
        template_segments = _template_segments(group_events)
        operation = operation_lookup_by_path[(method, _path_from_template(template_segments))]
        for event in group_events:
            operation_lookup[event.index] = operation

    evidence = _workflow_evidence(operation_lookup, prepared_events)
    grouped_evidence: dict[tuple[str, str], list[_WorkflowEvidence]] = defaultdict(list)
    for item in evidence:
        grouped_evidence[(item.producer_operation_id, item.consumer_operation_id)].append(item)

    operations_by_id = {operation.operation_id: operation for operation in operations}
    workflows: list[LearnedWorkflow] = []
    for (producer_id, consumer_id), items in grouped_evidence.items():
        consumer_count = max(operations_by_id[consumer_id].observation_count, 1)
        bindings = [
            LearnedBinding(
                source_name=item.source_name,
                source_pointer=item.source_pointer,
                target=item.target,
                target_name=item.target_name,
                confidence=_workflow_confidence(item, consumer_count),
            )
            for item in sorted(
                items,
                key=lambda item: (item.exact_name_matches, item.count, item.target_name),
                reverse=True,
            )
        ]
        confidence = round(sum(binding.confidence for binding in bindings) / len(bindings), 2)
        workflow_id = f"wf_{sha1(f'{producer_id}:{consumer_id}'.encode()).hexdigest()[:12]}"
        workflows.append(
            LearnedWorkflow(
                id=workflow_id,
                name=f"Learned workflow via {producer_id} -> {consumer_id}",
                producer_operation_id=producer_id,
                consumer_operation_id=consumer_id,
                bindings=bindings,
                confidence=confidence,
                observation_count=sum(item.count for item in items),
            )
        )

    delete_bindings: dict[tuple[str, str], tuple[str, list[LearnedBinding]]] = {}
    for workflow in workflows:
        consumer_operation = operations_by_id[workflow.consumer_operation_id]
        if consumer_operation.method.upper() != "DELETE":
            continue
        for binding in workflow.bindings:
            delete_bindings[(workflow.producer_operation_id, binding.target_name)] = (
                workflow.consumer_operation_id,
                workflow.bindings,
            )
    return [
        workflow.model_copy(
            update={
                "delete_operation_id": next(
                    (
                        delete_bindings[(workflow.producer_operation_id, binding.target_name)][0]
                        for binding in workflow.bindings
                        if (workflow.producer_operation_id, binding.target_name) in delete_bindings
                    ),
                    None,
                ),
                "delete_bindings": next(
                    (
                        delete_bindings[(workflow.producer_operation_id, binding.target_name)][1]
                        for binding in workflow.bindings
                        if (workflow.producer_operation_id, binding.target_name) in delete_bindings
                    ),
                    [],
                ),
            }
        )
        for workflow in workflows
        if workflow.bindings
    ]


def discover_learned_model(paths: list[str | Path]) -> LearnedModel:
    events = load_capture_inputs(paths)
    prepared_events = _prepare_events(events)
    grouped = _group_events(prepared_events)

    operations: list[OperationSpec] = []
    warnings: list[PreflightWarning] = []
    for (method, _), group_events in sorted(grouped.items()):
        template_segments = _template_segments(group_events)
        operation = _build_operation(method, template_segments, group_events)
        operations.append(operation)
        if (operation.learned_confidence or 0.0) < 0.65:
            warnings.append(
                PreflightWarning(
                    code="low_learned_confidence",
                    message=(
                        f"Operation was learned from limited traffic and carries "
                        f"confidence {operation.learned_confidence:.2f}."
                    ),
                    operation_id=operation.operation_id,
                    method=operation.method,
                    path=operation.path,
                )
            )

    workflows = _learned_workflows(operations, prepared_events)
    for workflow in workflows:
        if workflow.confidence < 0.7:
            consumer = next(
                operation
                for operation in operations
                if operation.operation_id == workflow.consumer_operation_id
            )
            warnings.append(
                PreflightWarning(
                    code="low_workflow_confidence",
                    message=(
                        f"Learned workflow '{workflow.name}' is below the default "
                        f"auto-generation confidence threshold ({workflow.confidence:.2f})."
                    ),
                    operation_id=consumer.operation_id,
                    method=consumer.method,
                    path=consumer.path,
                )
            )

    return LearnedModel(
        source_inputs=[str(Path(path)) for path in paths],
        operations=operations,
        workflows=workflows,
        warnings=warnings,
    )
