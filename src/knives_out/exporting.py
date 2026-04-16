from __future__ import annotations

import json
from typing import Any
from xml.etree import ElementTree as ET

from knives_out import __version__
from knives_out.models import AttackResult, AttackResults, ProfileAttackResult, WorkflowStepResult
from knives_out.reporting import _protocol_label, _schema_summary, summarize_results
from knives_out.suppressions import SuppressedFinding, SuppressionRule
from knives_out.verification import (
    ComparedFinding,
    ResultComparison,
    compare_attack_results,
    compared_finding_sort_key,
)

_SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _issue_name(issue: str | None) -> str:
    return issue or "flagged_finding"


def _sarif_rule_id(issue: str | None) -> str:
    return f"knives-out/{_issue_name(issue)}"


def _issue_label(issue: str | None) -> str:
    return _issue_name(issue).replace("_", " ").capitalize()


def _workflow_step_properties(step: WorkflowStepResult) -> dict[str, Any]:
    return {
        "name": step.name,
        "operation_id": step.operation_id,
        "method": step.method,
        "url": step.url,
        "status_code": step.status_code,
        "error": step.error,
        "duration_ms": step.duration_ms,
        "response_excerpt": step.response_excerpt,
    }


def _profile_result_properties(result: ProfileAttackResult) -> dict[str, Any]:
    return {
        "profile": result.profile,
        "protocol": _protocol_label(result.protocol),
        "level": result.level,
        "anonymous": result.anonymous,
        "url": result.url,
        "status_code": result.status_code,
        "error": result.error,
        "issue": result.issue,
        "severity": result.severity,
        "confidence": result.confidence,
        "schema_status": _schema_summary(result),
        "workflow_step_count": len(result.workflow_steps or []),
    }


def _message_text(finding: ComparedFinding | Any, *, baseline_used: bool) -> str:
    result = finding.result if isinstance(finding, ComparedFinding) else finding
    target = f"{result.method} {result.path}" if result.path else result.url
    status = f"status {result.status_code}" if result.status_code is not None else "no status"
    prefix = ""
    if baseline_used and isinstance(finding, ComparedFinding):
        prefix = f"[{finding.change}] "
    return f"{prefix}{result.name}: {_issue_label(result.issue)} on {target} ({status})."


def _finding_properties(finding: ComparedFinding | Any, *, baseline_used: bool) -> dict[str, Any]:
    result = finding.result if isinstance(finding, ComparedFinding) else finding
    properties: dict[str, Any] = {
        "attack_id": result.attack_id,
        "name": result.name,
        "type": result.type,
        "protocol": _protocol_label(result.protocol),
        "kind": result.kind,
        "method": result.method,
        "path": result.path,
        "tags": list(result.tags),
        "url": result.url,
        "status_code": result.status_code,
        "severity": result.severity,
        "confidence": result.confidence,
        "issue": result.issue,
        "schema_status": _schema_summary(result),
        "duration_ms": result.duration_ms,
        "error": result.error,
        "response_excerpt": result.response_excerpt,
    }
    if result.response_schema_status is not None:
        properties["response_schema_status"] = result.response_schema_status
    if result.response_schema_valid is not None:
        properties["response_schema_valid"] = result.response_schema_valid
    if result.response_schema_error is not None:
        properties["response_schema_error"] = result.response_schema_error
    if result.graphql_response_valid is not None:
        properties["graphql_response_valid"] = result.graphql_response_valid
    if result.graphql_response_error is not None:
        properties["graphql_response_error"] = result.graphql_response_error
    if result.graphql_response_hint is not None:
        properties["graphql_response_hint"] = result.graphql_response_hint
    if result.workflow_steps:
        properties["workflow_step_count"] = len(result.workflow_steps)
        properties["workflow_steps"] = [
            _workflow_step_properties(step) for step in result.workflow_steps
        ]
    if result.profile_results:
        properties["profile_result_count"] = len(result.profile_results)
        properties["profile_results"] = [
            _profile_result_properties(profile_result) for profile_result in result.profile_results
        ]
    if baseline_used and isinstance(finding, ComparedFinding):
        properties["change"] = finding.change
        if finding.delta is not None and finding.delta.changed:
            properties["delta_changes"] = [
                {
                    "field": change.field,
                    "baseline": change.baseline,
                    "current": change.current,
                }
                for change in finding.delta.changes
            ]
    return properties


def _finding_key(result: AttackResult) -> tuple[str, str | None]:
    return (result.attack_id, result.issue)


def _exported_findings(
    comparison: ResultComparison,
    *,
    baseline_used: bool,
) -> list[ComparedFinding | AttackResult]:
    if not baseline_used:
        return comparison.current_findings
    return sorted(
        [*comparison.new_findings, *comparison.persisting_findings],
        key=compared_finding_sort_key,
    )


def _rule_payload(issue: str | None) -> dict[str, Any]:
    issue_name = _issue_name(issue)
    return {
        "id": _sarif_rule_id(issue),
        "name": issue_name,
        "shortDescription": {"text": _issue_label(issue)},
        "fullDescription": {"text": f"knives-out finding class `{issue_name}`."},
        "properties": {"issue": issue_name},
    }


def render_sarif_export(
    results: AttackResults,
    *,
    baseline: AttackResults | None = None,
    suppressions: list[SuppressionRule] | None = None,
) -> dict[str, Any]:
    comparison = compare_attack_results(results, baseline, suppressions=suppressions)
    summary = summarize_results(results, baseline=baseline, suppressions=suppressions, top_limit=0)
    baseline_used = baseline is not None
    exported_findings = _exported_findings(comparison, baseline_used=baseline_used)

    exported_issues = sorted(
        {
            _issue_name(
                finding.result.issue if isinstance(finding, ComparedFinding) else finding.issue
            )
            for finding in exported_findings
        }
    )
    rules = [_rule_payload(issue) for issue in exported_issues]
    sarif_results: list[dict[str, Any]] = []
    for finding in exported_findings:
        result = finding.result if isinstance(finding, ComparedFinding) else finding
        issue = result.issue
        sarif_results.append(
            {
                "ruleId": _sarif_rule_id(issue),
                "level": _sarif_level(result.severity),
                "message": {"text": _message_text(finding, baseline_used=baseline_used)},
                "partialFingerprints": {
                    "attackIssue": f"{result.attack_id}:{_issue_name(issue)}",
                },
                "properties": _finding_properties(finding, baseline_used=baseline_used),
            }
        )

    return {
        "$schema": _SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "knives-out",
                        "version": __version__,
                        "informationUri": "https://github.com/keithwegner/knives-out",
                        "rules": rules,
                    }
                },
                "properties": summary.model_dump(
                    mode="json",
                    exclude_none=True,
                    exclude={"top_findings"},
                ),
                "results": sarif_results,
            }
        ],
    }


def _junit_time_seconds(result: AttackResult) -> str:
    if result.duration_ms is None:
        return "0.000"
    return f"{max(result.duration_ms, 0.0) / 1000:.3f}"


def _junit_classname(result: AttackResult) -> str:
    protocol = _protocol_label(result.protocol).replace(" ", "_")
    operation = result.operation_id.replace(" ", "_") or "operation"
    return f"knives_out.{protocol}.{operation}"


def _junit_test_name(result: AttackResult) -> str:
    target = f"{result.method} {result.path}" if result.path else result.url
    return f"{target} - {result.name}"


def _junit_property_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(value, sort_keys=True)


def _add_junit_properties(parent: ET.Element, properties: dict[str, Any]) -> None:
    properties_element = ET.SubElement(parent, "properties")
    for name, value in sorted(properties.items()):
        ET.SubElement(
            properties_element,
            "property",
            name=name,
            value=_junit_property_value(value),
        )


def _junit_failure_text(finding: ComparedFinding | AttackResult, *, baseline_used: bool) -> str:
    result = finding.result if isinstance(finding, ComparedFinding) else finding
    lines = [
        _message_text(finding, baseline_used=baseline_used),
        f"attack_id: {result.attack_id}",
        f"operation_id: {result.operation_id}",
        f"severity: {result.severity}",
        f"confidence: {result.confidence}",
        f"schema: {_schema_summary(result)}",
        f"url: {result.url}",
    ]
    if isinstance(finding, ComparedFinding) and finding.delta is not None and finding.delta.changed:
        lines.append(f"delta: {finding.delta_summary}")
    if result.error:
        lines.append(f"error: {result.error}")
    if result.response_excerpt:
        lines.extend(["", result.response_excerpt])
    return "\n".join(lines)


def _junit_skipped_text(suppressed: SuppressedFinding) -> str:
    rule = suppressed.rule
    lines = [
        f"Suppressed finding: {rule.reason}",
        f"owner: {rule.owner}",
    ]
    if rule.expires_on is not None:
        lines.append(f"expires_on: {rule.expires_on.isoformat()}")
    return "\n".join(lines)


def render_junit_export(
    results: AttackResults,
    *,
    baseline: AttackResults | None = None,
    suppressions: list[SuppressionRule] | None = None,
) -> str:
    comparison = compare_attack_results(results, baseline, suppressions=suppressions)
    summary = summarize_results(results, baseline=baseline, suppressions=suppressions, top_limit=0)
    baseline_used = baseline is not None
    exported_findings = _exported_findings(comparison, baseline_used=baseline_used)
    failures_by_key = {
        _finding_key(finding.result if isinstance(finding, ComparedFinding) else finding): finding
        for finding in exported_findings
    }
    suppressed_by_key = {
        _finding_key(suppressed.result): suppressed
        for suppressed in comparison.suppressed_current_findings
    }

    total_time = sum(max(result.duration_ms or 0.0, 0.0) for result in results.results) / 1000
    suite = ET.Element(
        "testsuite",
        name="knives-out",
        tests=str(len(results.results)),
        failures=str(len(failures_by_key)),
        errors="0",
        skipped=str(len(suppressed_by_key)),
        time=f"{total_time:.3f}",
        timestamp=results.executed_at.isoformat(),
    )
    _add_junit_properties(
        suite,
        summary.model_dump(
            mode="json",
            exclude_none=True,
            exclude={"top_findings"},
        ),
    )

    for result in results.results:
        testcase = ET.SubElement(
            suite,
            "testcase",
            classname=_junit_classname(result),
            name=_junit_test_name(result),
            time=_junit_time_seconds(result),
        )
        key = _finding_key(result)
        failure = failures_by_key.get(key)
        suppressed = suppressed_by_key.get(key)
        _add_junit_properties(
            testcase,
            _finding_properties(
                failure if failure is not None else result,
                baseline_used=baseline_used and failure is not None,
            ),
        )
        if failure is not None:
            failure_result = failure.result if isinstance(failure, ComparedFinding) else failure
            failure_element = ET.SubElement(
                testcase,
                "failure",
                type=_issue_name(failure_result.issue),
                message=_message_text(failure, baseline_used=baseline_used),
            )
            failure_element.text = _junit_failure_text(failure, baseline_used=baseline_used)
        elif suppressed is not None:
            skipped_element = ET.SubElement(
                testcase,
                "skipped",
                type="suppressed",
                message=f"Suppressed: {suppressed.rule.reason}",
            )
            skipped_element.text = _junit_skipped_text(suppressed)

    ET.indent(suite, space="  ")
    rendered = ET.tostring(suite, encoding="unicode", short_empty_elements=True)
    return f'<?xml version="1.0" encoding="UTF-8"?>\n{rendered}\n'
