from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from pydantic import ValidationError

from knives_out.attack_packs import load_attack_packs
from knives_out.auth_config import (
    BuiltInAuthConfig,
    auth_config_map,
    auth_profiles_from_configs,
    load_auth_configs,
    select_auth_configs,
)
from knives_out.auth_plugins import LoadedAuthPlugin, load_auth_plugins
from knives_out.exporting import render_sarif_export
from knives_out.filtering import filter_attack_suite, filter_operations
from knives_out.generator import generate_attack_suite
from knives_out.learned_discovery import discover_learned_model
from knives_out.models import (
    AttackResults,
    AttackSuite,
    AuthProfile,
    LearnedModel,
    LoadedOperations,
    OperationSpec,
    ResultsSummary,
)
from knives_out.profiles import (
    load_auth_profiles,
    resolve_auth_profile_modules,
    select_auth_profiles,
)
from knives_out.promotion import PromotionError, PromotionResult, promote_attack_suite
from knives_out.reporting import (
    load_attack_results,
    render_html_report,
    render_markdown_report,
    summarize_results,
)
from knives_out.review_bundles import render_review_bundle
from knives_out.runner import execute_attack_suite, execute_attack_suite_profiles, load_attack_suite
from knives_out.spec_loader import load_operations_with_warnings
from knives_out.suppressions import (
    DEFAULT_SUPPRESSIONS_PATH,
    SuppressionRule,
    SuppressionsFile,
    load_suppressions,
    merge_suppressions,
    triage_rule_for_result,
    write_suppressions,
)
from knives_out.verification import ResultComparison, VerificationResult, compare_attack_results
from knives_out.verification import evaluate_verification as evaluate_results_verification
from knives_out.workflow_packs import load_workflow_packs


@dataclass(frozen=True)
class InlineInput:
    name: str
    content: str


@dataclass(frozen=True)
class InspectServiceResult:
    loaded: LoadedOperations
    operations: list[OperationSpec]


@dataclass(frozen=True)
class GenerateServiceResult:
    loaded: LoadedOperations
    suite: AttackSuite


@dataclass(frozen=True)
class RunServiceResult:
    suite: AttackSuite
    results: AttackResults


@dataclass(frozen=True)
class ReportServiceResult:
    rendered: str
    suppressions_path: Path | None
    suppressions: list[SuppressionRule]


@dataclass(frozen=True)
class VerifyServiceResult:
    verification: VerificationResult
    suppressions_path: Path | None
    suppressions: list[SuppressionRule]


@dataclass(frozen=True)
class SummaryServiceResult:
    summary: ResultsSummary
    suppressions_path: Path | None
    suppressions: list[SuppressionRule]


@dataclass(frozen=True)
class ExportServiceResult:
    content: dict[str, Any]
    suppressions_path: Path | None
    suppressions: list[SuppressionRule]


@dataclass(frozen=True)
class BundleServiceResult:
    content: bytes
    suppressions_path: Path | None
    suppressions: list[SuppressionRule]


@dataclass(frozen=True)
class PromoteServiceResult:
    promotion: PromotionResult
    suppressions_path: Path | None
    suppressions: list[SuppressionRule]


@dataclass(frozen=True)
class TriageServiceResult:
    comparison: ResultComparison
    suppressions_file: SuppressionsFile
    added_count: int


def parse_key_value_map(items: list[str] | None, *, separator: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for item in items or []:
        if separator not in item:
            raise ValueError(f"Expected '{separator}' in value: {item!r}")
        key, value = item.split(separator, 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError(f"Missing key in value: {item!r}")
        parsed[key] = value
    return parsed


def load_attack_results_or_raise(path: Path, *, label: str) -> AttackResults:
    try:
        return load_attack_results(path)
    except (OSError, ValidationError, ValueError) as exc:
        raise ValueError(f"Could not read {label} results file '{path}': {exc}") from exc


def load_attack_suite_or_raise(path: Path) -> AttackSuite:
    try:
        return load_attack_suite(path)
    except (OSError, ValidationError, ValueError) as exc:
        raise ValueError(f"Could not read attacks file '{path}': {exc}") from exc


def load_suppressions_or_default(
    path: Path | None,
) -> tuple[Path | None, list[SuppressionRule]]:
    resolved_path = path
    if resolved_path is None and DEFAULT_SUPPRESSIONS_PATH.exists():
        resolved_path = DEFAULT_SUPPRESSIONS_PATH
    if resolved_path is None:
        return None, []

    try:
        suppressions_file = load_suppressions(resolved_path)
    except (OSError, ValueError) as exc:
        raise ValueError(f"Could not read suppressions file '{resolved_path}': {exc}") from exc
    return resolved_path, suppressions_file.suppressions


def _inline_path(stack: ExitStack, inline_input: InlineInput) -> Path:
    temp_dir = Path(stack.enter_context(TemporaryDirectory()))
    path = temp_dir / Path(inline_input.name).name
    path.write_text(inline_input.content, encoding="utf-8")
    return path


def _load_operations_from_inline(
    source: InlineInput,
    *,
    graphql_endpoint: str,
) -> LoadedOperations:
    with ExitStack() as stack:
        path = _inline_path(stack, source)
        return load_operations_with_warnings(path, graphql_endpoint=graphql_endpoint)


def _load_suppressions_from_text(text: str | None) -> list[SuppressionRule]:
    if text is None:
        return []
    with ExitStack() as stack:
        path = _inline_path(stack, InlineInput(name=".knives-out-ignore.yml", content=text))
        return load_suppressions(path).suppressions


def _load_auth_profiles_from_path(
    path: Path | None,
    *,
    include_names: list[str] | None = None,
) -> list[AuthProfile]:
    if path is None:
        if include_names:
            raise ValueError("--profile requires --profile-file.")
        return []

    try:
        profiles_file = load_auth_profiles(path)
        selected_profiles = select_auth_profiles(profiles_file, include_names=include_names)
        return resolve_auth_profile_modules(selected_profiles, relative_to=path)
    except (OSError, ValueError) as exc:
        raise ValueError(f"Could not read auth profile file '{path}': {exc}") from exc


def _load_auth_profiles_from_text(
    text: str | None,
    *,
    include_names: list[str] | None = None,
) -> list[AuthProfile]:
    if text is None:
        if include_names:
            raise ValueError("profile_names require profile_file_yaml.")
        return []
    with ExitStack() as stack:
        path = _inline_path(stack, InlineInput(name="profiles.yml", content=text))
        profiles = _load_auth_profiles_from_path(path, include_names=include_names)
    for profile in profiles:
        if profile.auth_plugin_modules:
            raise ValueError(
                "Inline profile YAML cannot use auth_plugin_modules; use auth_plugin names instead."
            )
    return profiles


def _load_auth_configs_from_path(
    path: Path | None,
    *,
    include_names: list[str] | None = None,
) -> list[BuiltInAuthConfig]:
    if path is None:
        if include_names:
            raise ValueError("--auth-profile requires --auth-config.")
        return []

    try:
        auth_file = load_auth_configs(path)
        selected_configs = select_auth_configs(auth_file, include_names=include_names)
    except (OSError, ValueError) as exc:
        raise ValueError(f"Could not read auth config file '{path}': {exc}") from exc

    if not selected_configs:
        raise ValueError(f"Auth config file '{path}' did not define any auth entries.")
    return selected_configs


def _load_auth_configs_from_text(
    text: str | None,
    *,
    include_names: list[str] | None = None,
) -> list[BuiltInAuthConfig]:
    if text is None:
        if include_names:
            raise ValueError("auth_profile_names require auth_config_yaml.")
        return []
    with ExitStack() as stack:
        path = _inline_path(stack, InlineInput(name="auth-config.yml", content=text))
        return _load_auth_configs_from_path(path, include_names=include_names)


def inspect_source_path(
    spec: Path,
    *,
    graphql_endpoint: str = "/graphql",
    tag: list[str] | None = None,
    exclude_tag: list[str] | None = None,
    path: list[str] | None = None,
    exclude_path: list[str] | None = None,
) -> InspectServiceResult:
    loaded = load_operations_with_warnings(spec, graphql_endpoint=graphql_endpoint)
    operations = filter_operations(
        loaded.operations,
        include_paths=path,
        exclude_paths=exclude_path,
        include_tags=tag,
        exclude_tags=exclude_tag,
    )
    return InspectServiceResult(loaded=loaded, operations=operations)


def inspect_source_inline(
    source: InlineInput,
    *,
    graphql_endpoint: str = "/graphql",
    tag: list[str] | None = None,
    exclude_tag: list[str] | None = None,
    path: list[str] | None = None,
    exclude_path: list[str] | None = None,
) -> InspectServiceResult:
    loaded = _load_operations_from_inline(source, graphql_endpoint=graphql_endpoint)
    operations = filter_operations(
        loaded.operations,
        include_paths=path,
        exclude_paths=exclude_path,
        include_tags=tag,
        exclude_tags=exclude_tag,
    )
    return InspectServiceResult(loaded=loaded, operations=operations)


def discover_model_paths(inputs: list[Path]) -> LearnedModel:
    return discover_learned_model(inputs)


def discover_model_inline(inputs: list[InlineInput]) -> LearnedModel:
    with ExitStack() as stack:
        paths = [_inline_path(stack, current) for current in inputs]
        return discover_learned_model(paths)


def generate_suite_from_path(
    spec: Path,
    *,
    graphql_endpoint: str = "/graphql",
    operation: list[str] | None = None,
    exclude_operation: list[str] | None = None,
    method: list[str] | None = None,
    exclude_method: list[str] | None = None,
    kind: list[str] | None = None,
    exclude_kind: list[str] | None = None,
    tag: list[str] | None = None,
    exclude_tag: list[str] | None = None,
    path: list[str] | None = None,
    exclude_path: list[str] | None = None,
    pack_names: list[str] | None = None,
    pack_module_paths: list[Path] | None = None,
    auto_workflows: bool = False,
    workflow_pack_names: list[str] | None = None,
    workflow_pack_module_paths: list[Path] | None = None,
) -> GenerateServiceResult:
    loaded = load_operations_with_warnings(spec, graphql_endpoint=graphql_endpoint)
    attack_packs = load_attack_packs(
        entry_point_names=pack_names,
        module_paths=pack_module_paths,
    )
    workflow_packs = load_workflow_packs(
        entry_point_names=workflow_pack_names,
        module_paths=workflow_pack_module_paths,
    )
    suite = generate_attack_suite(
        loaded.operations,
        source=str(spec),
        extra_packs=attack_packs,
        auto_workflows=auto_workflows,
        workflow_packs=workflow_packs,
        learned_model=loaded.learned_model,
    )
    suite = filter_attack_suite(
        suite,
        include_operations=operation,
        exclude_operations=exclude_operation,
        include_methods=method,
        exclude_methods=exclude_method,
        include_kinds=kind,
        exclude_kinds=exclude_kind,
        include_paths=path,
        exclude_paths=exclude_path,
        include_tags=tag,
        exclude_tags=exclude_tag,
    )
    return GenerateServiceResult(loaded=loaded, suite=suite)


def generate_suite_from_inline(
    source: InlineInput,
    *,
    graphql_endpoint: str = "/graphql",
    operation: list[str] | None = None,
    exclude_operation: list[str] | None = None,
    method: list[str] | None = None,
    exclude_method: list[str] | None = None,
    kind: list[str] | None = None,
    exclude_kind: list[str] | None = None,
    tag: list[str] | None = None,
    exclude_tag: list[str] | None = None,
    path: list[str] | None = None,
    exclude_path: list[str] | None = None,
    pack_names: list[str] | None = None,
    auto_workflows: bool = False,
    workflow_pack_names: list[str] | None = None,
) -> GenerateServiceResult:
    with ExitStack() as stack:
        path_input = _inline_path(stack, source)
        return generate_suite_from_path(
            path_input,
            graphql_endpoint=graphql_endpoint,
            operation=operation,
            exclude_operation=exclude_operation,
            method=method,
            exclude_method=exclude_method,
            kind=kind,
            exclude_kind=exclude_kind,
            tag=tag,
            exclude_tag=exclude_tag,
            path=path,
            exclude_path=exclude_path,
            pack_names=pack_names,
            auto_workflows=auto_workflows,
            workflow_pack_names=workflow_pack_names,
        )


def run_suite(
    suite: AttackSuite,
    *,
    base_url: str,
    default_headers: dict[str, str] | None = None,
    default_query: dict[str, Any] | None = None,
    timeout_seconds: float = 10.0,
    artifact_dir: Path | None = None,
    auth_plugin_names: list[str] | None = None,
    auth_plugin_module_paths: list[Path] | None = None,
    auth_config_path: Path | None = None,
    auth_profile_names: list[str] | None = None,
    profile_file_path: Path | None = None,
    profile_names: list[str] | None = None,
    operation: list[str] | None = None,
    exclude_operation: list[str] | None = None,
    method: list[str] | None = None,
    exclude_method: list[str] | None = None,
    kind: list[str] | None = None,
    exclude_kind: list[str] | None = None,
    tag: list[str] | None = None,
    exclude_tag: list[str] | None = None,
    path: list[str] | None = None,
    exclude_path: list[str] | None = None,
) -> RunServiceResult:
    filtered_suite = filter_attack_suite(
        suite,
        include_operations=operation,
        exclude_operations=exclude_operation,
        include_methods=method,
        exclude_methods=exclude_method,
        include_kinds=kind,
        exclude_kinds=exclude_kind,
        include_paths=path,
        exclude_paths=exclude_path,
        include_tags=tag,
        exclude_tags=exclude_tag,
    )
    default_headers = dict(default_headers or {})
    default_query = dict(default_query or {})
    auth_profiles = _load_auth_profiles_from_path(profile_file_path, include_names=profile_names)
    built_in_auth_configs = _load_auth_configs_from_path(
        auth_config_path,
        include_names=auth_profile_names,
    )
    built_in_auth_by_name = auth_config_map(built_in_auth_configs)
    global_auth_plugin_modules = [
        str(current.resolve()) for current in auth_plugin_module_paths or []
    ]

    if auth_profiles or built_in_auth_configs:
        if not auth_profiles:
            auth_profiles = auth_profiles_from_configs(built_in_auth_configs)
        auth_profiles = [
            auth_profile.model_copy(
                update={
                    "auth_plugins": [*(auth_plugin_names or []), *auth_profile.auth_plugins],
                    "auth_plugin_modules": [
                        *global_auth_plugin_modules,
                        *auth_profile.auth_plugin_modules,
                    ],
                }
            )
            for auth_profile in auth_profiles
        ]
        auth_plugins: list[LoadedAuthPlugin] | None = None
    else:
        auth_plugins = load_auth_plugins(
            entry_point_names=auth_plugin_names,
            module_paths=auth_plugin_module_paths,
        )

    if auth_profiles:
        results = execute_attack_suite_profiles(
            filtered_suite,
            base_url=base_url,
            profiles=auth_profiles,
            default_headers=default_headers,
            default_query=default_query,
            timeout_seconds=timeout_seconds,
            artifact_dir=artifact_dir,
            built_in_auth_configs=built_in_auth_by_name,
        )
    else:
        results = execute_attack_suite(
            filtered_suite,
            base_url=base_url,
            default_headers=default_headers,
            default_query=default_query,
            timeout_seconds=timeout_seconds,
            artifact_dir=artifact_dir,
            auth_plugins=auth_plugins,
            built_in_auth_configs=built_in_auth_configs,
        )
    return RunServiceResult(suite=filtered_suite, results=results)


def run_suite_from_inline(
    suite: AttackSuite,
    *,
    base_url: str,
    default_headers: dict[str, str] | None = None,
    default_query: dict[str, Any] | None = None,
    timeout_seconds: float = 10.0,
    artifact_dir: Path | None = None,
    auth_plugin_names: list[str] | None = None,
    auth_config_yaml: str | None = None,
    auth_profile_names: list[str] | None = None,
    profile_file_yaml: str | None = None,
    profile_names: list[str] | None = None,
    operation: list[str] | None = None,
    exclude_operation: list[str] | None = None,
    method: list[str] | None = None,
    exclude_method: list[str] | None = None,
    kind: list[str] | None = None,
    exclude_kind: list[str] | None = None,
    tag: list[str] | None = None,
    exclude_tag: list[str] | None = None,
    path: list[str] | None = None,
    exclude_path: list[str] | None = None,
) -> RunServiceResult:
    with ExitStack() as stack:
        auth_config_path = (
            _inline_path(stack, InlineInput(name="auth-config.yml", content=auth_config_yaml))
            if auth_config_yaml is not None
            else None
        )
        profile_file_path = (
            _inline_path(stack, InlineInput(name="profiles.yml", content=profile_file_yaml))
            if profile_file_yaml is not None
            else None
        )
        return run_suite(
            suite,
            base_url=base_url,
            default_headers=default_headers,
            default_query=default_query,
            timeout_seconds=timeout_seconds,
            artifact_dir=artifact_dir,
            auth_plugin_names=auth_plugin_names,
            auth_config_path=auth_config_path,
            auth_profile_names=auth_profile_names,
            profile_file_path=profile_file_path,
            profile_names=profile_names,
            operation=operation,
            exclude_operation=exclude_operation,
            method=method,
            exclude_method=exclude_method,
            kind=kind,
            exclude_kind=exclude_kind,
            tag=tag,
            exclude_tag=exclude_tag,
            path=path,
            exclude_path=exclude_path,
        )


def render_report(
    results: AttackResults,
    *,
    baseline: AttackResults | None = None,
    suppressions: list[SuppressionRule] | None = None,
    format: str = "markdown",
    artifact_root: Path | None = None,
) -> str:
    if format == "html":
        return render_html_report(
            results,
            baseline=baseline,
            suppressions=suppressions,
            artifact_root=artifact_root,
        )
    return render_markdown_report(results, baseline=baseline, suppressions=suppressions)


def render_report_from_paths(
    results_path: Path,
    *,
    baseline_path: Path | None = None,
    suppressions_path: Path | None = None,
    format: str = "markdown",
    artifact_root: Path | None = None,
) -> ReportServiceResult:
    attack_results = load_attack_results_or_raise(results_path, label="current")
    baseline_results = (
        load_attack_results_or_raise(baseline_path, label="baseline")
        if baseline_path is not None
        else None
    )
    resolved_suppressions_path, suppression_rules = load_suppressions_or_default(suppressions_path)
    rendered = render_report(
        attack_results,
        baseline=baseline_results,
        suppressions=suppression_rules,
        format=format,
        artifact_root=artifact_root,
    )
    return ReportServiceResult(
        rendered=rendered,
        suppressions_path=resolved_suppressions_path,
        suppressions=suppression_rules,
    )


def render_report_from_models(
    results: AttackResults,
    *,
    baseline: AttackResults | None = None,
    suppressions_yaml: str | None = None,
    format: str = "markdown",
    artifact_root: Path | None = None,
) -> str:
    suppression_rules = _load_suppressions_from_text(suppressions_yaml)
    return render_report(
        results,
        baseline=baseline,
        suppressions=suppression_rules,
        format=format,
        artifact_root=artifact_root,
    )


def summarize_report_results(
    results: AttackResults,
    *,
    baseline: AttackResults | None = None,
    suppressions: list[SuppressionRule] | None = None,
    top_limit: int = 10,
) -> ResultsSummary:
    return summarize_results(
        results,
        baseline=baseline,
        suppressions=suppressions,
        top_limit=top_limit,
    )


def summarize_results_from_paths(
    results_path: Path,
    *,
    baseline_path: Path | None = None,
    suppressions_path: Path | None = None,
    top_limit: int = 10,
) -> SummaryServiceResult:
    attack_results = load_attack_results_or_raise(results_path, label="current")
    baseline_results = (
        load_attack_results_or_raise(baseline_path, label="baseline")
        if baseline_path is not None
        else None
    )
    resolved_suppressions_path, suppression_rules = load_suppressions_or_default(suppressions_path)
    summary = summarize_report_results(
        attack_results,
        baseline=baseline_results,
        suppressions=suppression_rules,
        top_limit=top_limit,
    )
    return SummaryServiceResult(
        summary=summary,
        suppressions_path=resolved_suppressions_path,
        suppressions=suppression_rules,
    )


def summarize_results_from_models(
    results: AttackResults,
    *,
    baseline: AttackResults | None = None,
    suppressions_yaml: str | None = None,
    top_limit: int = 10,
) -> ResultsSummary:
    suppression_rules = _load_suppressions_from_text(suppressions_yaml)
    return summarize_report_results(
        results,
        baseline=baseline,
        suppressions=suppression_rules,
        top_limit=top_limit,
    )


def export_results(
    results: AttackResults,
    *,
    baseline: AttackResults | None = None,
    suppressions: list[SuppressionRule] | None = None,
    format: str = "sarif",
) -> dict[str, Any]:
    if format == "sarif":
        return render_sarif_export(
            results,
            baseline=baseline,
            suppressions=suppressions,
        )
    raise ValueError(f"Unsupported export format: {format!r}")


def export_results_from_paths(
    results_path: Path,
    *,
    baseline_path: Path | None = None,
    suppressions_path: Path | None = None,
    format: str = "sarif",
) -> ExportServiceResult:
    attack_results = load_attack_results_or_raise(results_path, label="current")
    baseline_results = (
        load_attack_results_or_raise(baseline_path, label="baseline")
        if baseline_path is not None
        else None
    )
    resolved_suppressions_path, suppression_rules = load_suppressions_or_default(suppressions_path)
    return ExportServiceResult(
        content=export_results(
            attack_results,
            baseline=baseline_results,
            suppressions=suppression_rules,
            format=format,
        ),
        suppressions_path=resolved_suppressions_path,
        suppressions=suppression_rules,
    )


def export_results_from_models(
    results: AttackResults,
    *,
    baseline: AttackResults | None = None,
    suppressions_yaml: str | None = None,
    format: str = "sarif",
) -> dict[str, Any]:
    return export_results(
        results,
        baseline=baseline,
        suppressions=_load_suppressions_from_text(suppressions_yaml),
        format=format,
    )


def bundle_results_from_paths(
    results_path: Path,
    *,
    out_name: str | None = None,
    baseline_path: Path | None = None,
    suppressions_path: Path | None = None,
    artifact_dir: Path | None = None,
    min_severity: str = "high",
    min_confidence: str = "medium",
) -> BundleServiceResult:
    attack_results = load_attack_results_or_raise(results_path, label="current")
    baseline_results = (
        load_attack_results_or_raise(baseline_path, label="baseline")
        if baseline_path is not None
        else None
    )
    resolved_suppressions_path, suppression_rules = load_suppressions_or_default(suppressions_path)
    suppressions_yaml = (
        resolved_suppressions_path.read_text(encoding="utf-8")
        if resolved_suppressions_path is not None
        else None
    )
    if artifact_dir is not None and (not artifact_dir.exists() or not artifact_dir.is_dir()):
        raise ValueError(
            f"Artifact directory '{artifact_dir}' does not exist or is not a directory."
        )
    return BundleServiceResult(
        content=render_review_bundle(
            attack_results,
            name=out_name,
            baseline=baseline_results,
            suppressions_yaml=suppressions_yaml,
            artifact_dir=artifact_dir,
            min_severity=min_severity,
            min_confidence=min_confidence,
        ),
        suppressions_path=resolved_suppressions_path,
        suppressions=suppression_rules,
    )


def verify_results(
    results: AttackResults,
    *,
    baseline: AttackResults | None = None,
    suppressions: list[SuppressionRule] | None = None,
    min_severity: str = "high",
    min_confidence: str = "medium",
) -> VerificationResult:
    return evaluate_results_verification(
        results,
        baseline=baseline,
        min_severity=min_severity,
        min_confidence=min_confidence,
        suppressions=suppressions,
    )


def verify_results_from_paths(
    results_path: Path,
    *,
    baseline_path: Path | None = None,
    suppressions_path: Path | None = None,
    min_severity: str = "high",
    min_confidence: str = "medium",
) -> VerifyServiceResult:
    attack_results = load_attack_results_or_raise(results_path, label="current")
    baseline_results = (
        load_attack_results_or_raise(baseline_path, label="baseline")
        if baseline_path is not None
        else None
    )
    resolved_suppressions_path, suppression_rules = load_suppressions_or_default(suppressions_path)
    verification = verify_results(
        attack_results,
        baseline=baseline_results,
        suppressions=suppression_rules,
        min_severity=min_severity,
        min_confidence=min_confidence,
    )
    return VerifyServiceResult(
        verification=verification,
        suppressions_path=resolved_suppressions_path,
        suppressions=suppression_rules,
    )


def verify_results_from_models(
    results: AttackResults,
    *,
    baseline: AttackResults | None = None,
    suppressions_yaml: str | None = None,
    min_severity: str = "high",
    min_confidence: str = "medium",
) -> VerificationResult:
    return verify_results(
        results,
        baseline=baseline,
        suppressions=_load_suppressions_from_text(suppressions_yaml),
        min_severity=min_severity,
        min_confidence=min_confidence,
    )


def promote_results(
    current: AttackResults,
    attacks: AttackSuite,
    *,
    baseline: AttackResults | None = None,
    suppressions: list[SuppressionRule] | None = None,
    min_severity: str = "high",
    min_confidence: str = "medium",
) -> PromotionResult:
    try:
        return promote_attack_suite(
            current,
            attacks,
            baseline=baseline,
            min_severity=min_severity,
            min_confidence=min_confidence,
            suppressions=suppressions,
        )
    except PromotionError:
        raise


def promote_results_from_paths(
    results_path: Path,
    attacks_path: Path,
    *,
    baseline_path: Path | None = None,
    suppressions_path: Path | None = None,
    min_severity: str = "high",
    min_confidence: str = "medium",
) -> PromoteServiceResult:
    current_results = load_attack_results_or_raise(results_path, label="current")
    baseline_results = (
        load_attack_results_or_raise(baseline_path, label="baseline")
        if baseline_path is not None
        else None
    )
    attack_suite = load_attack_suite_or_raise(attacks_path)
    resolved_suppressions_path, suppression_rules = load_suppressions_or_default(suppressions_path)
    promotion = promote_results(
        current_results,
        attack_suite,
        baseline=baseline_results,
        suppressions=suppression_rules,
        min_severity=min_severity,
        min_confidence=min_confidence,
    )
    return PromoteServiceResult(
        promotion=promotion,
        suppressions_path=resolved_suppressions_path,
        suppressions=suppression_rules,
    )


def promote_results_from_models(
    current: AttackResults,
    attacks: AttackSuite,
    *,
    baseline: AttackResults | None = None,
    suppressions_yaml: str | None = None,
    min_severity: str = "high",
    min_confidence: str = "medium",
) -> PromotionResult:
    return promote_results(
        current,
        attacks,
        baseline=baseline,
        suppressions=_load_suppressions_from_text(suppressions_yaml),
        min_severity=min_severity,
        min_confidence=min_confidence,
    )


def triage_results(
    current_results: AttackResults,
    *,
    existing_rules: list[SuppressionRule],
) -> TriageServiceResult:
    comparison = compare_attack_results(current_results, suppressions=existing_rules)
    generated_rules = [triage_rule_for_result(result) for result in comparison.current_findings]
    merged_rules = merge_suppressions(existing_rules, generated_rules)
    suppressions_file = SuppressionsFile(suppressions=merged_rules)
    added_count = len(merged_rules) - len(existing_rules)
    return TriageServiceResult(
        comparison=comparison,
        suppressions_file=suppressions_file,
        added_count=added_count,
    )


def triage_results_from_path(
    results_path: Path,
    *,
    out_path: Path,
) -> TriageServiceResult:
    current_results = load_attack_results_or_raise(results_path, label="current")
    existing_file = SuppressionsFile()
    if out_path.exists():
        try:
            existing_file = load_suppressions(out_path)
        except (OSError, ValueError) as exc:
            raise ValueError(f"Could not read suppressions file '{out_path}': {exc}") from exc

    triage = triage_results(current_results, existing_rules=existing_file.suppressions)
    write_suppressions(out_path, triage.suppressions_file)
    return triage


def triage_results_from_model(
    current_results: AttackResults,
    *,
    existing_suppressions_yaml: str | None = None,
) -> tuple[SuppressionsFile, int]:
    existing_rules = _load_suppressions_from_text(existing_suppressions_yaml)
    triage = triage_results(current_results, existing_rules=existing_rules)
    return triage.suppressions_file, triage.added_count
