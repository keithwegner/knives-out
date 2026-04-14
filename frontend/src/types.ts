export type ProjectSourceMode = "openapi" | "graphql" | "learned" | "capture_upload";
export type ProjectStep = "source" | "inspect" | "generate" | "run" | "review";
export type ApiJobStatus = "pending" | "running" | "completed" | "failed";
export type ApiReportFormat = "markdown" | "html";

export interface SourcePayload {
  name: string;
  content: string;
}

export interface PreflightWarning {
  code: string;
  message: string;
  operation_id?: string | null;
  method?: string | null;
  path?: string | null;
}

export interface OperationSpec {
  operation_id: string;
  method: string;
  path: string;
  protocol: string;
  summary?: string | null;
  tags: string[];
  auth_required: boolean;
  request_body_required: boolean;
  learned_confidence?: number | null;
}

export interface InspectResponse {
  source_kind: string;
  operations: OperationSpec[];
  warnings: PreflightWarning[];
  learned_workflow_count: number;
}

export interface AttackCase {
  type: "request" | "workflow";
  id: string;
  name: string;
  kind: string;
  operation_id: string;
  protocol: string;
  method: string;
  path: string;
  description: string;
  tags: string[];
  expected_outcomes?: string[];
  terminal_attack?: AttackCase;
}

export interface AttackSuite {
  source: string;
  generated_at: string;
  attacks: AttackCase[];
}

export interface LearnedModel {
  artifact_type: "learned-model";
  generated_at: string;
  source_inputs: string[];
  operations: OperationSpec[];
  workflows: Array<{
    id: string;
    name: string;
    producer_operation_id: string;
    consumer_operation_id: string;
    confidence: number;
    observation_count: number;
  }>;
  warnings: PreflightWarning[];
}

export interface DiscoverResponse {
  learned_model: LearnedModel;
}

export interface GenerateResponse {
  source_kind: string;
  suite: AttackSuite;
  warnings: PreflightWarning[];
}

export interface AuthEvent {
  name: string;
  strategy: string;
  phase: string;
  success: boolean;
  profile?: string | null;
  trigger?: string | null;
  endpoint?: string | null;
  status_code?: number | null;
  error?: string | null;
}

export interface ProfileAttackResult {
  profile: string;
  level: number;
  anonymous: boolean;
  url: string;
  status_code?: number | null;
  issue?: string | null;
  severity: string;
  confidence: string;
}

export interface AttackResult {
  type: "request" | "workflow";
  attack_id: string;
  operation_id: string;
  kind: string;
  name: string;
  protocol: string;
  method: string;
  path?: string | null;
  tags: string[];
  url: string;
  status_code?: number | null;
  error?: string | null;
  duration_ms?: number | null;
  flagged: boolean;
  issue?: string | null;
  severity: string;
  confidence: string;
  response_schema_status?: string | null;
  response_schema_valid?: boolean | null;
  graphql_response_valid?: boolean | null;
  workflow_steps?: Array<{
    name: string;
    operation_id: string;
    method: string;
    url: string;
    status_code?: number | null;
    error?: string | null;
  }> | null;
  profile_results?: ProfileAttackResult[] | null;
}

export interface AttackResults {
  source: string;
  base_url: string;
  executed_at: string;
  profiles: string[];
  auth_events: AuthEvent[];
  results: AttackResult[];
}

export interface SummaryFinding {
  attack_id: string;
  name: string;
  protocol: string;
  kind: string;
  issue?: string | null;
  severity: string;
  confidence: string;
  status_code?: number | null;
  url: string;
  schema_status: string;
}

export interface AuthSummaryEntry {
  profile: string;
  name: string;
  strategy: string;
  acquire: number;
  refresh: number;
  failures: number;
  triggers: string[];
}

export interface ResultsSummary {
  source: string;
  base_url: string;
  executed_at: string;
  baseline_used: boolean;
  baseline_executed_at?: string | null;
  total_results: number;
  profile_count: number;
  profile_names: string[];
  active_flagged_count: number;
  suppressed_flagged_count: number;
  new_findings_count: number;
  resolved_findings_count: number;
  persisting_findings_count: number;
  persisting_deltas_count: number;
  auth_failures: number;
  refresh_attempts: number;
  response_schema_mismatches: number;
  graphql_shape_mismatches: number;
  protocol_counts: Record<string, number>;
  issue_counts: Record<string, number>;
  finding_severity_counts: Record<string, number>;
  finding_confidence_counts: Record<string, number>;
  auth_summary: AuthSummaryEntry[];
  top_findings: SummaryFinding[];
}

export interface DeltaChangeResponse {
  field: string;
  baseline: string;
  current: string;
}

export interface FindingSummaryResponse {
  change: string;
  attack_id: string;
  name: string;
  protocol: string;
  kind: string;
  method: string;
  path?: string | null;
  tags: string[];
  issue?: string | null;
  severity: string;
  confidence: string;
  status_code?: number | null;
  url: string;
  delta_changes: DeltaChangeResponse[];
}

export interface VerifyResponse {
  passed: boolean;
  baseline_used: boolean;
  min_severity: string;
  min_confidence: string;
  current_findings_count: number;
  new_findings_count: number;
  resolved_findings_count: number;
  persisting_findings_count: number;
  suppressed_current_findings_count: number;
  current_findings: FindingSummaryResponse[];
  failing_findings: FindingSummaryResponse[];
  new_findings: FindingSummaryResponse[];
  resolved_findings: FindingSummaryResponse[];
  persisting_findings: FindingSummaryResponse[];
}

export interface SuppressionRule {
  attack_id?: string | null;
  issue?: string | null;
  operation_id?: string | null;
  method?: string | null;
  path?: string | null;
  kind?: string | null;
  tags: string[];
  reason: string;
  owner: string;
  expires_on?: string | null;
}

export interface SuppressionsFile {
  suppressions: SuppressionRule[];
}

export interface TriageResponse {
  suppressions: SuppressionsFile;
  added_count: number;
  rendered_yaml: string;
}

export interface PromoteResponse {
  promoted_suite: AttackSuite;
  promoted_attack_ids: string[];
  baseline_used: boolean;
}

export interface ReportResponse {
  format: ApiReportFormat;
  content: string;
}

export interface JobStatusResponse {
  id: string;
  kind: string;
  status: ApiJobStatus;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  base_url: string;
  attack_count: number;
  project_id?: string | null;
  error?: string | null;
  result_available: boolean;
  artifact_names: string[];
  result_summary?: ResultsSummary | null;
}

export interface ProjectInspectDraft {
  tag: string[];
  exclude_tag: string[];
  path: string[];
  exclude_path: string[];
}

export interface ProjectGenerateDraft {
  operation: string[];
  exclude_operation: string[];
  method: string[];
  exclude_method: string[];
  kind: string[];
  exclude_kind: string[];
  tag: string[];
  exclude_tag: string[];
  path: string[];
  exclude_path: string[];
  pack_names: string[];
  auto_workflows: boolean;
  workflow_pack_names: string[];
}

export interface ProjectRunDraft {
  base_url: string;
  headers: Record<string, string>;
  query: Record<string, unknown>;
  timeout: number;
  store_artifacts: boolean;
  auth_plugin_names: string[];
  auth_config_yaml?: string | null;
  auth_profile_names: string[];
  profile_file_yaml?: string | null;
  profile_names: string[];
  operation: string[];
  exclude_operation: string[];
  method: string[];
  exclude_method: string[];
  kind: string[];
  exclude_kind: string[];
  tag: string[];
  exclude_tag: string[];
  path: string[];
  exclude_path: string[];
}

export interface ProjectReviewDraft {
  baseline_job_id?: string | null;
  baseline?: AttackResults | null;
  suppressions_yaml?: string | null;
  min_severity: string;
  min_confidence: string;
}

export interface ProjectArtifacts {
  learned_model?: LearnedModel | null;
  inspect_result?: InspectResponse | null;
  generated_suite?: AttackSuite | null;
  latest_results?: AttackResults | null;
  latest_summary?: ResultsSummary | null;
  latest_verification?: VerifyResponse | null;
  latest_markdown_report?: string | null;
  latest_html_report?: string | null;
  latest_suppressions?: SuppressionsFile | null;
  latest_promoted_suite?: AttackSuite | null;
  last_run_job_id?: string | null;
}

export interface ProjectRecord {
  id: string;
  name: string;
  source_mode: ProjectSourceMode;
  active_step: ProjectStep;
  created_at: string;
  updated_at: string;
  graphql_endpoint: string;
  source?: SourcePayload | null;
  discover_inputs: SourcePayload[];
  inspect_draft: ProjectInspectDraft;
  generate_draft: ProjectGenerateDraft;
  run_draft: ProjectRunDraft;
  review_draft: ProjectReviewDraft;
  artifacts: ProjectArtifacts;
}

export interface ProjectSummaryResponse {
  id: string;
  name: string;
  source_mode: ProjectSourceMode;
  active_step: ProjectStep;
  created_at: string;
  updated_at: string;
  source_name?: string | null;
  job_count: number;
  last_run_job_id?: string | null;
  last_run_status?: ApiJobStatus | null;
  last_run_at?: string | null;
  active_flagged_count?: number | null;
}

export interface ProjectListResponse {
  projects: ProjectSummaryResponse[];
}

export interface ProjectJobsResponse {
  project_id: string;
  jobs: JobStatusResponse[];
}
