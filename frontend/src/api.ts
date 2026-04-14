import type {
  ApiReportFormat,
  AttackResults,
  AttackSuite,
  DiscoverResponse,
  GenerateResponse,
  InspectResponse,
  JobStatusResponse,
  ProjectJobsResponse,
  ProjectListResponse,
  ProjectRecord,
  ProjectReviewDraft,
  PromoteResponse,
  ReportResponse,
  ResultsSummary,
  SourcePayload,
  TriageResponse,
  VerifyResponse,
} from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed with status ${response.status}.`);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export function listProjects() {
  return request<ProjectListResponse>("/v1/projects");
}

export function createProject(name: string) {
  return request<ProjectRecord>("/v1/projects", {
    method: "POST",
    body: JSON.stringify({ name }),
  });
}

export function getProject(projectId: string) {
  return request<ProjectRecord>(`/v1/projects/${projectId}`);
}

export function updateProject(projectId: string, project: Partial<ProjectRecord>) {
  return request<ProjectRecord>(`/v1/projects/${projectId}`, {
    method: "PATCH",
    body: JSON.stringify(project),
  });
}

export function deleteProject(projectId: string) {
  return request<{ deleted: boolean }>(`/v1/projects/${projectId}`, {
    method: "DELETE",
  });
}

export function listProjectJobs(projectId: string) {
  return request<ProjectJobsResponse>(`/v1/projects/${projectId}/jobs`);
}

export function inspectSource(payload: {
  source: SourcePayload;
  graphql_endpoint: string;
  tag: string[];
  exclude_tag: string[];
  path: string[];
  exclude_path: string[];
}) {
  return request<InspectResponse>("/v1/inspect", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function discoverModel(inputs: SourcePayload[]) {
  return request<DiscoverResponse>("/v1/discover", {
    method: "POST",
    body: JSON.stringify({ inputs }),
  });
}

export function generateSuite(payload: {
  source: SourcePayload;
  graphql_endpoint: string;
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
}) {
  return request<GenerateResponse>("/v1/generate", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function createRun(payload: {
  project_id: string;
  suite: AttackSuite;
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
}) {
  return request<JobStatusResponse>("/v1/runs", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getJobResult(jobId: string) {
  return request<AttackResults>(`/v1/jobs/${jobId}/result`);
}

export function summarizeResults(results: AttackResults, review: ProjectReviewDraft) {
  return request<ResultsSummary>("/v1/summary", {
    method: "POST",
    body: JSON.stringify({
      results,
      baseline: review.baseline ?? null,
      suppressions_yaml: review.suppressions_yaml ?? null,
      top_limit: 50,
    }),
  });
}

export function verifyResults(results: AttackResults, review: ProjectReviewDraft) {
  return request<VerifyResponse>("/v1/verify", {
    method: "POST",
    body: JSON.stringify({
      results,
      baseline: review.baseline ?? null,
      suppressions_yaml: review.suppressions_yaml ?? null,
      min_severity: review.min_severity,
      min_confidence: review.min_confidence,
    }),
  });
}

export function renderReport(
  results: AttackResults,
  review: ProjectReviewDraft,
  format: ApiReportFormat,
) {
  return request<ReportResponse>("/v1/report", {
    method: "POST",
    body: JSON.stringify({
      results,
      baseline: review.baseline ?? null,
      suppressions_yaml: review.suppressions_yaml ?? null,
      format,
    }),
  });
}

export function triageResults(results: AttackResults, review: ProjectReviewDraft) {
  return request<TriageResponse>("/v1/triage", {
    method: "POST",
    body: JSON.stringify({
      results,
      existing_suppressions_yaml: review.suppressions_yaml ?? null,
    }),
  });
}

export function promoteResults(
  results: AttackResults,
  suite: AttackSuite,
  review: ProjectReviewDraft,
) {
  return request<PromoteResponse>("/v1/promote", {
    method: "POST",
    body: JSON.stringify({
      results,
      attacks: suite,
      baseline: review.baseline ?? null,
      suppressions_yaml: review.suppressions_yaml ?? null,
      min_severity: review.min_severity,
      min_confidence: review.min_confidence,
    }),
  });
}
