import type {
  ApiReportFormat,
  AttackResults,
  AttackSuite,
  DeleteJobResponse,
  DiscoverResponse,
  GenerateResponse,
  InspectResponse,
  JobArtifactDocument,
  JobFindingEvidenceResponse,
  JobStatusResponse,
  PruneJobsRequest,
  PruneJobsResponse,
  ProjectJobsResponse,
  ProjectListResponse,
  ProjectReviewRequest,
  ProjectReviewResponse,
  ProjectRecord,
  ProjectReviewDraft,
  ProjectSourceMode,
  PromoteResponse,
  ReportResponse,
  ResultsSummary,
  SourcePayload,
  TriageResponse,
  VerifyResponse,
} from "./types";
import { buildApiUrl, needsConfiguredApiBase } from "./apiConfig";

function requestFailureMessage(requestUrl: string, response: Response): string {
  return `Request to ${requestUrl} failed with ${response.status}${response.statusText ? ` ${response.statusText}` : ""}.`;
}

async function parseErrorMessage(response: Response, requestUrl: string): Promise<string> {
  const contentType = response.headers.get("content-type") ?? "";

  if (contentType.includes("application/json")) {
    try {
      const payload = (await response.json()) as Record<string, unknown>;
      const detail =
        typeof payload.detail === "string"
          ? payload.detail
          : typeof payload.message === "string"
            ? payload.message
            : null;
      if (detail) {
        return detail;
      }
    } catch {
      return requestFailureMessage(requestUrl, response);
    }
    return requestFailureMessage(requestUrl, response);
  }

  const text = (await response.text()).trim();
  if (contentType.includes("text/html")) {
    return `${requestFailureMessage(requestUrl, response)} The endpoint returned HTML instead of the JSON API. Check the configured API base URL.`;
  }
  if (!text) {
    return requestFailureMessage(requestUrl, response);
  }
  const snippet = text.replace(/\s+/g, " ").slice(0, 180);
  return `${requestFailureMessage(requestUrl, response)} ${snippet}`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  if (needsConfiguredApiBase()) {
    throw new Error("Set the API base URL before using the GitHub Pages workbench.");
  }

  const requestUrl = buildApiUrl(path);
  const response = await fetch(requestUrl, {
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
  });

  if (!response.ok) {
    throw new Error(await parseErrorMessage(response, requestUrl));
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error(
      `Request to ${requestUrl} succeeded but returned ${contentType || "non-JSON content"} instead of JSON.`,
    );
  }

  return (await response.json()) as T;
}

async function requestText(path: string, init?: RequestInit): Promise<string> {
  if (needsConfiguredApiBase()) {
    throw new Error("Set the API base URL before using the GitHub Pages workbench.");
  }

  const requestUrl = buildApiUrl(path);
  const response = await fetch(requestUrl, {
    ...init,
    headers: {
      ...(init?.headers ?? {}),
    },
  });

  if (!response.ok) {
    throw new Error(await parseErrorMessage(response, requestUrl));
  }

  return await response.text();
}

export function getHealthStatus() {
  return request<{ status: string }>("/healthz");
}

export function listProjects() {
  return request<ProjectListResponse>("/v1/projects");
}

export function createProject(
  input:
    | string
    | {
        name: string;
        source_mode?: ProjectSourceMode;
      },
) {
  const payload = typeof input === "string" ? { name: input } : input;
  return request<ProjectRecord>("/v1/projects", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getProject(projectId: string) {
  return request<ProjectRecord>(`/v1/projects/${projectId}`);
}

export function duplicateProject(projectId: string) {
  return request<ProjectRecord>(`/v1/projects/${projectId}/duplicate`, {
    method: "POST",
  });
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

export function deleteProjectJob(projectId: string, jobId: string) {
  return request<DeleteJobResponse>(`/v1/projects/${projectId}/jobs/${jobId}`, {
    method: "DELETE",
  });
}

export function pruneProjectJobs(projectId: string, payload: PruneJobsRequest) {
  return request<PruneJobsResponse>(`/v1/projects/${projectId}/jobs/prune`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function refreshProjectReview(
  projectId: string,
  review: ProjectReviewDraft | ProjectReviewRequest,
) {
  return request<ProjectReviewResponse>(`/v1/projects/${projectId}/review`, {
    method: "POST",
    body: JSON.stringify({
      baseline_mode: review.baseline_mode ?? null,
      baseline_job_id: review.baseline_job_id ?? null,
      baseline: review.baseline ?? null,
      suppressions_yaml: review.suppressions_yaml ?? null,
      min_severity: review.min_severity ?? null,
      min_confidence: review.min_confidence ?? null,
    }),
  });
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

export function getJobFindingEvidence(jobId: string, attackId: string) {
  return request<JobFindingEvidenceResponse>(
    `/v1/jobs/${encodeURIComponent(jobId)}/findings/${encodeURIComponent(attackId)}/evidence`,
  );
}

export async function getJobArtifact(jobId: string, artifactName: string): Promise<JobArtifactDocument> {
  const encodedName = artifactName
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  const text = await requestText(`/v1/jobs/${encodeURIComponent(jobId)}/artifacts/${encodedName}`);
  try {
    return {
      artifact_name: artifactName,
      format: "json",
      content: JSON.parse(text) as unknown,
    };
  } catch {
    return {
      artifact_name: artifactName,
      format: "text",
      content: text,
    };
  }
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
