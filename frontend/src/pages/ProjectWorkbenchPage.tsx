import {
  startTransition,
  useDeferredValue,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { getApiBaseUrl, needsConfiguredApiBase, persistApiBaseUrl } from "../apiConfig";
import ApiConnectionPanel from "../components/ApiConnectionPanel";
import CodeEditor from "../components/CodeEditor";
import {
  buildJobArtifactUrl,
  createRun,
  deleteProjectJob,
  discoverModel,
  duplicateProject,
  fetchJobArtifactText,
  generateSuite,
  getJobResult,
  getProject,
  inspectSource,
  listProjectJobs,
  promoteResults,
  pruneProjectJobs,
  renderReport,
  summarizeResults,
  triageResults,
  updateProject,
  verifyResults,
} from "../api";
import type {
  ApiJobStatus,
  AttackResults,
  AttackSuite,
  FindingSummaryResponse,
  JobStatusResponse,
  PruneJobsRequest,
  PruneJobsResponse,
  ProjectRecord,
  ProjectReviewDraft,
  ProjectSourceMode,
  ProjectStep,
  SourcePayload,
} from "../types";

type ReviewTab =
  | "summary"
  | "findings"
  | "deltas"
  | "auth"
  | "artifacts"
  | "suppressions"
  | "promote";

type FindingScope = "current" | "new" | "resolved" | "persisting";
type RunHistoryFilter = "all" | "active" | "completed" | "failed";
type ArtifactPreviewMode = "structured" | "raw";

const STEP_ORDER: ProjectStep[] = ["source", "inspect", "generate", "run", "review"];
const PRUNEABLE_JOB_STATUSES: ApiJobStatus[] = ["completed", "failed"];

type ArtifactPreviewRecord = {
  attack: {
    id?: string;
    name?: string;
    kind?: string;
    operation_id?: string;
    path?: string | null;
  };
  request: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    query?: Record<string, unknown>;
    body?: {
      present?: boolean;
      kind?: string;
      content_type?: string | null;
      excerpt?: string | null;
    } | null;
  };
  response: {
    status_code?: number | null;
    error?: string | null;
    duration_ms?: number | null;
    body_excerpt?: string | null;
  };
};

function defaultSourceForMode(mode: ProjectSourceMode): SourcePayload | null {
  if (mode === "openapi") {
    return { name: "openapi.yaml", content: "" };
  }
  if (mode === "graphql") {
    return { name: "schema.graphql", content: "" };
  }
  if (mode === "learned") {
    return { name: "learned-model.json", content: "" };
  }
  return null;
}

function normalizeList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatList(values: string[]): string {
  return values.join(", ");
}

function formatJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) {
    return "—";
  }
  return new Date(value).toLocaleString();
}

function jobTimestamp(job: JobStatusResponse): string {
  return job.completed_at ?? job.started_at ?? job.created_at;
}

function shortJobId(jobId: string | null | undefined): string {
  return jobId ? jobId.slice(0, 8) : "manual";
}

function formatJobOptionLabel(job: JobStatusResponse): string {
  const flaggedCount = job.result_summary?.active_flagged_count ?? 0;
  return `${shortJobId(job.id)} • ${formatDateTime(jobTimestamp(job))} • ${flaggedCount} flagged`;
}

function formatArtifactJobOptionLabel(job: JobStatusResponse): string {
  return `${shortJobId(job.id)} • ${formatDateTime(jobTimestamp(job))} • ${job.artifact_names.length} artifact(s)`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return isRecord(value) && Object.values(value).every((entry) => typeof entry === "string");
}

function isArtifactPreviewRecord(value: unknown): value is ArtifactPreviewRecord {
  if (!isRecord(value)) {
    return false;
  }
  const attack = value.attack;
  const request = value.request;
  const response = value.response;
  const headers = isRecord(request) ? request.headers : null;
  return (
    isRecord(attack) &&
    isRecord(request) &&
    typeof request.method === "string" &&
    typeof request.url === "string" &&
    (headers == null || isStringRecord(headers)) &&
    isRecord(response)
  );
}

function parseArtifactPreview(text: string): {
  structured: ArtifactPreviewRecord | null;
  raw: string;
} {
  try {
    const parsed = JSON.parse(text) as unknown;
    return {
      structured: isArtifactPreviewRecord(parsed) ? parsed : null,
      raw: formatJson(parsed),
    };
  } catch {
    return {
      structured: null,
      raw: text,
    };
  }
}

function defaultArtifactSelection(
  jobs: JobStatusResponse[],
  options: {
    currentRunJob: JobStatusResponse | null;
    baselineJob: JobStatusResponse | null;
  },
): { jobId: string; artifactName: string } | null {
  const { currentRunJob, baselineJob } = options;
  const preferredJobs = [
    currentRunJob && currentRunJob.artifact_names.length ? currentRunJob : null,
    baselineJob &&
    baselineJob.artifact_names.length &&
    baselineJob.id !== currentRunJob?.id
      ? baselineJob
      : null,
    ...jobs.filter((job) => job.id !== currentRunJob?.id && job.id !== baselineJob?.id),
  ].filter((job): job is JobStatusResponse => Boolean(job));

  const selectedJob = preferredJobs[0];
  if (!selectedJob || !selectedJob.artifact_names.length) {
    return null;
  }
  return {
    jobId: selectedJob.id,
    artifactName: selectedJob.artifact_names[0],
  };
}

function toTrustedHttpUrl(value: string | null | undefined): URL | null {
  if (!value) {
    return null;
  }
  try {
    const baseOrigin = typeof window === "undefined" ? "http://localhost" : window.location.origin;
    const candidate = new URL(value, baseOrigin);
    if (candidate.protocol !== "http:" && candidate.protocol !== "https:") {
      return null;
    }
    return candidate;
  } catch {
    return null;
  }
}

function filterFindings(findings: FindingSummaryResponse[], filter: string) {
  return findings.filter((finding) => {
    if (!filter) {
      return true;
    }
    const haystack = [
      finding.attack_id,
      finding.name,
      finding.kind,
      finding.issue ?? "",
      finding.method,
      finding.path ?? "",
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(filter);
  });
}

async function analyzeReviewArtifacts(results: AttackResults, reviewDraft: ProjectReviewDraft) {
  const [summary, verification, markdownReport, htmlReport] = await Promise.all([
    summarizeResults(results, reviewDraft),
    verifyResults(results, reviewDraft),
    renderReport(results, reviewDraft, "markdown"),
    renderReport(results, reviewDraft, "html"),
  ]);

  return {
    latest_summary: summary,
    latest_verification: verification,
    latest_markdown_report: markdownReport.content,
    latest_html_report: htmlReport.content,
  };
}

function buildProjectPatch(project: ProjectRecord) {
  return {
    name: project.name,
    source_mode: project.source_mode,
    active_step: project.active_step,
    graphql_endpoint: project.graphql_endpoint,
    source: project.source,
    discover_inputs: project.discover_inputs,
    inspect_draft: project.inspect_draft,
    generate_draft: project.generate_draft,
    run_draft: project.run_draft,
    review_draft: project.review_draft,
    artifacts: project.artifacts,
  };
}

function statusTone(status: ApiJobStatus | "idle") {
  if (status === "completed") {
    return "status-completed";
  }
  if (status === "failed") {
    return "status-failed";
  }
  if (status === "running") {
    return "status-running";
  }
  if (status === "pending") {
    return "status-pending";
  }
  return "status-idle";
}

function isPruneableJobStatus(status: ApiJobStatus): boolean {
  return PRUNEABLE_JOB_STATUSES.includes(status);
}

function matchesRunHistoryFilter(job: JobStatusResponse, filter: RunHistoryFilter): boolean {
  if (filter === "all") {
    return true;
  }
  if (filter === "active") {
    return job.status === "pending" || job.status === "running";
  }
  return job.status === filter;
}

function ReviewTable({
  headings,
  rows,
  emptyCopy,
}: {
  headings: string[];
  rows: Array<Array<ReactNode | null | undefined>>;
  emptyCopy: string;
}) {
  return (
    <div className="table-shell">
      <table className="data-table">
        <thead>
          <tr>
            {headings.map((heading) => (
              <th key={heading}>{heading}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length ? (
            rows.map((row, index) => (
              <tr key={`row-${index}`}>
                {row.map((value, cellIndex) => (
                  <td key={`${index}-${cellIndex}`}>{value ?? "—"}</td>
                ))}
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={headings.length} className="table-empty">
                {emptyCopy}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function ListField({
  label,
  value,
  placeholder,
  onChange,
}: {
  label: string;
  value: string[];
  placeholder: string;
  onChange: (value: string[]) => void;
}) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      <input
        className="text-input"
        value={formatList(value)}
        onChange={(event) => onChange(normalizeList(event.target.value))}
        placeholder={placeholder}
      />
    </label>
  );
}

function StepRail({
  activeStep,
  onChange,
}: {
  activeStep: ProjectStep;
  onChange: (step: ProjectStep) => void;
}) {
  return (
    <nav className="step-rail" aria-label="Workbench steps">
      {STEP_ORDER.map((step, index) => (
        <button
          className={`step-rail-button${step === activeStep ? " step-rail-button-active" : ""}`}
          key={step}
          onClick={() => onChange(step)}
          type="button"
        >
          <span className="step-rail-index">0{index + 1}</span>
          <span className="step-rail-name">{step}</span>
        </button>
      ))}
    </nav>
  );
}

export default function ProjectWorkbenchPage() {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<ProjectRecord | null>(null);
  const [apiBaseUrl, setApiBaseUrl] = useState(() => getApiBaseUrl());
  const [hasPendingSave, setHasPendingSave] = useState(false);
  const [sourceText, setSourceText] = useState("");
  const [headersText, setHeadersText] = useState("{}");
  const [queryText, setQueryText] = useState("{}");
  const [baselineText, setBaselineText] = useState("");
  const [authConfigText, setAuthConfigText] = useState("");
  const [profileFileText, setProfileFileText] = useState("");
  const [suppressionsText, setSuppressionsText] = useState("");
  const [headersError, setHeadersError] = useState<string | null>(null);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [baselineError, setBaselineError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [activityMessage, setActivityMessage] = useState<string | null>(null);
  const [reviewTab, setReviewTab] = useState<ReviewTab>("summary");
  const [findingScope, setFindingScope] = useState<FindingScope>("current");
  const [reviewFilter, setReviewFilter] = useState("");
  const [runHistoryFilter, setRunHistoryFilter] = useState<RunHistoryFilter>("all");
  const [selectedArtifactJobId, setSelectedArtifactJobId] = useState<string | null>(null);
  const [selectedArtifactName, setSelectedArtifactName] = useState<string | null>(null);
  const [artifactPreviewMode, setArtifactPreviewMode] = useState<ArtifactPreviewMode>("structured");
  const [artifactPreviewRecord, setArtifactPreviewRecord] = useState<ArtifactPreviewRecord | null>(
    null,
  );
  const [artifactPreviewText, setArtifactPreviewText] = useState("");
  const [artifactPreviewError, setArtifactPreviewError] = useState<string | null>(null);
  const [artifactPreviewLoading, setArtifactPreviewLoading] = useState(false);
  const [artifactActionBusy, setArtifactActionBusy] = useState<"download" | null>(null);
  const [trackedJobId, setTrackedJobId] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [pruneStatuses, setPruneStatuses] = useState<ApiJobStatus[]>([
    "completed",
    "failed",
  ]);
  const [pruneCompletedBefore, setPruneCompletedBefore] = useState("");
  const [pruneLimit, setPruneLimit] = useState("10");
  const [prunePreview, setPrunePreview] = useState<PruneJobsResponse | null>(null);
  const syncedJobIdRef = useRef<string | null>(null);
  const deferredReviewFilter = useDeferredValue(reviewFilter.trim().toLowerCase());
  const requiresApiBase = needsConfiguredApiBase(apiBaseUrl);

  const projectQuery = useQuery({
    queryKey: ["project", projectId, apiBaseUrl],
    queryFn: () => getProject(projectId!),
    enabled: Boolean(projectId) && !requiresApiBase,
    retry: false,
  });

  const projectJobsQuery = useQuery({
    queryKey: ["projectJobs", projectId, apiBaseUrl],
    queryFn: () => listProjectJobs(projectId!),
    enabled: Boolean(projectId) && !requiresApiBase,
    refetchInterval: trackedJobId ? 1500 : false,
    retry: false,
  });

  const saveProjectMutation = useMutation({
    mutationFn: (project: ProjectRecord) => updateProject(project.id, buildProjectPatch(project)),
    onSuccess: (project) => {
      queryClient.setQueryData(["project", project.id], project);
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      setDraft(project);
      hydrateTextBuffers(project);
      setHasPendingSave(false);
    },
  });

  function hydrateTextBuffers(project: ProjectRecord) {
    setSourceText(project.source?.content ?? "");
    setHeadersText(formatJson(project.run_draft.headers));
    setQueryText(formatJson(project.run_draft.query));
    setBaselineText(project.review_draft.baseline ? formatJson(project.review_draft.baseline) : "");
    setAuthConfigText(project.run_draft.auth_config_yaml ?? "");
    setProfileFileText(project.run_draft.profile_file_yaml ?? "");
    setSuppressionsText(project.review_draft.suppressions_yaml ?? "");
    setHeadersError(null);
    setQueryError(null);
    setBaselineError(null);
  }

  function applyDraftUpdate(updater: (current: ProjectRecord) => ProjectRecord) {
    setDraft((current) => {
      if (!current) {
        return current;
      }
      return updater(current);
    });
    setHasPendingSave(true);
  }

  function getLoadedProject(): ProjectRecord {
    if (!draft) {
      throw new Error("Project is not loaded yet.");
    }
    return draft;
  }

  function applyApiBase(nextValue: string) {
    const normalized = persistApiBaseUrl(nextValue);
    setApiBaseUrl(normalized);
    setDraft(null);
    setActionError(null);
    void queryClient.invalidateQueries();
  }

  useEffect(() => {
    if (!projectQuery.data) {
      return;
    }
    if (hasPendingSave || saveProjectMutation.isPending) {
      return;
    }
    setDraft(projectQuery.data);
    hydrateTextBuffers(projectQuery.data);
  }, [projectQuery.data, hasPendingSave, saveProjectMutation.isPending]);

  useEffect(() => {
    if (!draft || !hasPendingSave) {
      return;
    }
    const timer = window.setTimeout(() => {
      saveProjectMutation.mutate(draft);
    }, 650);
    return () => window.clearTimeout(timer);
  }, [draft, hasPendingSave, saveProjectMutation]);

  useEffect(() => {
    const job = projectJobsQuery.data?.jobs.find((candidate) => candidate.id === trackedJobId);
    if (!draft || !job || job.id === syncedJobIdRef.current) {
      return;
    }

    if (job.status === "failed") {
      syncedJobIdRef.current = job.id;
      setTrackedJobId(null);
      setActivityMessage("Run failed. Check the run history panel for details.");
      return;
    }

    if (job.status !== "completed" || !job.result_available) {
      return;
    }

    syncedJobIdRef.current = job.id;
    setBusyAction("refresh-review");
    void (async () => {
      try {
        const results = await getJobResult(job.id);
        const reviewDraft: ProjectReviewDraft = draft.review_draft;
        const reviewArtifacts = await analyzeReviewArtifacts(results, reviewDraft);
        applyDraftUpdate((current) => ({
          ...current,
          active_step: "review",
          artifacts: {
            ...current.artifacts,
            last_run_job_id: job.id,
            latest_results: results,
            ...reviewArtifacts,
          },
        }));
        setActivityMessage("Run finished and the review workspace is up to date.");
        setActionError(null);
      } catch (error) {
        setActionError(error instanceof Error ? error.message : "Could not refresh review data.");
      } finally {
        setBusyAction(null);
        setTrackedJobId(null);
      }
    })();
  }, [draft, projectJobsQuery.data, trackedJobId]);

  useEffect(() => {
    setPrunePreview(null);
  }, [pruneCompletedBefore, pruneLimit, pruneStatuses]);

  const currentJobs = projectJobsQuery.data?.jobs ?? [];
  const latestJob = currentJobs[0] ?? null;
  const currentRunJob = draft
    ? currentJobs.find((job) => job.id === draft.artifacts.last_run_job_id) ?? latestJob
    : latestJob;
  const selectedBaselineJob =
    draft?.review_draft.baseline_job_id != null
      ? currentJobs.find((job) => job.id === draft.review_draft.baseline_job_id) ?? null
      : null;
  const artifactSourceJobs = currentJobs.filter((job) => job.artifact_names.length > 0);
  const selectedArtifactJob =
    selectedArtifactJobId != null
      ? artifactSourceJobs.find((job) => job.id === selectedArtifactJobId) ?? null
      : null;
  const selectedArtifactUrl =
    selectedArtifactJobId && selectedArtifactName
      ? buildJobArtifactUrl(selectedArtifactJobId, selectedArtifactName)
      : null;
  const selectedArtifactLink = toTrustedHttpUrl(selectedArtifactUrl);

  useEffect(() => {
    if (!artifactSourceJobs.length) {
      setSelectedArtifactJobId(null);
      setSelectedArtifactName(null);
      setArtifactPreviewRecord(null);
      setArtifactPreviewText("");
      setArtifactPreviewError(null);
      setArtifactPreviewLoading(false);
      return;
    }

    if (selectedArtifactJobId != null) {
      const matchingJob = artifactSourceJobs.find((job) => job.id === selectedArtifactJobId);
      if (matchingJob) {
        if (selectedArtifactName && matchingJob.artifact_names.includes(selectedArtifactName)) {
          return;
        }
        setSelectedArtifactName(matchingJob.artifact_names[0] ?? null);
        setArtifactPreviewMode("structured");
        return;
      }
    }

    const nextSelection = defaultArtifactSelection(artifactSourceJobs, {
      currentRunJob,
      baselineJob: selectedBaselineJob,
    });
    if (!nextSelection) {
      return;
    }
    setSelectedArtifactJobId(nextSelection.jobId);
    setSelectedArtifactName(nextSelection.artifactName);
    setArtifactPreviewMode("structured");
  }, [
    artifactSourceJobs,
    currentRunJob,
    selectedBaselineJob,
    selectedArtifactJobId,
    selectedArtifactName,
  ]);

  useEffect(() => {
    if (reviewTab !== "artifacts") {
      setArtifactPreviewLoading(false);
      return;
    }
    if (!selectedArtifactJobId || !selectedArtifactName) {
      setArtifactPreviewLoading(false);
      setArtifactPreviewRecord(null);
      setArtifactPreviewText("");
      setArtifactPreviewError(null);
      return;
    }

    let cancelled = false;
    setArtifactPreviewLoading(true);
    setArtifactPreviewError(null);
    void (async () => {
      try {
        const previewText = await fetchJobArtifactText(selectedArtifactJobId, selectedArtifactName);
        if (cancelled) {
          return;
        }
        const preview = parseArtifactPreview(previewText);
        setArtifactPreviewRecord(preview.structured);
        setArtifactPreviewText(preview.raw);
        setArtifactPreviewMode(preview.structured ? "structured" : "raw");
      } catch (error) {
        if (cancelled) {
          return;
        }
        setArtifactPreviewRecord(null);
        setArtifactPreviewText("");
        setArtifactPreviewError(
          error instanceof Error ? error.message : "Could not load the selected artifact.",
        );
      } finally {
        if (!cancelled) {
          setArtifactPreviewLoading(false);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [reviewTab, selectedArtifactJobId, selectedArtifactName]);

  if (!projectId) {
    return (
      <main className="shell">
        <section className="panel">
          <p className="empty-copy">Missing project id.</p>
        </section>
      </main>
    );
  }

  if (requiresApiBase) {
    return (
      <main className="shell">
        <section className="panel stack">
          <div>
            <p className="eyebrow">Workbench unavailable</p>
            <h2>Connect the API before loading this project</h2>
            <p className="hero-body">
              This GitHub Pages deployment only hosts the frontend shell. Set the API base URL to a
              reachable knives-out server, then reopen the project.
            </p>
          </div>
          <ApiConnectionPanel
            apiBaseUrl={apiBaseUrl}
            description="Saved projects, jobs, and review data live on the API backend. Once the endpoint is set, the workbench will load this project from there."
            onApply={applyApiBase}
            statusLabel="configure API"
            statusTone="idle"
            title="Reconnect the workbench"
          />
          <div className="action-row">
            <Link className="ghost-button" to="/">
              Back to projects
            </Link>
          </div>
        </section>
      </main>
    );
  }

  if (projectQuery.isError) {
    const errorMessage =
      projectQuery.error instanceof Error ? projectQuery.error.message : "Could not load the project.";
    return (
      <main className="shell">
        <section className="panel stack">
          <div>
            <p className="eyebrow">Workbench unavailable</p>
            <h2>Could not load this project</h2>
            <p className="hero-body">{errorMessage}</p>
          </div>
          <ApiConnectionPanel
            apiBaseUrl={apiBaseUrl}
            description="If you are using GitHub Pages or another static host, point the workbench at a reachable knives-out API and try again."
            onApply={applyApiBase}
            statusLabel="retry setup"
            statusTone="failed"
            title="Reconnect the workbench"
          />
          <div className="action-row">
            <Link className="ghost-button" to="/">
              Back to projects
            </Link>
          </div>
        </section>
      </main>
    );
  }

  if (projectQuery.isLoading || !draft) {
    return (
      <main className="shell">
        <section className="panel">
          <p className="empty-copy">Loading workbench…</p>
        </section>
      </main>
    );
  }

  const runHistoryJobs = currentJobs.filter((job) => matchesRunHistoryFilter(job, runHistoryFilter));
  const pruneableJobCount = currentJobs.filter((job) => isPruneableJobStatus(job.status)).length;
  const baselineCandidates = currentJobs.filter(
    (job) => job.status === "completed" && job.result_available && job.id !== currentRunJob?.id,
  );
  const reviewVerification = draft.artifacts.latest_verification;
  const findingBuckets = {
    current: filterFindings(reviewVerification?.current_findings ?? [], deferredReviewFilter),
    new: filterFindings(reviewVerification?.new_findings ?? [], deferredReviewFilter),
    resolved: filterFindings(reviewVerification?.resolved_findings ?? [], deferredReviewFilter),
    persisting: filterFindings(
      reviewVerification?.persisting_findings ?? [],
      deferredReviewFilter,
    ),
  };
  const findingScopeRows = findingBuckets[findingScope];
  const baselineDescription = selectedBaselineJob
    ? `Run ${shortJobId(selectedBaselineJob.id)} • ${formatDateTime(jobTimestamp(selectedBaselineJob))}`
    : draft.review_draft.baseline
      ? `Manual baseline • ${formatDateTime(draft.review_draft.baseline.executed_at)}`
      : "No comparison baseline selected";
  const selectedArtifactNames = selectedArtifactJob?.artifact_names ?? [];

  async function handleSourceUpload(files: FileList | null) {
    if (!files?.length) {
      return;
    }
    const file = files[0];
    const content = await file.text();
    setSourceText(content);
    applyDraftUpdate((current) => ({
      ...current,
      source: { name: file.name, content },
    }));
  }

  async function handleCaptureUpload(files: FileList | null) {
    if (!files?.length) {
      return;
    }
    const uploaded = await Promise.all(
      Array.from(files).map(async (file) => ({
        name: file.name,
        content: await file.text(),
      })),
    );
    applyDraftUpdate((current) => ({
      ...current,
      discover_inputs: uploaded,
    }));
  }

  async function handleInspect() {
    const project = getLoadedProject();
    if (!project.source) {
      setActionError("Add a source document before inspecting.");
      return;
    }
    setBusyAction("inspect");
    setActionError(null);
    try {
      const inspected = await inspectSource({
        source: project.source,
        graphql_endpoint: project.graphql_endpoint,
        ...project.inspect_draft,
      });
      applyDraftUpdate((current) => ({
        ...current,
        active_step: "inspect",
        artifacts: {
          ...current.artifacts,
          inspect_result: inspected,
        },
      }));
      setActivityMessage(`Inspected ${inspected.operations.length} operation(s).`);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Inspect failed.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleDiscover() {
    const project = getLoadedProject();
    if (!project.discover_inputs.length) {
      setActionError("Upload at least one capture NDJSON or HAR file first.");
      return;
    }
    setBusyAction("discover");
    setActionError(null);
    try {
      const discovered = await discoverModel(project.discover_inputs);
      const content = formatJson(discovered.learned_model);
      setSourceText(content);
      applyDraftUpdate((current) => ({
        ...current,
        source_mode: "learned",
        active_step: "inspect",
        source: { name: "learned-model.json", content },
        artifacts: {
          ...current.artifacts,
          learned_model: discovered.learned_model,
        },
      }));
      setActivityMessage(
        `Discovered ${discovered.learned_model.operations.length} learned operation(s).`,
      );
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Discover failed.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleGenerate() {
    const project = getLoadedProject();
    if (!project.source) {
      setActionError("Add a source before generating attacks.");
      return;
    }
    setBusyAction("generate");
    setActionError(null);
    try {
      const generated = await generateSuite({
        source: project.source,
        graphql_endpoint: project.graphql_endpoint,
        ...project.generate_draft,
      });
      applyDraftUpdate((current) => ({
        ...current,
        active_step: "run",
        artifacts: {
          ...current.artifacts,
          generated_suite: generated.suite,
        },
      }));
      setActivityMessage(`Generated ${generated.suite.attacks.length} attack(s).`);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Generate failed.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRun() {
    const project = getLoadedProject();
    if (!project.artifacts.generated_suite) {
      setActionError("Generate an attack suite before running.");
      return;
    }
    if (!project.run_draft.base_url.trim()) {
      setActionError("Add a base URL before starting a run.");
      return;
    }
    if (headersError || queryError) {
      setActionError("Fix JSON errors in the run settings before starting a run.");
      return;
    }
    setBusyAction("run");
    setActionError(null);
    try {
      const job = await createRun({
        project_id: project.id,
        suite: project.artifacts.generated_suite,
        ...project.run_draft,
      });
      syncedJobIdRef.current = null;
      setTrackedJobId(job.id);
      applyDraftUpdate((current) => ({
        ...current,
        active_step: "review",
        artifacts: {
          ...current.artifacts,
          last_run_job_id: job.id,
        },
      }));
      projectJobsQuery.refetch();
      setActivityMessage("Run started. The review step will refresh when it completes.");
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Run could not be started.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRefreshReview() {
    const project = getLoadedProject();
    if (!project.artifacts.latest_results) {
      setActionError("Run a suite first so there is data to analyze.");
      return;
    }
    if (baselineError) {
      setActionError("Fix baseline JSON before refreshing the review workspace.");
      return;
    }
    setBusyAction("refresh-review");
    setActionError(null);
    try {
      const reviewArtifacts = await analyzeReviewArtifacts(
        project.artifacts.latest_results,
        project.review_draft,
      );
      applyDraftUpdate((current) => ({
        ...current,
        artifacts: {
          ...current.artifacts,
          ...reviewArtifacts,
        },
      }));
      setActivityMessage("Review panels refreshed.");
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Could not refresh review panels.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleBaselineSelection(jobId: string) {
    if (!jobId) {
      await handleClearBaseline();
      return;
    }

    const project = getLoadedProject();
    if (project.review_draft.baseline_job_id === jobId && project.review_draft.baseline) {
      return;
    }

    setBusyAction("baseline");
    setActionError(null);
    try {
      const baseline = await getJobResult(jobId);
      const nextReviewDraft: ProjectReviewDraft = {
        ...project.review_draft,
        baseline_job_id: jobId,
        baseline,
      };
      setBaselineText(formatJson(baseline));
      setBaselineError(null);
      const reviewArtifacts = project.artifacts.latest_results
        ? await analyzeReviewArtifacts(project.artifacts.latest_results, nextReviewDraft)
        : null;
      applyDraftUpdate((current) => ({
        ...current,
        review_draft: nextReviewDraft,
        artifacts: reviewArtifacts
          ? {
              ...current.artifacts,
              ...reviewArtifacts,
            }
          : current.artifacts,
      }));
      setActivityMessage(`Using run ${shortJobId(jobId)} as the comparison baseline.`);
      setReviewTab("summary");
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Could not load the selected run.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleClearBaseline() {
    const project = getLoadedProject();
    setBusyAction("baseline");
    setActionError(null);
    try {
      const nextReviewDraft: ProjectReviewDraft = {
        ...project.review_draft,
        baseline_job_id: null,
        baseline: null,
      };
      setBaselineText("");
      setBaselineError(null);
      const reviewArtifacts = project.artifacts.latest_results
        ? await analyzeReviewArtifacts(project.artifacts.latest_results, nextReviewDraft)
        : null;
      applyDraftUpdate((current) => ({
        ...current,
        review_draft: nextReviewDraft,
        artifacts: reviewArtifacts
          ? {
              ...current.artifacts,
              ...reviewArtifacts,
            }
          : current.artifacts,
      }));
      setActivityMessage("Comparison baseline cleared.");
      setReviewTab("summary");
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Could not clear the baseline.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleGenerateSuppressions() {
    const project = getLoadedProject();
    if (!project.artifacts.latest_results) {
      setActionError("Run a suite first so suppressions can be generated.");
      return;
    }
    setBusyAction("suppressions");
    setActionError(null);
    try {
      const triaged = await triageResults(project.artifacts.latest_results, project.review_draft);
      setSuppressionsText(triaged.rendered_yaml);
      applyDraftUpdate((current) => ({
        ...current,
        review_draft: {
          ...current.review_draft,
          suppressions_yaml: triaged.rendered_yaml,
        },
        artifacts: {
          ...current.artifacts,
          latest_suppressions: triaged.suppressions,
        },
      }));
      setActivityMessage(`Generated ${triaged.added_count} suppression rule(s).`);
      setReviewTab("suppressions");
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Could not generate suppressions.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handlePromote() {
    const project = getLoadedProject();
    if (!project.artifacts.latest_results || !project.artifacts.generated_suite) {
      setActionError("Both run results and the generated suite are required for promotion.");
      return;
    }
    setBusyAction("promote");
    setActionError(null);
    try {
      const promoted = await promoteResults(
        project.artifacts.latest_results,
        project.artifacts.generated_suite,
        project.review_draft,
      );
      applyDraftUpdate((current) => ({
        ...current,
        artifacts: {
          ...current.artifacts,
          latest_promoted_suite: promoted.promoted_suite,
        },
      }));
      setActivityMessage(`Promoted ${promoted.promoted_attack_ids.length} attack(s).`);
      setReviewTab("promote");
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Promotion failed.");
    } finally {
      setBusyAction(null);
    }
  }

  function togglePruneStatus(status: ApiJobStatus) {
    setPruneStatuses((current) => {
      if (current.includes(status)) {
        return current.filter((entry) => entry !== status);
      }
      return PRUNEABLE_JOB_STATUSES.filter(
        (entry) => entry === status || current.includes(entry),
      );
    });
  }

  function buildPruneRequest(dryRun: boolean): PruneJobsRequest | null {
    if (!pruneStatuses.length) {
      setActionError("Select at least one completed or failed status to prune.");
      return null;
    }

    const parsedLimit = Number.parseInt(pruneLimit, 10);
    if (!Number.isFinite(parsedLimit) || parsedLimit < 1 || parsedLimit > 500) {
      setActionError("Prune limit must be a whole number between 1 and 500.");
      return null;
    }

    let completedBefore: string | null = null;
    if (pruneCompletedBefore) {
      const parsedDate = new Date(pruneCompletedBefore);
      if (Number.isNaN(parsedDate.getTime())) {
        setActionError("Choose a valid completed-before timestamp.");
        return null;
      }
      completedBefore = parsedDate.toISOString();
    }

    return {
      statuses: pruneStatuses,
      completed_before: completedBefore,
      limit: parsedLimit,
      dry_run: dryRun,
    };
  }

  async function reconcileProjectAfterRetention(
    removedJobIds: string[],
    remainingJobs: JobStatusResponse[],
  ) {
    if (!removedJobIds.length) {
      return;
    }

    const project = getLoadedProject();
    const removed = new Set(removedJobIds);
    const baselineRemoved =
      project.review_draft.baseline_job_id !== null &&
      project.review_draft.baseline_job_id !== undefined &&
      removed.has(project.review_draft.baseline_job_id);
    const currentJobRemoved =
      project.artifacts.last_run_job_id !== null &&
      project.artifacts.last_run_job_id !== undefined &&
      removed.has(project.artifacts.last_run_job_id);
    if (!baselineRemoved && !currentJobRemoved) {
      return;
    }

    const nextReviewDraft: ProjectReviewDraft = baselineRemoved
      ? {
          ...project.review_draft,
          baseline_job_id: null,
          baseline: null,
        }
      : project.review_draft;

    const canReuseCurrentResults = !currentJobRemoved && Boolean(project.artifacts.latest_results);
    const fallbackReviewJob =
      remainingJobs.find((job) => job.status === "completed" && job.result_available) ?? null;
    const nextLastRunJobId = canReuseCurrentResults
      ? project.artifacts.last_run_job_id ?? null
      : fallbackReviewJob?.id ?? null;

    if (canReuseCurrentResults && project.artifacts.latest_results) {
      const reviewArtifacts = await analyzeReviewArtifacts(
        project.artifacts.latest_results,
        nextReviewDraft,
      );
      setBaselineText(
        nextReviewDraft.baseline ? formatJson(nextReviewDraft.baseline) : "",
      );
      setBaselineError(null);
      applyDraftUpdate((current) => ({
        ...current,
        review_draft: nextReviewDraft,
        artifacts: {
          ...current.artifacts,
          last_run_job_id: nextLastRunJobId,
          latest_promoted_suite: null,
          latest_suppressions: null,
          ...reviewArtifacts,
        },
      }));
      return;
    }

    if (!fallbackReviewJob) {
      setBaselineText(nextReviewDraft.baseline ? formatJson(nextReviewDraft.baseline) : "");
      setBaselineError(null);
      applyDraftUpdate((current) => ({
        ...current,
        review_draft: nextReviewDraft,
        artifacts: {
          ...current.artifacts,
          last_run_job_id: null,
          latest_results: null,
          latest_summary: null,
          latest_verification: null,
          latest_markdown_report: null,
          latest_html_report: null,
          latest_promoted_suite: null,
          latest_suppressions: null,
        },
      }));
      return;
    }

    const results = await getJobResult(fallbackReviewJob.id);
    const reviewArtifacts = await analyzeReviewArtifacts(results, nextReviewDraft);
    setBaselineText(nextReviewDraft.baseline ? formatJson(nextReviewDraft.baseline) : "");
    setBaselineError(null);
    applyDraftUpdate((current) => ({
      ...current,
      review_draft: nextReviewDraft,
      artifacts: {
        ...current.artifacts,
        last_run_job_id: fallbackReviewJob.id,
        latest_results: results,
        latest_promoted_suite: null,
        latest_suppressions: null,
        ...reviewArtifacts,
      },
    }));
  }

  async function handleDeleteJob(job: JobStatusResponse) {
    const project = getLoadedProject();
    const isCurrentRun = project.artifacts.last_run_job_id === job.id;
    const isBaselineRun = project.review_draft.baseline_job_id === job.id;
    const impactNotes = [
      isCurrentRun ? "current review run" : null,
      isBaselineRun ? "saved baseline" : null,
    ].filter(Boolean);
    const confirmMessage = impactNotes.length
      ? `Delete run ${shortJobId(job.id)}? This also clears the ${impactNotes.join(" and ")}.`
      : `Delete run ${shortJobId(job.id)} and its stored artifacts?`;
    if (!window.confirm(confirmMessage)) {
      return;
    }

    setBusyAction(`delete-job:${job.id}`);
    setActionError(null);
    try {
      await deleteProjectJob(project.id, job.id);
      setPrunePreview((current) =>
        current
          ? {
              ...current,
              matched_count: Math.max(0, current.matched_count - 1),
              jobs: current.jobs.filter((entry) => entry.id !== job.id),
            }
          : null,
      );
      const refreshedJobs = (await projectJobsQuery.refetch()).data?.jobs ?? [];
      await reconcileProjectAfterRetention([job.id], refreshedJobs);
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      setActivityMessage(`Deleted run ${shortJobId(job.id)} from this project.`);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Could not delete the selected run.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handlePreviewPrune() {
    const project = getLoadedProject();
    const request = buildPruneRequest(true);
    if (!request) {
      return;
    }

    setBusyAction("preview-prune");
    setActionError(null);
    try {
      const preview = await pruneProjectJobs(project.id, request);
      setPrunePreview(preview);
      setActivityMessage(
        preview.matched_count
          ? `Preview matched ${preview.matched_count} run(s) for this project.`
          : "No runs match the current prune filters.",
      );
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Could not preview prune results.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handlePruneRuns() {
    const project = getLoadedProject();
    if (!prunePreview) {
      setActionError("Preview the prune set before deleting matched runs.");
      return;
    }
    const request = buildPruneRequest(false);
    if (!request) {
      return;
    }
    if (!prunePreview.matched_count) {
      setActionError("No runs match the current prune filters.");
      return;
    }
    if (
      !window.confirm(
        `Delete ${prunePreview.matched_count} matched run(s) from this project and remove their stored artifacts?`,
      )
    ) {
      return;
    }

    setBusyAction("prune");
    setActionError(null);
    try {
      const response = await pruneProjectJobs(project.id, request);
      setPrunePreview(null);
      const removedJobIds = response.jobs.map((job) => job.id);
      const refreshedJobs = (await projectJobsQuery.refetch()).data?.jobs ?? [];
      await reconcileProjectAfterRetention(removedJobIds, refreshedJobs);
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      setActivityMessage(
        response.deleted_count
          ? `Deleted ${response.deleted_count} run(s) from this project.`
          : "No runs matched the current prune filters.",
      );
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Could not prune project runs.");
    } finally {
      setBusyAction(null);
    }
  }

  function handleInspectArtifacts(job: JobStatusResponse) {
    if (!job.artifact_names.length) {
      return;
    }
    setReviewTab("artifacts");
    setSelectedArtifactJobId(job.id);
    setSelectedArtifactName(job.artifact_names[0]);
    setArtifactPreviewMode("structured");
    setArtifactPreviewError(null);
    setActivityMessage(`Inspecting artifacts from run ${shortJobId(job.id)}.`);
  }

  function handleArtifactSourceChange(jobId: string) {
    const nextJob = artifactSourceJobs.find((job) => job.id === jobId);
    setSelectedArtifactJobId(jobId || null);
    setSelectedArtifactName(nextJob?.artifact_names[0] ?? null);
    setArtifactPreviewMode("structured");
    setArtifactPreviewError(null);
  }

  function handleArtifactSelection(artifactName: string) {
    setSelectedArtifactName(artifactName || null);
    setArtifactPreviewMode("structured");
    setArtifactPreviewError(null);
  }

  function handleOpenRawArtifact() {
    if (!selectedArtifactLink) {
      setArtifactPreviewError("Could not open the selected artifact.");
      return;
    }
    window.open(selectedArtifactLink.toString(), "_blank", "noopener,noreferrer");
  }

  async function handleDownloadArtifact() {
    if (!selectedArtifactLink || !selectedArtifactName) {
      setArtifactPreviewError("Could not download the selected artifact.");
      return;
    }

    setArtifactActionBusy("download");
    setArtifactPreviewError(null);
    try {
      const response = await fetch(selectedArtifactLink.toString());
      if (!response.ok) {
        throw new Error(`Could not download artifact (${response.status}).`);
      }
      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = selectedArtifactName;
      document.body.append(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(objectUrl);
    } catch (error) {
      setArtifactPreviewError(
        error instanceof Error ? error.message : "Could not download the selected artifact.",
      );
    } finally {
      setArtifactActionBusy(null);
    }
  }

  async function handleDuplicateProject() {
    let project = getLoadedProject();
    setBusyAction("duplicate-project");
    setActionError(null);
    try {
      if (hasPendingSave || saveProjectMutation.isPending) {
        project = await saveProjectMutation.mutateAsync(project);
      }
      const duplicated = await duplicateProject(project.id);
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      setActivityMessage("Project duplicated. Opening the copy.");
      startTransition(() => {
        navigate(`/projects/${duplicated.id}`);
      });
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Could not duplicate the project.");
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <main className="workbench-shell">
      <header className="workbench-header">
        <div>
          <p className="eyebrow">Local companion app</p>
          <h1>{draft.name}</h1>
          <p className="hero-body">
            Saved {hasPendingSave || saveProjectMutation.isPending ? "drafting changes…" : "locally"}.
            {activityMessage ? ` ${activityMessage}` : ""}
          </p>
        </div>
        <div className="header-actions">
          <button
            className="secondary-button"
            onClick={() => void handleDuplicateProject()}
            type="button"
            disabled={busyAction === "duplicate-project" || saveProjectMutation.isPending}
          >
            {busyAction === "duplicate-project" ? "Duplicating…" : "Duplicate project"}
          </button>
          <Link className="ghost-button" to="/">
            Back to projects
          </Link>
          <div className={`status-chip ${statusTone(latestJob?.status ?? "idle")}`}>
            {latestJob?.status ?? "draft"}
          </div>
        </div>
      </header>

      {actionError ? <div className="error-banner">{actionError}</div> : null}

      <div className="workbench-layout">
        <StepRail
          activeStep={draft.active_step}
          onChange={(step) =>
            applyDraftUpdate((current) => ({
              ...current,
              active_step: step,
            }))
          }
        />

        <section className="workbench-main">
          <div className="panel">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Source</p>
                <h2>Choose how this project begins</h2>
              </div>
              <div className="mode-switch">
                {(
                  ["openapi", "graphql", "learned", "capture_upload"] as ProjectSourceMode[]
                ).map((mode) => (
                  <button
                    className={`mode-button${draft.source_mode === mode ? " mode-button-active" : ""}`}
                    key={mode}
                    onClick={() => {
                      const nextSource = defaultSourceForMode(mode);
                      setSourceText(nextSource?.content ?? "");
                      applyDraftUpdate((current) => ({
                        ...current,
                        source_mode: mode,
                        active_step: "source",
                        source:
                          mode === "capture_upload"
                            ? null
                            : {
                                name: nextSource?.name ?? current.source?.name ?? "",
                                content:
                                  mode === current.source_mode
                                    ? current.source?.content ?? ""
                                    : nextSource?.content ?? "",
                              },
                      }));
                    }}
                    type="button"
                  >
                    {mode.replace("_", " ")}
                  </button>
                ))}
              </div>
            </div>

            {draft.source_mode === "capture_upload" ? (
              <div className="stack">
                <label className="upload-box">
                  <span className="field-label">Capture inputs</span>
                  <span className="field-hint">Upload one or more `capture.ndjson` or HAR files.</span>
                  <input
                    multiple
                    onChange={(event) => void handleCaptureUpload(event.target.files)}
                    type="file"
                  />
                </label>
                <ul className="compact-list">
                  {draft.discover_inputs.length ? (
                    draft.discover_inputs.map((input) => (
                      <li key={input.name}>
                        <strong>{input.name}</strong>
                        <span>{input.content.length} chars loaded</span>
                      </li>
                    ))
                  ) : (
                    <li>No capture files loaded yet.</li>
                  )}
                </ul>
                <div className="action-row">
                  <button
                    className="primary-button"
                    disabled={busyAction === "discover" || !draft.discover_inputs.length}
                    onClick={() => void handleDiscover()}
                    type="button"
                  >
                    {busyAction === "discover" ? "Discovering…" : "Discover learned model"}
                  </button>
                </div>
              </div>
            ) : (
              <div className="stack">
                <div className="field-grid field-grid-2">
                  <label className="field">
                    <span className="field-label">Source name</span>
                    <input
                      className="text-input"
                      value={draft.source?.name ?? ""}
                      onChange={(event) =>
                        applyDraftUpdate((current) => ({
                          ...current,
                          source: {
                            name: event.target.value,
                            content: current.source?.content ?? sourceText,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="field">
                    <span className="field-label">GraphQL endpoint</span>
                    <input
                      className="text-input"
                      value={draft.graphql_endpoint}
                      onChange={(event) =>
                        applyDraftUpdate((current) => ({
                          ...current,
                          graphql_endpoint: event.target.value,
                        }))
                      }
                    />
                  </label>
                </div>

                <label className="upload-box">
                  <span className="field-label">Upload source</span>
                  <span className="field-hint">Load a local file into the project editor.</span>
                  <input onChange={(event) => void handleSourceUpload(event.target.files)} type="file" />
                </label>

                <CodeEditor
                  error={null}
                  height={300}
                  hint="This editor is the saved source of truth for inspect and generate."
                  label="Source document"
                  language={
                    draft.source_mode === "graphql"
                      ? "graphql"
                      : draft.source_mode === "learned"
                        ? "json"
                        : "yaml"
                  }
                  onChange={(value) => {
                    setSourceText(value);
                    applyDraftUpdate((current) => ({
                      ...current,
                      source: {
                        name:
                          current.source?.name ??
                          defaultSourceForMode(current.source_mode)?.name ??
                          "source.txt",
                        content: value,
                      },
                    }));
                  }}
                  value={sourceText}
                />

                <div className="action-row">
                  <button
                    className="primary-button"
                    disabled={busyAction === "inspect" || !draft.source?.content.trim()}
                    onClick={() => void handleInspect()}
                    type="button"
                  >
                    {busyAction === "inspect" ? "Inspecting…" : "Inspect source"}
                  </button>
                </div>
              </div>
            )}
          </div>

          <div className="panel">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Inspect</p>
                <h2>Preflight the operation surface</h2>
              </div>
              <div className="meta-pill">
                {draft.artifacts.inspect_result?.operations.length ?? 0}
                <span>ops</span>
              </div>
            </div>
            <div className="field-grid field-grid-4">
              <ListField
                label="Include tags"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    inspect_draft: { ...current.inspect_draft, tag: value },
                  }))
                }
                placeholder="orders, pets"
                value={draft.inspect_draft.tag}
              />
              <ListField
                label="Exclude tags"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    inspect_draft: { ...current.inspect_draft, exclude_tag: value },
                  }))
                }
                placeholder="internal"
                value={draft.inspect_draft.exclude_tag}
              />
              <ListField
                label="Include paths"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    inspect_draft: { ...current.inspect_draft, path: value },
                  }))
                }
                placeholder="/draft-orders/{draftId}"
                value={draft.inspect_draft.path}
              />
              <ListField
                label="Exclude paths"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    inspect_draft: { ...current.inspect_draft, exclude_path: value },
                  }))
                }
                placeholder="/internal"
                value={draft.inspect_draft.exclude_path}
              />
            </div>
            <ReviewTable
              emptyCopy="Run inspect to see discovered operations."
              headings={["Operation", "Method", "Path", "Protocol", "Tags", "Auth"]}
              rows={(draft.artifacts.inspect_result?.operations ?? []).map((operation) => [
                operation.operation_id,
                operation.method,
                operation.path,
                operation.protocol,
                operation.tags.join(", ") || "—",
                operation.auth_required ? "yes" : "no",
              ])}
            />
          </div>

          <div className="panel">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Generate</p>
                <h2>Shape the attack suite</h2>
              </div>
              <div className="meta-pill">
                {draft.artifacts.generated_suite?.attacks.length ?? 0}
                <span>attacks</span>
              </div>
            </div>
            <div className="field-grid field-grid-4">
              <ListField
                label="Include operations"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    generate_draft: { ...current.generate_draft, operation: value },
                  }))
                }
                placeholder="listPets"
                value={draft.generate_draft.operation}
              />
              <ListField
                label="Methods"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    generate_draft: { ...current.generate_draft, method: value },
                  }))
                }
                placeholder="GET, POST"
                value={draft.generate_draft.method}
              />
              <ListField
                label="Kinds"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    generate_draft: { ...current.generate_draft, kind: value },
                  }))
                }
                placeholder="missing_auth"
                value={draft.generate_draft.kind}
              />
              <ListField
                label="Pack names"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    generate_draft: { ...current.generate_draft, pack_names: value },
                  }))
                }
                placeholder="unexpected-header"
                value={draft.generate_draft.pack_names}
              />
            </div>
            <div className="field-grid field-grid-3">
              <ListField
                label="Tags"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    generate_draft: { ...current.generate_draft, tag: value },
                  }))
                }
                placeholder="orders"
                value={draft.generate_draft.tag}
              />
              <ListField
                label="Paths"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    generate_draft: { ...current.generate_draft, path: value },
                  }))
                }
                placeholder="/draft-orders/{draftId}"
                value={draft.generate_draft.path}
              />
              <ListField
                label="Workflow packs"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    generate_draft: { ...current.generate_draft, workflow_pack_names: value },
                  }))
                }
                placeholder="listed-id-lookup"
                value={draft.generate_draft.workflow_pack_names}
              />
            </div>
            <label className="checkbox-row">
              <input
                checked={draft.generate_draft.auto_workflows}
                onChange={(event) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    generate_draft: {
                      ...current.generate_draft,
                      auto_workflows: event.target.checked,
                    },
                  }))
                }
                type="checkbox"
              />
              <span>Enable auto-generated workflows</span>
            </label>
            <div className="action-row">
              <button
                className="primary-button"
                disabled={busyAction === "generate" || !draft.source?.content.trim()}
                onClick={() => void handleGenerate()}
                type="button"
              >
                {busyAction === "generate" ? "Generating…" : "Generate suite"}
              </button>
            </div>
          </div>

          <div className="panel">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Run</p>
                <h2>Execute against a live target</h2>
              </div>
              <div className="meta-pill">
                {draft.artifacts.generated_suite?.attacks.length ?? 0}
                <span>ready</span>
              </div>
            </div>
            <div className="field-grid field-grid-3">
              <label className="field">
                <span className="field-label">Base URL</span>
                <input
                  className="text-input"
                  placeholder="https://api.example.com"
                  value={draft.run_draft.base_url}
                  onChange={(event) =>
                    applyDraftUpdate((current) => ({
                      ...current,
                      run_draft: { ...current.run_draft, base_url: event.target.value },
                    }))
                  }
                />
              </label>
              <label className="field">
                <span className="field-label">Timeout (seconds)</span>
                <input
                  className="text-input"
                  type="number"
                  value={draft.run_draft.timeout}
                  onChange={(event) =>
                    applyDraftUpdate((current) => ({
                      ...current,
                      run_draft: {
                        ...current.run_draft,
                        timeout: Number(event.target.value || 0),
                      },
                    }))
                  }
                />
              </label>
              <label className="checkbox-row checkbox-row-inline">
                <input
                  checked={draft.run_draft.store_artifacts}
                  onChange={(event) =>
                    applyDraftUpdate((current) => ({
                      ...current,
                      run_draft: {
                        ...current.run_draft,
                        store_artifacts: event.target.checked,
                      },
                    }))
                  }
                  type="checkbox"
                />
                <span>Store request/response artifacts</span>
              </label>
            </div>
            <div className="field-grid field-grid-2">
              <CodeEditor
                error={headersError}
                height={220}
                hint='JSON object, for example `{ "Authorization": "Bearer token" }`.'
                label="Default headers"
                language="json"
                onChange={(value) => {
                  setHeadersText(value);
                  if (!value.trim()) {
                    setHeadersError(null);
                    applyDraftUpdate((current) => ({
                      ...current,
                      run_draft: { ...current.run_draft, headers: {} },
                    }));
                    return;
                  }
                  try {
                    const parsed = JSON.parse(value) as Record<string, string>;
                    setHeadersError(null);
                    applyDraftUpdate((current) => ({
                      ...current,
                      run_draft: { ...current.run_draft, headers: parsed },
                    }));
                  } catch (error) {
                    setHeadersError(error instanceof Error ? error.message : "Invalid JSON.");
                  }
                }}
                value={headersText}
              />
              <CodeEditor
                error={queryError}
                height={220}
                hint='JSON object, for example `{ "api_key": "secret" }`.'
                label="Default query"
                language="json"
                onChange={(value) => {
                  setQueryText(value);
                  if (!value.trim()) {
                    setQueryError(null);
                    applyDraftUpdate((current) => ({
                      ...current,
                      run_draft: { ...current.run_draft, query: {} },
                    }));
                    return;
                  }
                  try {
                    const parsed = JSON.parse(value) as Record<string, unknown>;
                    setQueryError(null);
                    applyDraftUpdate((current) => ({
                      ...current,
                      run_draft: { ...current.run_draft, query: parsed },
                    }));
                  } catch (error) {
                    setQueryError(error instanceof Error ? error.message : "Invalid JSON.");
                  }
                }}
                value={queryText}
              />
            </div>
            <div className="field-grid field-grid-2">
              <CodeEditor
                error={null}
                height={220}
                hint="Optional YAML for built-in auth configs."
                label="Auth config YAML"
                language="yaml"
                onChange={(value) => {
                  setAuthConfigText(value);
                  applyDraftUpdate((current) => ({
                    ...current,
                    run_draft: { ...current.run_draft, auth_config_yaml: value || null },
                  }));
                }}
                value={authConfigText}
              />
              <CodeEditor
                error={null}
                height={220}
                hint="Optional YAML for multi-profile runs."
                label="Profile file YAML"
                language="yaml"
                onChange={(value) => {
                  setProfileFileText(value);
                  applyDraftUpdate((current) => ({
                    ...current,
                    run_draft: { ...current.run_draft, profile_file_yaml: value || null },
                  }));
                }}
                value={profileFileText}
              />
            </div>
            <div className="field-grid field-grid-3">
              <ListField
                label="Auth plugins"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    run_draft: { ...current.run_draft, auth_plugin_names: value },
                  }))
                }
                placeholder="env-bearer"
                value={draft.run_draft.auth_plugin_names}
              />
              <ListField
                label="Auth profile names"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    run_draft: { ...current.run_draft, auth_profile_names: value },
                  }))
                }
                placeholder="user, admin"
                value={draft.run_draft.auth_profile_names}
              />
              <ListField
                label="Profile names"
                onChange={(value) =>
                  applyDraftUpdate((current) => ({
                    ...current,
                    run_draft: { ...current.run_draft, profile_names: value },
                  }))
                }
                placeholder="anonymous, admin"
                value={draft.run_draft.profile_names}
              />
            </div>
            <div className="action-row">
              <button
                className="primary-button"
                disabled={busyAction === "run" || !draft.artifacts.generated_suite}
                onClick={() => void handleRun()}
                type="button"
              >
                {busyAction === "run" ? "Starting…" : "Run suite"}
              </button>
            </div>
          </div>

          <div className="panel">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Review</p>
                <h2>Native triage and regression workspace</h2>
              </div>
              <div className="action-row">
                <button
                  className="secondary-button"
                  disabled={busyAction === "refresh-review" || !draft.artifacts.latest_results}
                  onClick={() => void handleRefreshReview()}
                  type="button"
                >
                  {busyAction === "refresh-review" ? "Refreshing…" : "Refresh analysis"}
                </button>
                <button
                  className="secondary-button"
                  disabled={busyAction === "suppressions" || !draft.artifacts.latest_results}
                  onClick={() => void handleGenerateSuppressions()}
                  type="button"
                >
                  {busyAction === "suppressions" ? "Generating…" : "Seed suppressions"}
                </button>
                <button
                  className="secondary-button"
                  disabled={busyAction === "promote" || !draft.artifacts.latest_results}
                  onClick={() => void handlePromote()}
                  type="button"
                >
                  {busyAction === "promote" ? "Promoting…" : "Promote findings"}
                </button>
              </div>
            </div>
            <div className="field-grid field-grid-3">
              <label className="field">
                <span className="field-label">Minimum severity</span>
                <select
                  className="text-input"
                  value={draft.review_draft.min_severity}
                  onChange={(event) =>
                    applyDraftUpdate((current) => ({
                      ...current,
                      review_draft: {
                        ...current.review_draft,
                        min_severity: event.target.value,
                      },
                    }))
                  }
                >
                  {["low", "medium", "high", "critical"].map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span className="field-label">Minimum confidence</span>
                <select
                  className="text-input"
                  value={draft.review_draft.min_confidence}
                  onChange={(event) =>
                    applyDraftUpdate((current) => ({
                      ...current,
                      review_draft: {
                        ...current.review_draft,
                        min_confidence: event.target.value,
                      },
                    }))
                  }
                >
                  {["low", "medium", "high"].map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span className="field-label">Findings filter</span>
                <input
                  className="text-input"
                  value={reviewFilter}
                  onChange={(event) => setReviewFilter(event.target.value)}
                  placeholder="search by attack, kind, issue, path"
                />
              </label>
            </div>
            <div className="summary-card-grid comparison-card-grid">
              <div className="summary-card">
                <span>Current run</span>
                <strong>{currentRunJob ? shortJobId(currentRunJob.id) : "—"}</strong>
                <p className="summary-card-detail">
                  {currentRunJob ? formatDateTime(jobTimestamp(currentRunJob)) : "No completed run yet"}
                </p>
              </div>
              <div className="summary-card">
                <span>Baseline</span>
                <strong>
                  {selectedBaselineJob
                    ? shortJobId(selectedBaselineJob.id)
                    : draft.review_draft.baseline
                      ? "manual"
                      : "none"}
                </strong>
                <p className="summary-card-detail">{baselineDescription}</p>
              </div>
              <div className="summary-card">
                <span>New findings</span>
                <strong>{reviewVerification?.new_findings_count ?? 0}</strong>
              </div>
              <div className="summary-card">
                <span>Resolved</span>
                <strong>{reviewVerification?.resolved_findings_count ?? 0}</strong>
              </div>
              <div className="summary-card">
                <span>Persisting</span>
                <strong>{reviewVerification?.persisting_findings_count ?? 0}</strong>
              </div>
              <div className="summary-card">
                <span>Mode</span>
                <strong>
                  {draft.artifacts.latest_summary?.baseline_used ? "comparison" : "standalone"}
                </strong>
              </div>
            </div>
            <div className="field-grid field-grid-2">
              <label className="field">
                <span className="field-label">Baseline run</span>
                <select
                  aria-label="Baseline run"
                  className="text-input"
                  disabled={busyAction === "baseline" || !baselineCandidates.length}
                  onChange={(event) => void handleBaselineSelection(event.target.value)}
                  value={draft.review_draft.baseline_job_id ?? ""}
                >
                  <option value="">No saved run selected</option>
                  {baselineCandidates.map((job) => (
                    <option key={job.id} value={job.id}>
                      {formatJobOptionLabel(job)}
                    </option>
                  ))}
                </select>
                <span className="field-hint">
                  {baselineCandidates.length
                    ? "Load any prior completed project run as the regression baseline."
                    : "Complete at least two runs in this project to compare them here."}
                </span>
              </label>
              <section className="comparison-panel">
                <div>
                  <p className="eyebrow">Compare mode</p>
                  <h3>{selectedBaselineJob ? "Saved run loaded" : "Manual JSON still supported"}</h3>
                  <p className="hero-body">
                    {draft.artifacts.latest_summary?.baseline_used
                      ? "Summary, verification, reports, suppressions, and promotion are using the selected baseline."
                      : "Review panels are showing the latest run without a comparison baseline."}
                  </p>
                </div>
                <div className="action-row">
                  <button
                    className="ghost-button"
                    disabled={
                      busyAction === "baseline" ||
                      (!draft.review_draft.baseline_job_id && !draft.review_draft.baseline)
                    }
                    onClick={() => void handleClearBaseline()}
                    type="button"
                  >
                    Clear baseline
                  </button>
                </div>
              </section>
            </div>
            <CodeEditor
              error={baselineError}
              height={220}
              hint="Advanced override. Picking a saved run above is the normal way to compare runs."
              label="Baseline results JSON"
              language="json"
              onChange={(value) => {
                setBaselineText(value);
                if (!value.trim()) {
                  setBaselineError(null);
                  applyDraftUpdate((current) => ({
                    ...current,
                    review_draft: {
                      ...current.review_draft,
                      baseline_job_id: null,
                      baseline: null,
                    },
                  }));
                  return;
                }
                try {
                  const parsed = JSON.parse(value) as AttackResults;
                  setBaselineError(null);
                  applyDraftUpdate((current) => ({
                    ...current,
                    review_draft: {
                      ...current.review_draft,
                      baseline_job_id: null,
                      baseline: parsed,
                    },
                  }));
                } catch (error) {
                  setBaselineError(error instanceof Error ? error.message : "Invalid JSON.");
                }
              }}
              value={baselineText}
            />

            <div className="tab-row" role="tablist" aria-label="Review panels">
              {(
                [
                  ["summary", "Summary"],
                  ["findings", "Findings"],
                  ["deltas", "Deltas"],
                  ["auth", "Auth"],
                  ["artifacts", "Artifacts"],
                  ["suppressions", "Suppressions"],
                  ["promote", "Promote"],
                ] as Array<[ReviewTab, string]>
              ).map(([tab, label]) => (
                <button
                  className={`tab-button${reviewTab === tab ? " tab-button-active" : ""}`}
                  key={tab}
                  onClick={() => setReviewTab(tab)}
                  role="tab"
                  type="button"
                >
                  {label}
                </button>
              ))}
            </div>

            {reviewTab === "summary" ? (
              <div className="stack">
                <div className="summary-card-grid">
                  <div className="summary-card">
                    <span>Total results</span>
                    <strong>{draft.artifacts.latest_summary?.total_results ?? 0}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Active flagged</span>
                    <strong>{draft.artifacts.latest_summary?.active_flagged_count ?? 0}</strong>
                  </div>
                  <div className="summary-card">
                    <span>New</span>
                    <strong>{draft.artifacts.latest_summary?.new_findings_count ?? 0}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Persisting deltas</span>
                    <strong>{draft.artifacts.latest_summary?.persisting_deltas_count ?? 0}</strong>
                  </div>
                </div>
                <ReviewTable
                  emptyCopy="Run a suite and refresh analysis to populate the summary."
                  headings={["Attack", "Kind", "Issue", "Severity", "Confidence", "URL"]}
                  rows={(draft.artifacts.latest_summary?.top_findings ?? []).map((finding) => [
                    finding.name,
                    finding.kind,
                    finding.issue ?? "—",
                    finding.severity,
                    finding.confidence,
                    finding.url,
                  ])}
                />
                <div className="report-grid">
                  <article className="report-card">
                    <h3>Markdown report</h3>
                    <pre>{draft.artifacts.latest_markdown_report ?? "No Markdown report yet."}</pre>
                  </article>
                  <article className="report-card">
                    <h3>HTML report</h3>
                    <pre>{draft.artifacts.latest_html_report ?? "No HTML report yet."}</pre>
                  </article>
                </div>
              </div>
            ) : null}

            {reviewTab === "findings" ? (
              <div className="stack">
                <div className="tab-row" role="tablist" aria-label="Finding scopes">
                  {(
                    [
                      ["current", "Current", reviewVerification?.current_findings_count ?? 0],
                      ["new", "New", reviewVerification?.new_findings_count ?? 0],
                      ["resolved", "Resolved", reviewVerification?.resolved_findings_count ?? 0],
                      ["persisting", "Persisting", reviewVerification?.persisting_findings_count ?? 0],
                    ] as Array<[FindingScope, string, number]>
                  ).map(([scope, label, count]) => (
                    <button
                      className={`tab-button${findingScope === scope ? " tab-button-active" : ""}`}
                      key={scope}
                      onClick={() => setFindingScope(scope)}
                      role="tab"
                      type="button"
                    >
                      {label}
                      <span className="tab-count">{count}</span>
                    </button>
                  ))}
                </div>
                <ReviewTable
                  emptyCopy={`No ${findingScope} findings match the current filter.`}
                  headings={["Attack", "Kind", "Issue", "Severity", "Confidence", "Status", "Path"]}
                  rows={findingScopeRows.map((finding) => [
                    finding.name,
                    finding.kind,
                    finding.issue ?? "—",
                    finding.severity,
                    finding.confidence,
                    finding.status_code ?? "—",
                    finding.path ?? "—",
                  ])}
                />
              </div>
            ) : null}

            {reviewTab === "deltas" ? (
              <ReviewTable
                emptyCopy="No persisting deltas are available."
                headings={["Attack", "Issue", "Change summary", "Method", "Path"]}
                rows={findingBuckets.persisting.map((finding) => [
                  finding.name,
                  finding.issue ?? "—",
                  finding.delta_changes.length
                    ? finding.delta_changes
                        .map((change) => `${change.field} ${change.baseline} -> ${change.current}`)
                        .join("; ")
                    : "unchanged",
                  finding.method,
                  finding.path ?? "—",
                ])}
              />
            ) : null}

            {reviewTab === "auth" ? (
              <div className="stack">
                <ReviewTable
                  emptyCopy="No auth summary recorded."
                  headings={["Profile", "Name", "Strategy", "Acquire", "Refresh", "Failures"]}
                  rows={(draft.artifacts.latest_summary?.auth_summary ?? []).map((entry) => [
                    entry.profile,
                    entry.name,
                    entry.strategy,
                    entry.acquire,
                    entry.refresh,
                    entry.failures,
                  ])}
                />
                <ReviewTable
                  emptyCopy="No auth events captured."
                  headings={["Profile", "Name", "Strategy", "Phase", "Status", "Error"]}
                  rows={(draft.artifacts.latest_results?.auth_events ?? []).map((event) => [
                    event.profile ?? "—",
                    event.name,
                    event.strategy,
                    event.phase,
                    event.status_code ?? (event.success ? "ok" : "failed"),
                    event.error ?? "—",
                  ])}
                />
              </div>
            ) : null}

            {reviewTab === "artifacts" ? (
              <div className="stack">
                <div className="comparison-panel artifact-browser-shell">
                  <div className="section-heading">
                    <div>
                      <p className="eyebrow">Artifact browser</p>
                      <h3>Inspect saved request and response artifacts across project runs.</h3>
                    </div>
                    <div className="meta-pill">
                      {artifactSourceJobs.length}
                      <span>runs with artifacts</span>
                    </div>
                  </div>

                  {artifactSourceJobs.length ? (
                    <div className="stack">
                      <div className="field-grid field-grid-2">
                        <label className="field">
                          <span className="field-label">Artifact source run</span>
                          <select
                            aria-label="Artifact source run"
                            className="text-input"
                            onChange={(event) => handleArtifactSourceChange(event.target.value)}
                            value={selectedArtifactJobId ?? ""}
                          >
                            {artifactSourceJobs.map((job) => (
                              <option key={job.id} value={job.id}>
                                {formatArtifactJobOptionLabel(job)}
                              </option>
                            ))}
                          </select>
                          <span className="field-hint">
                            The artifact browser includes every saved project run with stored files,
                            regardless of the run-history filter below.
                          </span>
                        </label>
                        <label className="field">
                          <span className="field-label">Artifact file</span>
                          <select
                            aria-label="Artifact file"
                            className="text-input"
                            disabled={!selectedArtifactNames.length}
                            onChange={(event) => handleArtifactSelection(event.target.value)}
                            value={selectedArtifactName ?? ""}
                          >
                            {selectedArtifactNames.map((artifactName) => (
                              <option key={artifactName} value={artifactName}>
                                {artifactName}
                              </option>
                            ))}
                          </select>
                          <span className="field-hint">
                            Choose a stored artifact from the selected run for inline review.
                          </span>
                        </label>
                      </div>

                      {selectedArtifactLink ? (
                        <div className="action-row">
                          <div className="artifact-action-row">
                            <button
                              className="secondary-button"
                              onClick={handleOpenRawArtifact}
                              type="button"
                            >
                              Open raw
                            </button>
                            <button
                              className="ghost-button"
                              disabled={artifactActionBusy === "download"}
                              onClick={() => void handleDownloadArtifact()}
                              type="button"
                            >
                              {artifactActionBusy === "download" ? "Downloading…" : "Download"}
                            </button>
                            {artifactPreviewRecord ? (
                              <button
                                className="ghost-button"
                                onClick={() =>
                                  setArtifactPreviewMode((current) =>
                                    current === "structured" ? "raw" : "structured",
                                  )
                                }
                                type="button"
                              >
                                {artifactPreviewMode === "structured"
                                  ? "View raw JSON"
                                  : "View structured"}
                              </button>
                            ) : null}
                          </div>
                          <div className="field-hint">
                            {selectedArtifactJob
                              ? `Run ${shortJobId(selectedArtifactJob.id)} • ${selectedArtifactNames.length} artifact(s)`
                              : "No artifact selected"}
                          </div>
                        </div>
                      ) : null}

                      {artifactPreviewError ? (
                        <div className="error-banner">{artifactPreviewError}</div>
                      ) : null}

                      {artifactPreviewLoading ? (
                        <p className="empty-copy">Loading artifact preview…</p>
                      ) : artifactPreviewMode === "raw" || !artifactPreviewRecord ? (
                        <article className="report-card">
                          <h3>Raw artifact preview</h3>
                          <pre className="json-preview">
                            {artifactPreviewText || "Select an artifact to preview it here."}
                          </pre>
                        </article>
                      ) : (
                        <div className="stack">
                          <div className="summary-card-grid">
                            <div className="summary-card">
                              <span>Attack</span>
                              <strong>{artifactPreviewRecord.attack.name ?? "Unnamed artifact"}</strong>
                            </div>
                            <div className="summary-card">
                              <span>Kind</span>
                              <strong>{artifactPreviewRecord.attack.kind ?? "—"}</strong>
                            </div>
                            <div className="summary-card">
                              <span>Status</span>
                              <strong>{artifactPreviewRecord.response.status_code ?? "—"}</strong>
                            </div>
                          </div>
                          <div className="artifact-preview-grid">
                            <article className="artifact-preview-panel">
                              <h3>Attack summary</h3>
                              <dl className="artifact-detail-grid">
                                <div>
                                  <dt>ID</dt>
                                  <dd>{artifactPreviewRecord.attack.id ?? "—"}</dd>
                                </div>
                                <div>
                                  <dt>Name</dt>
                                  <dd>{artifactPreviewRecord.attack.name ?? "—"}</dd>
                                </div>
                                <div>
                                  <dt>Kind</dt>
                                  <dd>{artifactPreviewRecord.attack.kind ?? "—"}</dd>
                                </div>
                                <div>
                                  <dt>Operation</dt>
                                  <dd>{artifactPreviewRecord.attack.operation_id ?? "—"}</dd>
                                </div>
                                <div>
                                  <dt>Path</dt>
                                  <dd>{artifactPreviewRecord.attack.path ?? "—"}</dd>
                                </div>
                              </dl>
                            </article>
                            <article className="artifact-preview-panel">
                              <h3>Request summary</h3>
                              <dl className="artifact-detail-grid">
                                <div>
                                  <dt>Method</dt>
                                  <dd>{artifactPreviewRecord.request.method}</dd>
                                </div>
                                <div>
                                  <dt>URL</dt>
                                  <dd>{artifactPreviewRecord.request.url}</dd>
                                </div>
                                <div>
                                  <dt>Headers</dt>
                                  <dd>
                                    <pre className="artifact-code">
                                      {artifactPreviewRecord.request.headers &&
                                      Object.keys(artifactPreviewRecord.request.headers).length
                                        ? formatJson(artifactPreviewRecord.request.headers)
                                        : "{}"}
                                    </pre>
                                  </dd>
                                </div>
                                <div>
                                  <dt>Query</dt>
                                  <dd>
                                    <pre className="artifact-code">
                                      {artifactPreviewRecord.request.query &&
                                      Object.keys(artifactPreviewRecord.request.query).length
                                        ? formatJson(artifactPreviewRecord.request.query)
                                        : "{}"}
                                    </pre>
                                  </dd>
                                </div>
                                <div>
                                  <dt>Body</dt>
                                  <dd>
                                    <pre className="artifact-code">
                                      {formatJson({
                                        present:
                                          artifactPreviewRecord.request.body?.present ?? false,
                                        kind: artifactPreviewRecord.request.body?.kind ?? null,
                                        content_type:
                                          artifactPreviewRecord.request.body?.content_type ?? null,
                                        excerpt:
                                          artifactPreviewRecord.request.body?.excerpt ?? null,
                                      })}
                                    </pre>
                                  </dd>
                                </div>
                              </dl>
                            </article>
                            <article className="artifact-preview-panel">
                              <h3>Response summary</h3>
                              <dl className="artifact-detail-grid">
                                <div>
                                  <dt>Status</dt>
                                  <dd>{artifactPreviewRecord.response.status_code ?? "—"}</dd>
                                </div>
                                <div>
                                  <dt>Error</dt>
                                  <dd>{artifactPreviewRecord.response.error ?? "—"}</dd>
                                </div>
                                <div>
                                  <dt>Duration</dt>
                                  <dd>
                                    {artifactPreviewRecord.response.duration_ms != null
                                      ? `${artifactPreviewRecord.response.duration_ms} ms`
                                      : "—"}
                                  </dd>
                                </div>
                                <div>
                                  <dt>Body excerpt</dt>
                                  <dd>
                                    <pre className="artifact-code">
                                      {artifactPreviewRecord.response.body_excerpt ?? "—"}
                                    </pre>
                                  </dd>
                                </div>
                              </dl>
                            </article>
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="empty-state">
                      <p>No artifacts stored for this project yet.</p>
                      <p>Run a suite with artifact storage enabled to inspect request and response snapshots here.</p>
                    </div>
                  )}
                </div>

                <div className="comparison-panel">
                  <div className="section-heading">
                    <div>
                      <p className="eyebrow">Run retention</p>
                      <h3>Clean up completed history without leaving the project.</h3>
                    </div>
                    <div className="meta-pill">
                      {pruneableJobCount}
                      <span>pruneable</span>
                    </div>
                  </div>
                  <div className="field-grid field-grid-3">
                    <div className="field">
                      <span className="field-label">Statuses</span>
                      <div className="mode-switch">
                        {PRUNEABLE_JOB_STATUSES.map((status) => (
                          <button
                            aria-pressed={pruneStatuses.includes(status)}
                            className={`mode-button${pruneStatuses.includes(status) ? " mode-button-active" : ""}`}
                            key={status}
                            onClick={() => togglePruneStatus(status)}
                            type="button"
                          >
                            {status}
                          </button>
                        ))}
                      </div>
                    </div>
                    <label className="field">
                      <span className="field-label">Completed before</span>
                      <input
                        className="text-input"
                        onChange={(event) => setPruneCompletedBefore(event.target.value)}
                        type="datetime-local"
                        value={pruneCompletedBefore}
                      />
                    </label>
                    <label className="field">
                      <span className="field-label">Limit</span>
                      <input
                        className="text-input"
                        inputMode="numeric"
                        min={1}
                        max={500}
                        onChange={(event) => setPruneLimit(event.target.value)}
                        type="number"
                        value={pruneLimit}
                      />
                    </label>
                  </div>
                  <div className="action-row">
                    <button
                      className="secondary-button"
                      disabled={busyAction === "preview-prune"}
                      onClick={() => void handlePreviewPrune()}
                      type="button"
                    >
                      {busyAction === "preview-prune" ? "Previewing…" : "Preview matches"}
                    </button>
                    <button
                      className="ghost-button danger-button"
                      disabled={!prunePreview?.matched_count || busyAction === "prune"}
                      onClick={() => void handlePruneRuns()}
                      type="button"
                    >
                      {busyAction === "prune" ? "Deleting…" : "Delete matched runs"}
                    </button>
                  </div>
                  <p className="field-hint">
                    Prune actions stay project-scoped here and never touch runs from other saved
                    workbenches.
                  </p>
                </div>

                {prunePreview ? (
                  <ReviewTable
                    emptyCopy="No runs match the current prune filters."
                    headings={["Job", "Status", "Completed", "Artifacts", "Error"]}
                    rows={prunePreview.jobs.map((job) => [
                      shortJobId(job.id),
                      job.status,
                      formatDateTime(job.completed_at),
                      job.artifact_names.length,
                      job.error ?? "—",
                    ])}
                  />
                ) : null}

                <div className="section-heading">
                  <div>
                    <p className="eyebrow">Run history</p>
                    <h3>Inspect, filter, and retire saved runs.</h3>
                  </div>
                  <div className="tab-row" role="tablist" aria-label="Run history filters">
                    {(
                      [
                        ["all", "All"],
                        ["active", "Active"],
                        ["completed", "Completed"],
                        ["failed", "Failed"],
                      ] as Array<[RunHistoryFilter, string]>
                    ).map(([filter, label]) => (
                      <button
                        className={`tab-button${runHistoryFilter === filter ? " tab-button-active" : ""}`}
                        key={filter}
                        onClick={() => setRunHistoryFilter(filter)}
                        role="tab"
                        type="button"
                      >
                        {label}
                        <span className="tab-count">
                          {currentJobs.filter((job) => matchesRunHistoryFilter(job, filter)).length}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
                <ReviewTable
                  emptyCopy="No jobs for this project yet."
                  headings={["Job", "Status", "Created", "Artifacts", "Findings", "Actions"]}
                  rows={runHistoryJobs.map((job) => [
                    <div key={job.id}>
                      <strong>{shortJobId(job.id)}</strong>
                      <div className="field-hint">
                        {job.id === currentRunJob?.id ? "Current review run" : "Saved run"}
                        {job.id === draft.review_draft.baseline_job_id ? " • Baseline" : ""}
                      </div>
                    </div>,
                    <span className={`status-chip ${statusTone(job.status)}`}>{job.status}</span>,
                    formatDateTime(job.created_at),
                    job.artifact_names.length,
                    job.result_summary?.active_flagged_count ?? "—",
                    job.artifact_names.length || isPruneableJobStatus(job.status) ? (
                      <div className="artifact-action-row">
                        {job.artifact_names.length ? (
                          <button
                            aria-label={`Inspect artifacts from run ${shortJobId(job.id)}`}
                            className="secondary-button"
                            onClick={() => handleInspectArtifacts(job)}
                            type="button"
                          >
                            Inspect artifacts
                          </button>
                        ) : null}
                        {isPruneableJobStatus(job.status) ? (
                          <button
                            aria-label={`Delete run ${shortJobId(job.id)}`}
                            className="ghost-button danger-button"
                            disabled={Boolean(busyAction)}
                            onClick={() => void handleDeleteJob(job)}
                            type="button"
                          >
                            {busyAction === `delete-job:${job.id}` ? "Deleting…" : "Delete"}
                          </button>
                        ) : null}
                      </div>
                    ) : (
                      "—"
                    ),
                  ])}
                />
              </div>
            ) : null}

            {reviewTab === "suppressions" ? (
              <div className="stack">
                <CodeEditor
                  error={null}
                  height={260}
                  hint="Edit suppressions directly. They are applied by summary, verify, report, and promote."
                  label="Suppressions YAML"
                  language="yaml"
                  onChange={(value) => {
                    setSuppressionsText(value);
                    applyDraftUpdate((current) => ({
                      ...current,
                      review_draft: {
                        ...current.review_draft,
                        suppressions_yaml: value || null,
                      },
                    }));
                  }}
                  value={suppressionsText}
                />
              </div>
            ) : null}

            {reviewTab === "promote" ? (
              <div className="stack">
                <div className="summary-card-grid">
                  <div className="summary-card">
                    <span>Promoted attacks</span>
                    <strong>{draft.artifacts.latest_promoted_suite?.attacks.length ?? 0}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Latest run</span>
                    <strong>{draft.artifacts.last_run_job_id ?? "—"}</strong>
                  </div>
                </div>
                <pre className="json-preview">
                  {draft.artifacts.latest_promoted_suite
                    ? formatJson(draft.artifacts.latest_promoted_suite)
                    : "No promoted suite yet."}
                </pre>
              </div>
            ) : null}
          </div>
        </section>

        <aside className="workbench-sidebar">
          <section className="sidebar-panel">
            <p className="eyebrow">Project state</p>
            <h3>Run history</h3>
            <ul className="job-feed">
              {currentJobs.length ? (
                currentJobs.map((job: JobStatusResponse) => (
                  <li className="job-feed-item" key={job.id}>
                    <div className="job-feed-top">
                      <code>{job.id.slice(0, 8)}</code>
                      <span className={`status-chip ${statusTone(job.status)}`}>{job.status}</span>
                    </div>
                    <p>{job.base_url}</p>
                    <small>
                      {new Date(job.created_at).toLocaleString()}
                      {job.error ? ` • ${job.error}` : ""}
                    </small>
                  </li>
                ))
              ) : (
                <li className="job-feed-item">No runs yet.</li>
              )}
            </ul>
          </section>
          <section className="sidebar-panel">
            <p className="eyebrow">Guideposts</p>
            <h3>Current materials</h3>
            <ul className="compact-list">
              <li>
                <strong>Source mode</strong>
                <span>{draft.source_mode.replace("_", " ")}</span>
              </li>
              <li>
                <strong>Suite</strong>
                <span>{draft.artifacts.generated_suite?.attacks.length ?? 0} attacks</span>
              </li>
              <li>
                <strong>Latest results</strong>
                <span>{draft.artifacts.latest_results?.results.length ?? 0} entries</span>
              </li>
              <li>
                <strong>Baseline</strong>
                <span>{baselineDescription}</span>
              </li>
              <li>
                <strong>Active findings</strong>
                <span>{draft.artifacts.latest_summary?.active_flagged_count ?? 0}</span>
              </li>
            </ul>
          </section>
        </aside>
      </div>
    </main>
  );
}
