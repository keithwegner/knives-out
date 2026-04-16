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
  createRun,
  deleteProjectJob,
  discoverModel,
  duplicateProject,
  generateSuite,
  getJobArtifact,
  getJobFindingEvidence,
  getJobResult,
  getProject,
  inspectSource,
  listProjectJobs,
  promoteResults,
  refreshProjectReview,
  pruneProjectJobs,
  triageResults,
  updateProject,
} from "../api";
import type {
  ApiJobStatus,
  ArtifactReferenceResponse,
  AttackResults,
  JobArtifactDocument,
  JobStatusResponse,
  PruneJobsRequest,
  PruneJobsResponse,
  ProjectRecord,
  ProjectReviewBaselineMode,
  ProjectSourceMode,
  ProjectStep,
  SourcePayload,
} from "../types";

type ReviewTab =
  | "overview"
  | "new"
  | "persisting"
  | "resolved"
  | "deltas"
  | "artifacts"
  | "suppressions"
  | "promote";

type ReviewTask = "findings" | "evidence" | "runs" | "policy";
type RunHistoryFilter = "all" | "active" | "completed" | "failed";
type StepStatusTone = "blocked" | "ready" | "done" | "running";

interface StepStatus {
  label: string;
  detail: string;
  tone: StepStatusTone;
}

interface NextAction {
  eyebrow: string;
  title: string;
  description: string;
  actionLabel: string;
  disabledReason: string | null;
  isBusy: boolean;
  onAction: () => void;
}

const STEP_ORDER: ProjectStep[] = ["source", "inspect", "generate", "run", "review"];
const PRUNEABLE_JOB_STATUSES: ApiJobStatus[] = ["completed", "failed"];
const REVIEW_TASKS: Array<[ReviewTask, string]> = [
  ["findings", "Findings"],
  ["evidence", "Evidence"],
  ["runs", "Runs & Reports"],
  ["policy", "Policy"],
];

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

function matchesReviewFilter(
  finding: {
    attack_id: string;
    name: string;
    kind: string;
    issue?: string | null;
    method: string;
    path?: string | null;
  },
  filter: string,
) {
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
}

function formatJobMoment(value?: string | null) {
  return value ? new Date(value).toLocaleString() : "—";
}

function summarizeJob(job: JobStatusResponse) {
  const active = job.result_summary?.active_flagged_count;
  const latestMoment = job.completed_at ?? job.started_at ?? job.created_at;
  const summaryBits = [
    formatJobMoment(latestMoment),
    active === undefined || active === null ? null : `${active} active`,
  ].filter(Boolean);
  return summaryBits.join(" • ");
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

function stepLabel(step: ProjectStep): string {
  if (step === "source") {
    return "Source";
  }
  if (step === "inspect") {
    return "Inspect";
  }
  if (step === "generate") {
    return "Generate";
  }
  if (step === "run") {
    return "Run";
  }
  return "Review";
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

function findingChangeLabel(change: string) {
  if (change === "new") {
    return "New";
  }
  if (change === "persisting") {
    return "Persisting";
  }
  if (change === "resolved") {
    return "Resolved";
  }
  return "Current";
}

function artifactKindLabel(kind: ArtifactReferenceResponse["kind"]) {
  if (kind === "workflow_terminal") {
    return "workflow terminal";
  }
  if (kind === "workflow_step") {
    return "workflow step";
  }
  if (kind === "profile_request") {
    return "profile request";
  }
  if (kind === "profile_workflow_step") {
    return "profile step";
  }
  return "request";
}

function artifactPath(jobId: string, artifactName: string) {
  const encodedName = artifactName
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return `/v1/jobs/${jobId}/artifacts/${encodedName}`;
}

function ArtifactDocumentPreview({
  document,
}: {
  document: JobArtifactDocument | null | undefined;
}) {
  if (!document) {
    return <p className="empty-copy">Select an artifact to inspect.</p>;
  }

  if (
    document.format === "json" &&
    document.content &&
    typeof document.content === "object" &&
    !Array.isArray(document.content) &&
    "request" in document.content &&
    "response" in document.content
  ) {
    const content = document.content as {
      attack?: Record<string, unknown>;
      request?: {
        method?: string;
        url?: string;
        headers?: unknown;
        query?: unknown;
        body?: unknown;
      };
      response?: {
        status_code?: number | null;
        error?: string | null;
        duration_ms?: number | null;
        body_excerpt?: string | null;
      };
    };
    const attack = content.attack ?? {};
    const request = content.request ?? {};
    const response = content.response ?? {};
    const body = request.body as
      | {
          kind?: string;
          content_type?: string | null;
          excerpt?: string | null;
          present?: boolean;
        }
      | undefined;

    return (
      <div className="stack">
        <div className="summary-card-grid">
          <div className="summary-card">
            <span>Artifact</span>
            <strong>{String(attack.name ?? attack.id ?? document.artifact_name)}</strong>
          </div>
          <div className="summary-card">
            <span>Request</span>
            <strong>{String(request.method ?? "—")}</strong>
          </div>
          <div className="summary-card">
            <span>Response</span>
            <strong>{response.status_code ?? "—"}</strong>
          </div>
          <div className="summary-card">
            <span>Duration</span>
            <strong>{response.duration_ms ? `${response.duration_ms} ms` : "—"}</strong>
          </div>
        </div>
        <article className="artifact-structured-card">
          <h4>Request</h4>
          <p>
            <strong>{String(request.method ?? "—")}</strong> {String(request.url ?? "—")}
          </p>
          <pre className="json-preview">{formatJson(request.headers ?? {})}</pre>
          <pre className="json-preview">{formatJson(request.query ?? {})}</pre>
          {body?.present ? (
            <pre className="json-preview">
              {body.kind === "json" && body.excerpt
                ? body.excerpt
                : body?.excerpt || body?.content_type || "Request body present."}
            </pre>
          ) : (
            <p className="field-hint">No request body recorded.</p>
          )}
        </article>
        <article className="artifact-structured-card">
          <h4>Response</h4>
          <p>
            <strong>Status:</strong> {response.status_code ?? "—"}{" "}
            <strong>Error:</strong> {response.error ?? "—"}
          </p>
          <pre className="json-preview">{String(response.body_excerpt ?? "No response body excerpt.")}</pre>
        </article>
      </div>
    );
  }

  return (
    <pre className="json-preview">
      {document.format === "json" ? formatJson(document.content) : String(document.content)}
    </pre>
  );
}

function ArtifactViewer({
  jobId,
  references,
  selectedArtifactName,
  onSelect,
  document,
  isLoading,
  error,
  emptyCopy,
}: {
  jobId: string;
  references: ArtifactReferenceResponse[];
  selectedArtifactName: string | null;
  onSelect: (artifactName: string) => void;
  document: JobArtifactDocument | null | undefined;
  isLoading: boolean;
  error: string | null;
  emptyCopy: string;
}) {
  const selectedReference =
    references.find((reference) => reference.artifact_name === selectedArtifactName) ?? null;

  return (
    <div className="artifact-viewer">
      <ul className="artifact-reference-list">
        {references.length ? (
          references.map((reference) => (
            <li
              className={`artifact-reference-item${
                selectedReference?.artifact_name === reference.artifact_name
                  ? " artifact-reference-item-active"
                  : ""
              }`}
              key={reference.artifact_name}
            >
              <button
                className="artifact-reference-button"
                disabled={!reference.available}
                onClick={() => onSelect(reference.artifact_name)}
                type="button"
              >
                {reference.label}
              </button>
              <small>{reference.artifact_name}</small>
              <div className="artifact-reference-meta">
                <span>{artifactKindLabel(reference.kind)}</span>
                {reference.available ? (
                  <a href={artifactPath(jobId, reference.artifact_name)} rel="noreferrer" target="_blank">
                    raw
                  </a>
                ) : (
                  <span>missing</span>
                )}
              </div>
            </li>
          ))
        ) : (
          <li className="artifact-reference-item">
            <span>{emptyCopy}</span>
          </li>
        )}
      </ul>
      <div className="artifact-preview-panel">
        {!selectedReference ? (
          <p className="empty-copy">{emptyCopy}</p>
        ) : !selectedReference.available ? (
          <div className="empty-state">
            <p>This artifact was expected for the finding, but it is not stored for this run.</p>
            <small>{selectedReference.artifact_name}</small>
          </div>
        ) : isLoading ? (
          <p className="empty-copy">Loading artifact…</p>
        ) : error ? (
          <div className="empty-state">
            <p>{error}</p>
          </div>
        ) : (
          <ArtifactDocumentPreview document={document} />
        )}
      </div>
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
  statuses,
}: {
  activeStep: ProjectStep;
  onChange: (step: ProjectStep) => void;
  statuses: Record<ProjectStep, StepStatus>;
}) {
  return (
    <nav className="step-rail" aria-label="Workbench steps">
      {STEP_ORDER.map((step, index) => (
        <button
          aria-current={step === activeStep ? "step" : undefined}
          className={`step-rail-button step-rail-${statuses[step].tone}${
            step === activeStep ? " step-rail-button-active" : ""
          }`}
          key={step}
          onClick={() => onChange(step)}
          type="button"
        >
          <span className="step-rail-index">0{index + 1}</span>
          <span className="step-rail-name">{stepLabel(step)}</span>
          <span className="step-rail-status">{statuses[step].label}</span>
          <span className="step-rail-detail">{statuses[step].detail}</span>
        </button>
      ))}
    </nav>
  );
}

function NextActionCard({ action }: { action: NextAction }) {
  return (
    <section className="next-action-card" aria-label="Next action">
      <div>
        <p className="eyebrow">{action.eyebrow}</p>
        <h2>{action.title}</h2>
        <p>{action.description}</p>
        {action.disabledReason ? <p className="next-action-blocker">{action.disabledReason}</p> : null}
      </div>
      <button
        className="primary-button"
        disabled={Boolean(action.disabledReason) || action.isBusy}
        onClick={action.onAction}
        type="button"
      >
        {action.isBusy ? "Working…" : action.actionLabel}
      </button>
    </section>
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
  const [reviewTask, setReviewTask] = useState<ReviewTask>("findings");
  const [reviewTab, setReviewTab] = useState<ReviewTab>("overview");
  const [reviewFilter, setReviewFilter] = useState("");
  const [selectedEvidenceAttackId, setSelectedEvidenceAttackId] = useState<string | null>(null);
  const [selectedDrawerArtifactName, setSelectedDrawerArtifactName] = useState<string | null>(null);
  const [selectedArtifactsTabArtifactName, setSelectedArtifactsTabArtifactName] = useState<string | null>(null);
  const [evidenceNotice, setEvidenceNotice] = useState<string | null>(null);
  const [runHistoryFilter, setRunHistoryFilter] = useState<RunHistoryFilter>("all");
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

  const currentJobs = projectJobsQuery.data?.jobs ?? [];
  const completedReviewJobs = currentJobs.filter(
    (job) => job.status === "completed" && job.result_available,
  );
  const currentReviewedJob =
    currentJobs.find((job) => job.id === draft?.artifacts.last_run_job_id) ??
    completedReviewJobs[0] ??
    null;

  const findingEvidenceQuery = useQuery({
    queryKey: ["jobFindingEvidence", currentReviewedJob?.id, selectedEvidenceAttackId],
    queryFn: () => getJobFindingEvidence(currentReviewedJob!.id, selectedEvidenceAttackId!),
    enabled: Boolean(currentReviewedJob?.id && selectedEvidenceAttackId),
  });

  const drawerArtifactQuery = useQuery({
    queryKey: ["jobArtifact", currentReviewedJob?.id, selectedDrawerArtifactName],
    queryFn: () => getJobArtifact(currentReviewedJob!.id, selectedDrawerArtifactName!),
    enabled: Boolean(currentReviewedJob?.id && selectedDrawerArtifactName),
  });

  const artifactsTabArtifactQuery = useQuery({
    queryKey: ["jobArtifact", currentReviewedJob?.id, "artifacts-tab", selectedArtifactsTabArtifactName],
    queryFn: () => getJobArtifact(currentReviewedJob!.id, selectedArtifactsTabArtifactName!),
    enabled: Boolean(currentReviewedJob?.id && selectedArtifactsTabArtifactName),
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

  function commitDraft(project: ProjectRecord) {
    setDraft(project);
    setHasPendingSave(true);
  }

  function withReviewBundle(project: ProjectRecord, review: Awaited<ReturnType<typeof refreshProjectReview>>) {
    return {
      ...project,
      active_step: "review" as const,
      artifacts: {
        ...project.artifacts,
        last_run_job_id: review.current_job_id,
        latest_results: review.results,
        latest_summary: review.summary,
        latest_verification: review.verification,
        latest_markdown_report: review.markdown_report,
        latest_html_report: review.html_report,
      },
    };
  }

  async function runReviewRefresh(project: ProjectRecord, successMessage: string) {
    if (project.review_draft.baseline_mode === "external" && baselineError) {
      setActionError("Fix external baseline JSON before refreshing the review workspace.");
      return;
    }
    setBusyAction("refresh-review");
    setActionError(null);
    try {
      const review = await refreshProjectReview(project.id, project.review_draft);
      commitDraft(withReviewBundle(project, review));
      setReviewTask("findings");
      setReviewTab("overview");
      setActivityMessage(
        review.waiting_for_new_run
          ? "Baseline pinned to the latest completed run. New diffs will appear after the next completed run."
          : successMessage,
      );
      setActionError(null);
      void projectJobsQuery.refetch();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Could not refresh review workspace.");
    } finally {
      setBusyAction(null);
    }
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
    void (async () => {
      try {
        await runReviewRefresh(draft, "Run finished and the review workspace is up to date.");
      } finally {
        setTrackedJobId(null);
      }
    })();
  }, [draft, projectJobsQuery.data, trackedJobId]);

  useEffect(() => {
    const currentFindingIds = new Set(
      draft?.artifacts.latest_verification?.current_findings.map((finding) => finding.attack_id) ?? [],
    );
    if (!selectedEvidenceAttackId) {
      return;
    }
    if (currentFindingIds.has(selectedEvidenceAttackId)) {
      return;
    }
    setSelectedEvidenceAttackId(null);
    setSelectedDrawerArtifactName(null);
    setEvidenceNotice("Evidence changed with the latest run. Reopen a finding from the refreshed comparison.");
  }, [draft?.artifacts.latest_verification, selectedEvidenceAttackId]);

  useEffect(() => {
    const references = findingEvidenceQuery.data?.artifacts ?? [];
    if (!selectedEvidenceAttackId) {
      if (selectedDrawerArtifactName !== null) {
        setSelectedDrawerArtifactName(null);
      }
      return;
    }
    if (!references.length) {
      if (selectedDrawerArtifactName !== null) {
        setSelectedDrawerArtifactName(null);
      }
      return;
    }
    if (selectedDrawerArtifactName && references.some((artifact) => artifact.artifact_name === selectedDrawerArtifactName)) {
      return;
    }
    const nextArtifact = references.find((artifact) => artifact.available) ?? references[0];
    setSelectedDrawerArtifactName(nextArtifact.artifact_name);
  }, [findingEvidenceQuery.data, selectedDrawerArtifactName, selectedEvidenceAttackId]);

  useEffect(() => {
    const artifactNames = currentReviewedJob?.artifact_names ?? [];
    if (!artifactNames.length) {
      if (selectedArtifactsTabArtifactName !== null) {
        setSelectedArtifactsTabArtifactName(null);
      }
      return;
    }
    if (selectedArtifactsTabArtifactName && artifactNames.includes(selectedArtifactsTabArtifactName)) {
      return;
    }
    setSelectedArtifactsTabArtifactName(artifactNames[0]);
  }, [currentReviewedJob, selectedArtifactsTabArtifactName]);

  useEffect(() => {
    setPrunePreview(null);
  }, [pruneCompletedBefore, pruneLimit, pruneStatuses]);

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
  const latestJob = currentJobs[0];
  const baselineReviewedJob = draft.review_draft.baseline_job_id
    ? currentJobs.find((job) => job.id === draft.review_draft.baseline_job_id) ?? null
    : null;
  const verification = draft.artifacts.latest_verification;
  const currentFindings = verification?.current_findings ?? [];
  const newFindingIds = new Set(verification?.new_findings.map((finding) => finding.attack_id) ?? []);
  const persistingFindingIds = new Set(
    verification?.persisting_findings.map((finding) => finding.attack_id) ?? [],
  );
  const selectedEvidenceFinding = selectedEvidenceAttackId
    ? currentFindings.find((finding) => finding.attack_id === selectedEvidenceAttackId) ?? null
    : null;
  const selectedEvidenceChange = selectedEvidenceAttackId
    ? newFindingIds.has(selectedEvidenceAttackId)
      ? "new"
      : persistingFindingIds.has(selectedEvidenceAttackId)
        ? "persisting"
        : "current"
    : null;
  const reviewWaitingForNewRun =
    draft.review_draft.baseline_mode === "job" &&
    Boolean(currentReviewedJob && baselineReviewedJob && currentReviewedJob.id === baselineReviewedJob.id);
  const baselineDescription =
    draft.review_draft.baseline_mode === "external"
      ? draft.review_draft.baseline
        ? `External JSON • ${formatDateTime(draft.review_draft.baseline.executed_at)}`
        : "External JSON baseline not loaded"
      : baselineReviewedJob
        ? `Run ${shortJobId(baselineReviewedJob.id)} • ${formatJobMoment(jobTimestamp(baselineReviewedJob))}`
        : "No comparison baseline selected";
  const newFindings =
    verification?.new_findings.filter((finding) => matchesReviewFilter(finding, deferredReviewFilter)) ?? [];
  const persistingFindings =
    verification?.persisting_findings.filter((finding) =>
      matchesReviewFilter(finding, deferredReviewFilter),
    ) ?? [];
  const resolvedFindings =
    verification?.resolved_findings.filter((finding) =>
      matchesReviewFilter(finding, deferredReviewFilter),
    ) ?? [];
  const deltaFindings = persistingFindings.filter((finding) => finding.delta_changes.length);
  const artifactBrowserReferences = (currentReviewedJob?.artifact_names ?? []).map(
    (artifactName): ArtifactReferenceResponse => ({
      label: artifactName,
      kind: artifactName.includes("-step-")
        ? artifactName.includes("/")
          ? "profile_workflow_step"
          : "workflow_step"
        : artifactName.includes("/")
          ? "profile_request"
          : "request",
      artifact_name: artifactName,
      available: true,
      profile: artifactName.includes("/") ? artifactName.split("/")[0] : null,
      step_index: null,
    }),
  );
  const findingEvidenceError =
    findingEvidenceQuery.error instanceof Error ? findingEvidenceQuery.error.message : null;
  const drawerArtifactError =
    drawerArtifactQuery.error instanceof Error ? drawerArtifactQuery.error.message : null;
  const artifactsTabArtifactError =
    artifactsTabArtifactQuery.error instanceof Error ? artifactsTabArtifactQuery.error.message : null;
  const sourceDocumentReady = Boolean(draft.source?.content.trim());
  const suiteReady = Boolean(draft.artifacts.generated_suite?.attacks.length);
  const targetReady = Boolean(draft.run_draft.base_url.trim());
  const activeRun = currentJobs.find((job) => job.status === "pending" || job.status === "running");
  const stepStatuses: Record<ProjectStep, StepStatus> = {
    source: sourceDocumentReady
      ? {
          label: "Done",
          detail: `${draft.source_mode.replace("_", " ")} source saved`,
          tone: "done",
        }
      : draft.source_mode === "capture_upload" && draft.discover_inputs.length
        ? {
            label: "Ready",
            detail: `${draft.discover_inputs.length} capture file(s) loaded`,
            tone: "ready",
          }
        : {
            label: "Needs source",
            detail: "Add schema or captures",
            tone: "blocked",
          },
    inspect: draft.artifacts.inspect_result
      ? {
          label: "Done",
          detail: `${draft.artifacts.inspect_result.operations.length} operation(s)`,
          tone: "done",
        }
      : sourceDocumentReady
        ? {
            label: "Ready",
            detail: "Preflight available",
            tone: "ready",
          }
        : {
            label: "Needs source",
            detail: "Inspect waits for source",
            tone: "blocked",
          },
    generate: suiteReady
      ? {
          label: "Done",
          detail: `${draft.artifacts.generated_suite?.attacks.length ?? 0} attack(s)`,
          tone: "done",
        }
      : sourceDocumentReady
        ? {
            label: "Ready",
            detail: "Suite can be generated",
            tone: "ready",
          }
        : {
            label: "Needs source",
            detail: "Generate waits for source",
            tone: "blocked",
          },
    run: activeRun
      ? {
          label: "Running",
          detail: shortJobId(activeRun.id),
          tone: "running",
        }
      : currentReviewedJob
        ? {
            label: "Done",
            detail: `${currentReviewedJob.artifact_names.length} artifact(s)`,
            tone: "done",
          }
        : suiteReady
          ? {
              label: targetReady ? "Ready" : "Needs target",
              detail: targetReady ? "Run can start" : "Add a base URL",
              tone: targetReady ? "ready" : "blocked",
            }
          : {
              label: "Needs suite",
              detail: "Generate attacks first",
              tone: "blocked",
            },
    review: currentReviewedJob
      ? {
          label: "Review ready",
          detail: `${currentFindings.length} active finding(s)`,
          tone: "done",
        }
      : activeRun
        ? {
            label: "Running",
            detail: "Waiting for results",
            tone: "running",
          }
        : {
            label: "Needs run",
            detail: "Run a suite first",
            tone: "blocked",
          },
  };
  const nextAction: NextAction =
    draft.active_step === "source"
      ? draft.source_mode === "capture_upload"
        ? {
            eyebrow: "Next action",
            title: "Discover a source model from captured traffic",
            description:
              "Upload HAR or capture NDJSON files, then convert them into a learned model before inspection.",
            actionLabel: "Discover learned model",
            disabledReason: draft.discover_inputs.length
              ? null
              : "Upload at least one capture file to continue.",
            isBusy: busyAction === "discover",
            onAction: () => void handleDiscover(),
          }
        : {
            eyebrow: "Next action",
            title: "Inspect the source surface",
            description:
              "Load or paste the API source, then preflight the operations before choosing attacks.",
            actionLabel: "Inspect source",
            disabledReason: sourceDocumentReady ? null : "Paste or upload a source document first.",
            isBusy: busyAction === "inspect",
            onAction: () => void handleInspect(),
          }
      : draft.active_step === "inspect"
        ? {
            eyebrow: "Next action",
            title: "Refresh operation discovery",
            description:
              "Apply the inspect filters and confirm which operations are available for attack generation.",
            actionLabel: "Inspect source",
            disabledReason: sourceDocumentReady ? null : "Add a source document before inspecting.",
            isBusy: busyAction === "inspect",
            onAction: () => void handleInspect(),
          }
        : draft.active_step === "generate"
          ? {
              eyebrow: "Next action",
              title: "Generate an attack suite",
              description:
                "Use the selected filters and packs to build the suite that will run against your target.",
              actionLabel: "Generate suite",
              disabledReason: sourceDocumentReady ? null : "Add a source document before generating.",
              isBusy: busyAction === "generate",
              onAction: () => void handleGenerate(),
            }
          : draft.active_step === "run"
            ? {
                eyebrow: "Next action",
                title: "Run the suite against a target",
                description:
                  "Set the base URL and optional auth context, then start a project-scoped background run.",
                actionLabel: "Run suite",
                disabledReason: !suiteReady
                  ? "Generate an attack suite before running."
                  : !targetReady
                    ? "Add a base URL before starting a run."
                    : headersError || queryError
                      ? "Fix JSON errors in the run settings before starting."
                      : null,
                isBusy: busyAction === "run",
                onAction: () => void handleRun(),
              }
            : {
                eyebrow: "Next action",
                title: "Review the latest completed run",
                description:
                  "Refresh analysis to update findings, evidence, reports, policy checks, and comparison state.",
                actionLabel: "Refresh analysis",
                disabledReason: completedReviewJobs.length
                  ? null
                  : "Complete at least one run before reviewing.",
                isBusy: busyAction === "refresh-review",
                onAction: () => void handleRefreshReview(),
              };

  async function resolvePromotionReview(project: ProjectRecord) {
    if (project.review_draft.baseline_mode === "external") {
      if (baselineError) {
        throw new Error("Fix external baseline JSON before promoting findings.");
      }
      return project.review_draft;
    }
    if (!project.review_draft.baseline_job_id) {
      return project.review_draft;
    }
    const baselineResults = await getJobResult(project.review_draft.baseline_job_id);
    return {
      ...project.review_draft,
      baseline: baselineResults,
    };
  }

  function openFindingEvidence(finding: { attack_id: string }) {
    setReviewTask("evidence");
    setSelectedEvidenceAttackId(finding.attack_id);
    setSelectedDrawerArtifactName(null);
    setEvidenceNotice(null);
  }

  function findingAction(label: string, finding: { attack_id: string }) {
    return (
      <button className="finding-link" onClick={() => openFindingEvidence(finding)} type="button">
        {label}
      </button>
    );
  }

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
    if (!completedReviewJobs.length) {
      setActionError("Run a suite first so there is a completed project run to analyze.");
      return;
    }
    await runReviewRefresh(project, "Review workspace refreshed.");
  }

  async function handleBaselineSelection(jobId: string) {
    await handleBaselineJobChange(jobId);
  }

  async function handleClearBaseline() {
    const project = getLoadedProject();
    const nextProject = {
      ...project,
      review_draft: {
        ...project.review_draft,
        baseline_job_id: null,
        baseline: null,
      },
    };
    setBaselineText("");
    setBaselineError(null);
    commitDraft(nextProject);
    if (!completedReviewJobs.length) {
      setActivityMessage("Comparison baseline cleared.");
      return;
    }
    await runReviewRefresh(nextProject, "Comparison baseline cleared.");
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
      setReviewTask("policy");
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
      const promotionReview = await resolvePromotionReview(project);
      const promoted = await promoteResults(
        project.artifacts.latest_results,
        project.artifacts.generated_suite,
        promotionReview,
      );
      applyDraftUpdate((current) => ({
        ...current,
        artifacts: {
          ...current.artifacts,
          latest_promoted_suite: promoted.promoted_suite,
        },
      }));
      setActivityMessage(`Promoted ${promoted.promoted_attack_ids.length} attack(s).`);
      setReviewTask("policy");
      setReviewTab("promote");
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Promotion failed.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleBaselineModeChange(nextMode: ProjectReviewBaselineMode) {
    const project = getLoadedProject();
    const nextProject = {
      ...project,
      review_draft: {
        ...project.review_draft,
        baseline_mode: nextMode,
      },
    };
    commitDraft(nextProject);
    if (completedReviewJobs.length) {
      await runReviewRefresh(
        nextProject,
        nextMode === "external"
          ? "Review workspace switched to external baseline mode."
          : "Review workspace switched to project history baseline mode.",
      );
    }
  }

  async function handleBaselineJobChange(jobId: string) {
    const project = getLoadedProject();
    const nextProject = {
      ...project,
      review_draft: {
        ...project.review_draft,
        baseline_mode: "job" as const,
        baseline_job_id: jobId || null,
      },
    };
    commitDraft(nextProject);
    if (completedReviewJobs.length) {
      await runReviewRefresh(
        nextProject,
        jobId
          ? "Pinned a project run as the baseline."
          : "Cleared the baseline selection for this review workspace.",
      );
    }
  }

  async function handlePinLatestBaseline() {
    if (!currentReviewedJob) {
      setActionError("Run a suite first so there is a completed run to pin as the baseline.");
      return;
    }
    await handleBaselineJobChange(currentReviewedJob.id);
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

    const fallbackReviewJob =
      remainingJobs.find((job) => job.status === "completed" && job.result_available) ?? null;
    const nextProject = {
      ...project,
      review_draft: {
        ...project.review_draft,
        baseline_job_id: baselineRemoved ? null : project.review_draft.baseline_job_id,
        baseline: baselineRemoved ? null : project.review_draft.baseline,
      },
      artifacts: {
        ...project.artifacts,
        latest_promoted_suite: null,
        latest_suppressions: null,
      },
    };

    setBaselineText(
      nextProject.review_draft.baseline ? formatJson(nextProject.review_draft.baseline) : "",
    );
    setBaselineError(null);

    if (!fallbackReviewJob) {
      commitDraft({
        ...nextProject,
        artifacts: {
          ...nextProject.artifacts,
          last_run_job_id: null,
          latest_results: null,
          latest_summary: null,
          latest_verification: null,
          latest_markdown_report: null,
          latest_html_report: null,
          latest_promoted_suite: null,
          latest_suppressions: null,
        },
      });
      return;
    }

    const refreshedProject = {
      ...nextProject,
      artifacts: {
        ...nextProject.artifacts,
        last_run_job_id: currentJobRemoved ? fallbackReviewJob.id : nextProject.artifacts.last_run_job_id,
      },
    };

    await runReviewRefresh(
      refreshedProject,
      currentJobRemoved
        ? "Deleted the current review run and refreshed the comparison."
        : "Deleted a saved baseline run and refreshed the comparison.",
    );
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
          statuses={stepStatuses}
        />

        <section className="workbench-main">
          <NextActionCard action={nextAction} />

          {draft.active_step === "source" ? (
          <div className="panel step-panel">
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
          ) : null}

          {draft.active_step === "inspect" ? (
          <div className="panel step-panel">
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
          ) : null}

          {draft.active_step === "generate" ? (
          <div className="panel step-panel">
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
          ) : null}

          {draft.active_step === "run" ? (
          <div className="panel step-panel">
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
          ) : null}

          {draft.active_step === "review" ? (
          <div className="panel step-panel">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Review</p>
                <h2>Baseline-aware review workspace</h2>
              </div>
              <div className="action-row">
                <button
                  className="secondary-button"
                  disabled={busyAction === "refresh-review" || !completedReviewJobs.length}
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
            <div className="compare-banner">
              <article className="compare-card">
                <span>Current run</span>
                <strong>{currentReviewedJob ? currentReviewedJob.id.slice(0, 8) : "No completed run"}</strong>
                <small>
                  {currentReviewedJob
                    ? `${summarizeJob(currentReviewedJob)} • ${currentReviewedJob.base_url}`
                    : "Run a suite to create the current comparison target."}
                </small>
              </article>
              <article className="compare-card">
                <span>Baseline</span>
                <strong>
                  {draft.review_draft.baseline_mode === "external"
                    ? "External JSON"
                    : baselineReviewedJob
                      ? baselineReviewedJob.id.slice(0, 8)
                      : "Not pinned"}
                </strong>
                <small>
                  {draft.review_draft.baseline_mode === "external"
                    ? draft.review_draft.baseline
                      ? "Advanced fallback is active for this comparison."
                      : "External mode is active, but no baseline JSON is loaded yet."
                    : baselineReviewedJob
                      ? `${summarizeJob(baselineReviewedJob)}`
                      : "Select a prior completed run or pin the latest run first."}
                </small>
              </article>
              <article className="compare-card">
                <span>Compare state</span>
                <strong>
                  {reviewWaitingForNewRun
                    ? "Waiting for next run"
                    : draft.artifacts.latest_summary?.baseline_used
                      ? "Diffs ready"
                      : "Latest run only"}
                </strong>
                <small>
                  Last refreshed {formatJobMoment(draft.artifacts.latest_summary?.executed_at)}
                </small>
              </article>
            </div>

            <div className="tab-row review-task-row" role="tablist" aria-label="Review task groups">
              {REVIEW_TASKS.map(([task, label]) => (
                <button
                  aria-selected={reviewTask === task}
                  className={`tab-button${reviewTask === task ? " tab-button-active" : ""}`}
                  key={task}
                  onClick={() => setReviewTask(task)}
                  role="tab"
                  type="button"
                >
                  {label}
                </button>
              ))}
            </div>

            {reviewTask === "policy" ? (
            <div className="stack review-task-panel">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Policy</p>
                <h3>Set thresholds, baselines, suppressions, and promotion rules.</h3>
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
            </div>
            <div className="field-grid field-grid-3">
              <div className="field">
                <span className="field-label">Baseline source</span>
                <div className="mode-switch">
                  {(["job", "external"] as ProjectReviewBaselineMode[]).map((mode) => (
                    <button
                      className={`mode-button${
                        draft.review_draft.baseline_mode === mode ? " mode-button-active" : ""
                      }`}
                      key={mode}
                      onClick={() => void handleBaselineModeChange(mode)}
                      type="button"
                    >
                      {mode === "job" ? "Project history" : "External JSON"}
                    </button>
                  ))}
                </div>
              </div>
              <label className="field">
                <span className="field-label">Pinned baseline run</span>
                <select
                  aria-label="Pinned baseline run"
                  className="text-input"
                  disabled={draft.review_draft.baseline_mode !== "job"}
                  value={draft.review_draft.baseline_job_id ?? ""}
                  onChange={(event) => void handleBaselineJobChange(event.target.value)}
                >
                  <option value="">No pinned baseline</option>
                  {completedReviewJobs.map((job) => (
                    <option key={job.id} value={job.id}>
                      {`${job.id.slice(0, 8)} • ${summarizeJob(job)}`}
                    </option>
                  ))}
                </select>
                <span className="field-hint">Pick a completed run from this project’s history.</span>
              </label>
              <div className="field">
                <span className="field-label">Latest run shortcut</span>
                <div className="action-row">
                  <button
                    className="secondary-button"
                    disabled={!currentReviewedJob || busyAction === "refresh-review"}
                    onClick={() => void handlePinLatestBaseline()}
                    type="button"
                  >
                    Pin latest run as baseline
                  </button>
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
                <span className="field-hint">
                  Record today’s latest completed run, then wait for the next completed run to diff against it.
                </span>
              </div>
            </div>

            <details className="advanced-panel">
              <summary>External baseline JSON</summary>
              <p className="field-hint">
                Advanced fallback for comparison inputs that do not come from this project’s run history.
              </p>
              <CodeEditor
                error={baselineError}
                height={220}
                hint="Only used when baseline source is set to External JSON."
                label="External baseline results JSON"
                language="json"
                onChange={(value) => {
                  setBaselineText(value);
                  if (!value.trim()) {
                    setBaselineError(null);
                    applyDraftUpdate((current) => ({
                      ...current,
                      review_draft: { ...current.review_draft, baseline: null },
                    }));
                    return;
                  }
                  try {
                    const parsed = JSON.parse(value) as AttackResults;
                    setBaselineError(null);
                    applyDraftUpdate((current) => ({
                      ...current,
                      review_draft: { ...current.review_draft, baseline: parsed },
                    }));
                  } catch (error) {
                    setBaselineError(error instanceof Error ? error.message : "Invalid JSON.");
                  }
                }}
                value={baselineText}
              />
            </details>
            </div>
            ) : null}

            {reviewTask === "findings" ? (
            <div className="stack review-task-panel">
            <label className="field">
              <span className="field-label">Findings filter</span>
              <input
                className="text-input"
                value={reviewFilter}
                onChange={(event) => setReviewFilter(event.target.value)}
                placeholder="search by attack, kind, issue, path"
              />
            </label>
            <div className="tab-row" role="tablist" aria-label="Findings panels">
              {(
                [
                  ["overview", "Overview"],
                  ["new", "New"],
                  ["persisting", "Persisting"],
                  ["resolved", "Resolved"],
                  ["deltas", "Deltas"],
                ] as Array<[ReviewTab, string]>
              ).map(([tab, label]) => (
                <button
                  className={`tab-button${reviewTab === tab ? " tab-button-active" : ""}`}
                  key={tab}
                  onClick={() => setReviewTab(tab)}
                  aria-selected={reviewTab === tab}
                  role="tab"
                  type="button"
                >
                  {label}
                </button>
              ))}
            </div>
            </div>
            ) : null}

            {reviewTask === "evidence" ? (
            <div className="stack review-task-panel">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">Evidence</p>
                  <h3>Inspect artifacts, auth events, and finding-level request evidence.</h3>
                </div>
              </div>
            {selectedEvidenceAttackId && currentReviewedJob ? (
              <section className="evidence-drawer">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">Current-run evidence</p>
                    <h3>{selectedEvidenceFinding?.name ?? selectedEvidenceAttackId}</h3>
                    <p className="field-hint">
                      {findingChangeLabel(selectedEvidenceChange ?? "current")} finding from run{" "}
                      <code>{currentReviewedJob.id.slice(0, 8)}</code>
                    </p>
                  </div>
                  <button
                    className="secondary-button"
                    onClick={() => {
                      setSelectedEvidenceAttackId(null);
                      setSelectedDrawerArtifactName(null);
                    }}
                    type="button"
                  >
                    Close evidence
                  </button>
                </div>
                {findingEvidenceQuery.isLoading ? (
                  <p className="empty-copy">Loading finding evidence…</p>
                ) : findingEvidenceError ? (
                  <div className="empty-state">
                    <p>{findingEvidenceError}</p>
                  </div>
                ) : findingEvidenceQuery.data ? (
                  <div className="stack">
                    <div className="summary-card-grid">
                      <div className="summary-card">
                        <span>Compare state</span>
                        <strong>{findingChangeLabel(selectedEvidenceChange ?? "current")}</strong>
                      </div>
                      <div className="summary-card">
                        <span>Issue</span>
                        <strong>{findingEvidenceQuery.data.result.issue ?? "—"}</strong>
                      </div>
                      <div className="summary-card">
                        <span>Severity</span>
                        <strong>{findingEvidenceQuery.data.result.severity}</strong>
                      </div>
                      <div className="summary-card">
                        <span>Status</span>
                        <strong>{findingEvidenceQuery.data.result.status_code ?? "—"}</strong>
                      </div>
                    </div>
                    <ReviewTable
                      emptyCopy="No evidence metadata for this finding."
                      headings={["Method", "Path", "Kind", "URL"]}
                      rows={[
                        [
                          findingEvidenceQuery.data.result.method,
                          findingEvidenceQuery.data.result.path ?? "—",
                          findingEvidenceQuery.data.result.kind,
                          findingEvidenceQuery.data.result.url,
                        ],
                      ]}
                    />
                    {(findingEvidenceQuery.data.result.workflow_steps ?? []).length ? (
                      <ReviewTable
                        emptyCopy="No workflow steps recorded."
                        headings={["Step", "Method", "Status", "Duration", "URL"]}
                        rows={(findingEvidenceQuery.data.result.workflow_steps ?? []).map((step) => [
                          step.name,
                          step.method,
                          step.status_code ?? "—",
                          step.duration_ms ? `${step.duration_ms} ms` : "—",
                          step.url,
                        ])}
                      />
                    ) : null}
                    {(findingEvidenceQuery.data.result.profile_results ?? []).length ? (
                      <ReviewTable
                        emptyCopy="No profile evidence recorded."
                        headings={["Profile", "Level", "Status", "Issue", "Severity", "Workflow steps"]}
                        rows={(findingEvidenceQuery.data.result.profile_results ?? []).map((profile) => [
                          profile.anonymous ? `${profile.profile} (anonymous)` : profile.profile,
                          profile.level,
                          profile.status_code ?? "—",
                          profile.issue ?? "—",
                          profile.severity,
                          profile.workflow_steps?.length ?? 0,
                        ])}
                      />
                    ) : null}
                    <ArtifactViewer
                      document={drawerArtifactQuery.data}
                      emptyCopy="No artifact references were derived for this finding."
                      error={drawerArtifactError}
                      isLoading={drawerArtifactQuery.isLoading}
                      jobId={currentReviewedJob.id}
                      onSelect={setSelectedDrawerArtifactName}
                      references={findingEvidenceQuery.data.artifacts}
                      selectedArtifactName={selectedDrawerArtifactName}
                    />
                    {findingEvidenceQuery.data.highlighted_auth_events.length ? (
                      <ReviewTable
                        emptyCopy="No matching auth events."
                        headings={["Profile", "Name", "Strategy", "Phase", "Status", "Error"]}
                        rows={findingEvidenceQuery.data.highlighted_auth_events.map((event) => [
                          event.profile ?? "—",
                          event.name,
                          event.strategy,
                          event.phase,
                          event.status_code ?? (event.success ? "ok" : "failed"),
                          event.error ?? "—",
                        ])}
                      />
                    ) : null}
                    <ReviewTable
                      emptyCopy="No auth events captured for this run."
                      headings={["Profile", "Name", "Strategy", "Phase", "Status", "Error"]}
                      rows={findingEvidenceQuery.data.auth_events.map((event) => [
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
              </section>
            ) : evidenceNotice ? (
              <div className="empty-state">
                <p>{evidenceNotice}</p>
              </div>
            ) : null}
              {currentReviewedJob ? (
                <ArtifactViewer
                  document={artifactsTabArtifactQuery.data}
                  emptyCopy="No artifacts linked to the current compared run."
                  error={artifactsTabArtifactError}
                  isLoading={artifactsTabArtifactQuery.isLoading}
                  jobId={currentReviewedJob.id}
                  onSelect={setSelectedArtifactsTabArtifactName}
                  references={artifactBrowserReferences}
                  selectedArtifactName={selectedArtifactsTabArtifactName}
                />
              ) : (
                <div className="empty-state">
                  <p>No current compared run is available for artifact inspection.</p>
                </div>
              )}
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

            {reviewTask === "findings" && reviewTab === "overview" ? (
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
                    <strong>{draft.artifacts.latest_verification?.new_findings_count ?? 0}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Persisting</span>
                    <strong>{draft.artifacts.latest_verification?.persisting_findings_count ?? 0}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Resolved</span>
                    <strong>{draft.artifacts.latest_verification?.resolved_findings_count ?? 0}</strong>
                  </div>
                </div>
                <ReviewTable
                  emptyCopy="Run a suite and refresh analysis to populate the summary."
                  headings={["Attack", "Kind", "Issue", "Severity", "Confidence", "URL"]}
                  rows={(draft.artifacts.latest_summary?.top_findings ?? []).map((finding) => [
                    findingAction(finding.name, finding),
                    finding.kind,
                    finding.issue ?? "—",
                    finding.severity,
                    finding.confidence,
                    finding.url,
                  ])}
                />
                <ReviewTable
                  emptyCopy="No auth summary recorded for this run."
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
              </div>
            ) : null}

            {reviewTask === "findings" && reviewTab === "new" ? (
              <ReviewTable
                emptyCopy="No new findings match the current filter."
                headings={["Attack", "Kind", "Issue", "Severity", "Confidence", "Status", "Path"]}
                rows={newFindings.map((finding) => [
                  findingAction(finding.name, finding),
                  finding.kind,
                  finding.issue ?? "—",
                  finding.severity,
                  finding.confidence,
                  finding.status_code ?? "—",
                  finding.path ?? "—",
                ])}
              />
            ) : null}

            {reviewTask === "findings" && reviewTab === "persisting" ? (
              <ReviewTable
                emptyCopy="No persisting findings match the current filter."
                headings={["Attack", "Kind", "Issue", "Severity", "Confidence", "Status", "Path"]}
                rows={persistingFindings.map((finding) => [
                  findingAction(finding.name, finding),
                  finding.kind,
                  finding.issue ?? "—",
                  finding.severity,
                  finding.confidence,
                  finding.status_code ?? "—",
                  finding.path ?? "—",
                ])}
              />
            ) : null}

            {reviewTask === "findings" && reviewTab === "resolved" ? (
              <div className="stack">
                <p className="field-hint">
                  Resolved findings are baseline-only in this milestone, so current-run artifact evidence is not available.
                </p>
                <ReviewTable
                  emptyCopy="No resolved findings match the current filter."
                  headings={["Attack", "Kind", "Issue", "Severity", "Confidence", "Status", "Path"]}
                  rows={resolvedFindings.map((finding) => [
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

            {reviewTask === "findings" && reviewTab === "deltas" ? (
              <ReviewTable
                emptyCopy="No persisting deltas are available for the current comparison."
                headings={["Attack", "Issue", "Change summary", "Method", "Path"]}
                rows={deltaFindings.map((finding) => [
                  findingAction(finding.name, finding),
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

            {reviewTask === "runs" ? (
              <div className="stack">
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
                  headings={["Job", "Status", "Completed", "Findings", "Artifacts", "Actions"]}
                  rows={runHistoryJobs.map((job) => [
                    <div key={job.id}>
                      <strong>{shortJobId(job.id)}</strong>
                      <div className="field-hint">
                        {job.id === currentReviewedJob?.id ? "Current review run" : "Saved run"}
                        {job.id === draft.review_draft.baseline_job_id ? " • Baseline" : ""}
                      </div>
                    </div>,
                    <span className={`status-chip ${statusTone(job.status)}`}>{job.status}</span>,
                    formatJobMoment(job.completed_at ?? job.started_at ?? job.created_at),
                    job.result_summary?.active_flagged_count ?? "—",
                    job.artifact_names.length,
                    isPruneableJobStatus(job.status) ? (
                      <button
                        aria-label={`Delete run ${shortJobId(job.id)}`}
                        className="ghost-button danger-button"
                        disabled={Boolean(busyAction)}
                        onClick={() => void handleDeleteJob(job)}
                        type="button"
                      >
                        {busyAction === `delete-job:${job.id}` ? "Deleting…" : "Delete"}
                      </button>
                    ) : (
                      "—"
                    ),
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

            {reviewTask === "policy" ? (
              <div className="stack review-task-panel">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">Suppressions</p>
                    <h3>Keep accepted findings out of active review noise.</h3>
                  </div>
                </div>
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

            {reviewTask === "policy" ? (
              <div className="stack review-task-panel">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">Promotion</p>
                    <h3>Promote qualifying findings into a regression suite.</h3>
                  </div>
                </div>
                <div className="summary-card-grid">
                  <div className="summary-card">
                    <span>Promoted attacks</span>
                    <strong>{draft.artifacts.latest_promoted_suite?.attacks.length ?? 0}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Current run</span>
                    <strong>{currentReviewedJob?.id ?? "—"}</strong>
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
          ) : null}
        </section>

        <aside className="workbench-sidebar">
          <section className="sidebar-panel">
            <p className="eyebrow">Project state</p>
            <h3>Compare context</h3>
            <ul className="compact-list">
              <li>
                <strong>Current run</strong>
                <span>{currentReviewedJob ? currentReviewedJob.id.slice(0, 8) : "—"}</span>
              </li>
              <li>
                <strong>Pinned baseline</strong>
                <span>
                  {draft.review_draft.baseline_mode === "external"
                    ? "External JSON"
                    : baselineReviewedJob
                      ? baselineReviewedJob.id.slice(0, 8)
                      : "—"}
                </span>
              </li>
              <li>
                <strong>Last compared</strong>
                <span>{formatJobMoment(draft.artifacts.latest_summary?.executed_at)}</span>
              </li>
            </ul>
          </section>
          <section className="sidebar-panel">
            <p className="eyebrow">Project state</p>
            <h3>Run history</h3>
            <ul className="job-feed">
              {currentJobs.length ? (
                currentJobs.map((job: JobStatusResponse) => (
                  <li className="job-feed-item" key={job.id}>
                    <div className="job-feed-top">
                      <code>{job.id.slice(0, 8)}</code>
                      <div className="job-feed-badges">
                        {currentReviewedJob?.id === job.id ? (
                          <span className="status-chip status-running">current</span>
                        ) : null}
                        {draft.review_draft.baseline_mode === "job" &&
                        draft.review_draft.baseline_job_id === job.id ? (
                          <span className="status-chip status-pending">baseline</span>
                        ) : null}
                        <span className={`status-chip ${statusTone(job.status)}`}>{job.status}</span>
                      </div>
                    </div>
                    <p>{job.base_url}</p>
                    <small>
                      {summarizeJob(job)}
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
