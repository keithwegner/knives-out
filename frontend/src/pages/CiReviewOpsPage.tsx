import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  buildJobArtifactUrl,
  getEditionStatus,
  getProject,
  listProjectJobs,
  listProjects,
} from "../api";
import { getApiBaseUrl, needsConfiguredApiBase, persistApiBaseUrl } from "../apiConfig";
import ApiConnectionPanel from "../components/ApiConnectionPanel";
import type {
  EditionStatus,
  FindingSummaryResponse,
  JobStatusResponse,
  ProjectRecord,
  ProjectSummaryResponse,
} from "../types";

const REVIEWOPS_CAPABILITY = "ci_reviewops";

type FindingBucket = "new" | "persisting" | "resolved" | "current";

interface ComparisonFinding {
  finding: FindingSummaryResponse;
  bucket: FindingBucket;
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) {
    return "-";
  }
  return new Date(value).toLocaleString();
}

function shortId(value: string | null | undefined): string {
  return value ? value.slice(0, 8) : "-";
}

function jobMoment(job: JobStatusResponse): string {
  return job.completed_at ?? job.started_at ?? job.created_at;
}

function jobSortValue(job: JobStatusResponse): number {
  return new Date(jobMoment(job)).getTime();
}

function hasReviewOpsAccess(edition: EditionStatus | undefined): boolean {
  if (!edition) {
    return false;
  }
  return (
    edition.enabled_capabilities.includes(REVIEWOPS_CAPABILITY) &&
    !edition.locked_capabilities.includes(REVIEWOPS_CAPABILITY)
  );
}

function repositorySubtitle(project: ProjectSummaryResponse): string {
  if (project.source_mode === "review_bundle") {
    return "Imported CI review bundle";
  }
  return project.source_name ?? `${project.source_mode.replace("_", " ")} project`;
}

function currentReviewJob(project: ProjectRecord | undefined, jobs: JobStatusResponse[]): JobStatusResponse | null {
  if (!project) {
    return null;
  }
  const completedJobs = jobs
    .filter((job) => job.status === "completed" && job.result_available)
    .sort((a, b) => jobSortValue(b) - jobSortValue(a));
  return (
    jobs.find((job) => job.id === project.artifacts.last_run_job_id) ??
    completedJobs[0] ??
    null
  );
}

function baselineDescription(project: ProjectRecord | undefined, jobs: JobStatusResponse[]): string {
  if (!project) {
    return "No repository selected";
  }

  if (project.review_draft.baseline_mode === "external") {
    return project.review_draft.baseline
      ? `External baseline from ${formatDateTime(project.review_draft.baseline.executed_at)}`
      : "External baseline mode without imported results";
  }

  if (!project.review_draft.baseline_job_id) {
    return "No default-branch baseline pinned";
  }

  const baselineJob = jobs.find((job) => job.id === project.review_draft.baseline_job_id);
  return baselineJob
    ? `Run ${shortId(baselineJob.id)} from ${formatDateTime(jobMoment(baselineJob))}`
    : `Pinned baseline ${shortId(project.review_draft.baseline_job_id)} is not in this repository history`;
}

function comparisonFindings(project: ProjectRecord | undefined): ComparisonFinding[] {
  const verification = project?.artifacts.latest_verification;
  if (!verification) {
    return [];
  }

  const rows: ComparisonFinding[] = [];
  const seen = new Set<string>();
  const append = (bucket: FindingBucket, findings: FindingSummaryResponse[]) => {
    for (const finding of findings) {
      const key = `${bucket}:${finding.attack_id}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      rows.push({ bucket, finding });
    }
  };

  append("new", verification.new_findings);
  append("persisting", verification.persisting_findings);
  append("resolved", verification.resolved_findings);
  if (!rows.length) {
    append("current", verification.current_findings);
  }
  return rows.slice(0, 8);
}

function artifactForFinding(job: JobStatusResponse | null, attackId: string): string | null {
  if (!job) {
    return null;
  }
  const exact = `${attackId}.json`;
  return (
    job.artifact_names.find((artifactName) => artifactName === exact) ??
    job.artifact_names.find((artifactName) => artifactName.includes(attackId)) ??
    null
  );
}

function safeHttpHref(value: string): string {
  try {
    const url = new URL(value, window.location.origin);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return "#";
    }
    return url.href;
  } catch {
    return "#";
  }
}

function ReviewOpsLockedState({
  apiBaseUrl,
  edition,
  onApplyApiBase,
}: {
  apiBaseUrl: string;
  edition: EditionStatus | undefined;
  onApplyApiBase: (value: string) => void;
}) {
  return (
    <main className="shell">
      <section className="panel stack">
        <div>
          <p className="eyebrow">Pro CI ReviewOps</p>
          <h1>Repository and PR comparison views are locked</h1>
          <p className="hero-body">
            {edition?.message ??
              "The API did not report the CI ReviewOps capability. Free workbench projects still work normally."}
          </p>
        </div>
        <div className="summary-card-grid">
          <div className="summary-card">
            <span>Edition</span>
            <strong>{edition ? edition.plan : "Unknown"}</strong>
          </div>
          <div className="summary-card">
            <span>License</span>
            <strong>{edition?.license_state ?? "unavailable"}</strong>
          </div>
          <div className="summary-card">
            <span>Locked capability</span>
            <strong>{REVIEWOPS_CAPABILITY}</strong>
          </div>
        </div>
        <div className="action-row">
          <Link className="secondary-button" to="/">
            Open free workbench
          </Link>
          <a
            className="primary-button"
            href={edition?.upgrade_url ?? "https://github.com/keithwegner/knives-out/blob/main/docs/pro.md"}
          >
            View Pro options
          </a>
        </div>
      </section>
      <ApiConnectionPanel
        apiBaseUrl={apiBaseUrl}
        description="CI ReviewOps is enabled by the API edition status. Point this UI at a Pro-enabled backend to unlock repository and PR views."
        onApply={onApplyApiBase}
        statusLabel="locked"
        statusTone="idle"
        title="API edition source"
      />
    </main>
  );
}

export default function CiReviewOpsPage() {
  const queryClient = useQueryClient();
  const [apiBaseUrl, setApiBaseUrl] = useState(() => getApiBaseUrl());
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const requiresApiBase = needsConfiguredApiBase(apiBaseUrl);

  const editionQuery = useQuery({
    queryKey: ["edition", apiBaseUrl],
    queryFn: getEditionStatus,
    enabled: !requiresApiBase,
    retry: false,
  });
  const reviewOpsEnabled = hasReviewOpsAccess(editionQuery.data);

  const projectsQuery = useQuery({
    queryKey: ["projects", apiBaseUrl, "reviewops"],
    queryFn: listProjects,
    enabled: reviewOpsEnabled,
    retry: false,
  });

  const repositoryProjects = useMemo(
    () =>
      (projectsQuery.data?.projects ?? [])
        .filter((project) => project.job_count > 0 || project.source_mode === "review_bundle")
        .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime()),
    [projectsQuery.data],
  );

  useEffect(() => {
    if (!repositoryProjects.length) {
      return;
    }
    if (selectedProjectId && repositoryProjects.some((project) => project.id === selectedProjectId)) {
      return;
    }
    setSelectedProjectId(repositoryProjects[0].id);
  }, [repositoryProjects, selectedProjectId]);

  const projectQuery = useQuery({
    queryKey: ["project", selectedProjectId, apiBaseUrl, "reviewops"],
    queryFn: () => getProject(selectedProjectId!),
    enabled: reviewOpsEnabled && Boolean(selectedProjectId),
    retry: false,
  });

  const jobsQuery = useQuery({
    queryKey: ["projectJobs", selectedProjectId, apiBaseUrl, "reviewops"],
    queryFn: () => listProjectJobs(selectedProjectId!),
    enabled: reviewOpsEnabled && Boolean(selectedProjectId),
    retry: false,
  });

  function applyApiBase(nextValue: string) {
    const normalized = persistApiBaseUrl(nextValue);
    setApiBaseUrl(normalized);
    setSelectedProjectId(null);
    void queryClient.invalidateQueries();
  }

  if (requiresApiBase) {
    return (
      <main className="shell">
        <section className="panel stack">
          <div>
            <p className="eyebrow">Pro CI ReviewOps</p>
            <h1>Connect a Pro-enabled API</h1>
            <p className="hero-body">
              The static workbench shell needs a reachable API before it can inspect edition status
              or load repository run history.
            </p>
          </div>
          <ApiConnectionPanel
            apiBaseUrl={apiBaseUrl}
            description="Repository views, branch baselines, and PR comparisons are served by the configured API backend."
            onApply={applyApiBase}
            statusLabel="configure API"
            statusTone="idle"
            title="ReviewOps API endpoint"
          />
          <Link className="ghost-button" to="/">
            Back to projects
          </Link>
        </section>
      </main>
    );
  }

  if (editionQuery.isLoading) {
    return (
      <main className="shell">
        <section className="panel">
          <p className="empty-copy">Checking CI ReviewOps access...</p>
        </section>
      </main>
    );
  }

  if (editionQuery.isError || !reviewOpsEnabled) {
    return (
      <ReviewOpsLockedState
        apiBaseUrl={apiBaseUrl}
        edition={editionQuery.data}
        onApplyApiBase={applyApiBase}
      />
    );
  }

  const edition = editionQuery.data;
  const selectedProject = projectQuery.data;
  const jobs = jobsQuery.data?.jobs ?? [];
  const currentJob = currentReviewJob(selectedProject, jobs);
  const comparisonRows = comparisonFindings(selectedProject);
  const summary = selectedProject?.artifacts.latest_summary;
  const verification = selectedProject?.artifacts.latest_verification;
  const latestRunLabel = currentJob
    ? `Run ${shortId(currentJob.id)} from ${formatDateTime(jobMoment(currentJob))}`
    : "No imported run selected";
  const baselineLabel = baselineDescription(selectedProject, jobs);
  const proError =
    projectsQuery.error instanceof Error
      ? projectsQuery.error.message
      : projectQuery.error instanceof Error
        ? projectQuery.error.message
        : jobsQuery.error instanceof Error
          ? jobsQuery.error.message
          : null;

  return (
    <main className="shell">
      <section className="hero-panel reviewops-hero">
        <div className="hero-copy">
          <p className="eyebrow">Pro CI ReviewOps</p>
          <h1>Repository runs and PR comparisons</h1>
          <p className="hero-body">
            Review imported CI runs, pin branch baselines, and inspect pull request deltas with
            links back to stored evidence.
          </p>
          <div className="edition-badge edition-badge-pro">
            <span>{edition?.plan ?? "Pro"} edition</span>
            <strong>{edition?.license_state ?? "valid"}</strong>
          </div>
        </div>
        <div className="reviewops-snapshot" aria-label="CI ReviewOps snapshot">
          <div>
            <span>Repositories</span>
            <strong>{repositoryProjects.length}</strong>
          </div>
          <div>
            <span>Imported runs</span>
            <strong>
              {repositoryProjects.reduce((total, project) => total + project.job_count, 0)}
            </strong>
          </div>
          <div>
            <span>Active findings</span>
            <strong>
              {repositoryProjects.reduce(
                (total, project) => total + (project.active_flagged_count ?? 0),
                0,
              )}
            </strong>
          </div>
        </div>
      </section>

      {proError ? <div className="error-banner">{proError}</div> : null}

      <section className="reviewops-layout">
        <aside className="sidebar-panel stack" aria-label="Repositories">
          <div>
            <p className="eyebrow">Repository view</p>
            <h2>Imported CI runs</h2>
          </div>
          {projectsQuery.isLoading ? <p className="empty-copy">Loading repositories...</p> : null}
          {!projectsQuery.isLoading && !repositoryProjects.length ? (
            <div className="empty-state">
              <p>No imported CI runs are available yet.</p>
              <p>Publish or import a review bundle to populate the Pro workbench.</p>
            </div>
          ) : null}
          <div className="reviewops-repository-list">
            {repositoryProjects.map((project) => (
              <button
                className={`reviewops-repository-button${
                  project.id === selectedProjectId ? " reviewops-repository-button-active" : ""
                }`}
                key={project.id}
                onClick={() => setSelectedProjectId(project.id)}
                type="button"
              >
                <strong>{project.name}</strong>
                <span>{repositorySubtitle(project)}</span>
                <small>
                  {project.job_count} run{project.job_count === 1 ? "" : "s"} /{" "}
                  {project.active_flagged_count ?? 0} active
                </small>
              </button>
            ))}
          </div>
        </aside>

        <div className="stack">
          <section className="panel stack">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Branch baseline state</p>
                <h2>{selectedProject?.name ?? "Select a repository"}</h2>
              </div>
              {selectedProject ? (
                <Link className="secondary-button" to={`/projects/${selectedProject.id}`}>
                  Open workbench
                </Link>
              ) : null}
            </div>

            {projectQuery.isLoading || jobsQuery.isLoading ? (
              <p className="empty-copy">Loading repository details...</p>
            ) : null}

            {selectedProject ? (
              <>
                <div className="summary-card-grid">
                  <div className="summary-card">
                    <span>Latest imported run</span>
                    <strong>{latestRunLabel}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Default branch baseline</span>
                    <strong>{baselineLabel}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Baseline deltas</span>
                    <strong>{summary?.persisting_deltas_count ?? 0}</strong>
                  </div>
                </div>

                <ReviewOpsRunTable jobs={jobs} />
              </>
            ) : null}
          </section>

          <section className="panel stack">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Pull request comparison</p>
                <h2>New, resolved, and persisting findings</h2>
              </div>
              <div className={`status-chip status-${verification?.passed ? "completed" : "failed"}`}>
                {verification ? (verification.passed ? "policy passed" : "policy failed") : "no policy"}
              </div>
            </div>

            <div className="compare-banner">
              <div className="compare-card">
                <span>New</span>
                <strong>{summary?.new_findings_count ?? 0}</strong>
              </div>
              <div className="compare-card">
                <span>Resolved</span>
                <strong>{summary?.resolved_findings_count ?? 0}</strong>
              </div>
              <div className="compare-card">
                <span>Persisting</span>
                <strong>{summary?.persisting_findings_count ?? 0}</strong>
              </div>
            </div>

            <ReviewOpsFindingsTable
              currentJob={currentJob}
              findings={comparisonRows}
              projectId={selectedProject?.id ?? null}
            />
          </section>
        </div>
      </section>
    </main>
  );
}

function ReviewOpsRunTable({ jobs }: { jobs: JobStatusResponse[] }) {
  const sortedJobs = [...jobs].sort((a, b) => jobSortValue(b) - jobSortValue(a));
  return (
    <div className="table-shell">
      <table className="data-table">
        <thead>
          <tr>
            <th>Run</th>
            <th>Status</th>
            <th>Target</th>
            <th>Findings</th>
            <th>Artifacts</th>
          </tr>
        </thead>
        <tbody>
          {sortedJobs.length ? (
            sortedJobs.map((job) => (
              <tr key={job.id}>
                <td>
                  <strong>{shortId(job.id)}</strong>
                  <br />
                  <small>{formatDateTime(jobMoment(job))}</small>
                </td>
                <td>{job.status}</td>
                <td>{job.base_url || "-"}</td>
                <td>{job.result_summary?.active_flagged_count ?? "-"}</td>
                <td>{job.artifact_names.length}</td>
              </tr>
            ))
          ) : (
            <tr>
              <td className="table-empty" colSpan={5}>
                No imported runs are stored for this repository.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function ReviewOpsFindingsTable({
  currentJob,
  findings,
  projectId,
}: {
  currentJob: JobStatusResponse | null;
  findings: ComparisonFinding[];
  projectId: string | null;
}) {
  return (
    <div className="table-shell">
      <table className="data-table">
        <thead>
          <tr>
            <th>Change</th>
            <th>Finding</th>
            <th>Delta</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {findings.length ? (
            findings.map(({ bucket, finding }) => {
              const artifactName = bucket === "resolved" ? null : artifactForFinding(currentJob, finding.attack_id);
              const evidencePath = projectId
                ? `/projects/${encodeURIComponent(projectId)}?review=evidence&finding=${encodeURIComponent(finding.attack_id)}`
                : null;
              const artifactHref =
                artifactName && currentJob
                  ? safeHttpHref(buildJobArtifactUrl(currentJob.id, artifactName))
                  : null;
              return (
                <tr key={`${bucket}-${finding.attack_id}`}>
                  <td>
                    <span className={`status-chip reviewops-change-${bucket}`}>{bucket}</span>
                  </td>
                  <td>
                    <strong>{finding.name}</strong>
                    <br />
                    <small>
                      {finding.method} {finding.path ?? "-"} / {finding.issue ?? "finding"}
                    </small>
                  </td>
                  <td>
                    {finding.delta_changes.length ? (
                      <ul className="reviewops-delta-list">
                        {finding.delta_changes.map((delta) => (
                          <li key={`${finding.attack_id}-${delta.field}`}>
                            {`${delta.field}: ${delta.baseline} -> ${delta.current}`}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      "-"
                    )}
                  </td>
                  <td>
                    <div className="reviewops-evidence-links">
                      {evidencePath ? (
                        <Link to={evidencePath}>Open evidence</Link>
                      ) : null}
                      {artifactHref ? (
                        <a href={artifactHref} rel="noreferrer" target="_blank">
                          Stored artifact
                        </a>
                      ) : (
                        <span>{bucket === "resolved" ? "Baseline only" : "No stored artifact"}</span>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })
          ) : (
            <tr>
              <td className="table-empty" colSpan={4}>
                No PR comparison findings are available for this repository.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
