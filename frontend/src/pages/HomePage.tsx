import { startTransition, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import {
  createProject,
  deleteProject,
  duplicateProject,
  getHealthStatus,
  listProjects,
} from "../api";
import { getApiBaseUrl, needsConfiguredApiBase, persistApiBaseUrl } from "../apiConfig";
import ApiConnectionPanel from "../components/ApiConnectionPanel";

export default function HomePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [newProjectName, setNewProjectName] = useState("Security workbench");
  const [apiBaseUrl, setApiBaseUrl] = useState(() => getApiBaseUrl());
  const requiresApiBase = needsConfiguredApiBase(apiBaseUrl);

  const projectListQuery = useQuery({
    queryKey: ["projects", apiBaseUrl],
    queryFn: listProjects,
    enabled: !requiresApiBase,
    retry: false,
  });

  const healthQuery = useQuery({
    queryKey: ["health", apiBaseUrl],
    queryFn: getHealthStatus,
    enabled: !requiresApiBase,
    retry: false,
  });

  const createProjectMutation = useMutation({
    mutationFn: createProject,
    onSuccess: async (project) => {
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      startTransition(() => {
        navigate(`/projects/${project.id}`);
      });
    },
  });

  const deleteProjectMutation = useMutation({
    mutationFn: deleteProject,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
    },
  });

  const duplicateProjectMutation = useMutation({
    mutationFn: duplicateProject,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
    },
  });

  function applyApiBase(nextValue: string) {
    const normalized = persistApiBaseUrl(nextValue);
    setApiBaseUrl(normalized);
    void queryClient.invalidateQueries();
  }

  const homeError =
    projectListQuery.error instanceof Error
      ? projectListQuery.error.message
      : createProjectMutation.error instanceof Error
        ? createProjectMutation.error.message
        : deleteProjectMutation.error instanceof Error
          ? deleteProjectMutation.error.message
          : duplicateProjectMutation.error instanceof Error
            ? duplicateProjectMutation.error.message
          : null;
  const apiStatusTone = requiresApiBase
    ? "idle"
    : healthQuery.isLoading
      ? "pending"
      : healthQuery.isSuccess
        ? "completed"
        : "failed";
  const apiStatusLabel = requiresApiBase
    ? "configure API"
    : healthQuery.isLoading
      ? "checking"
      : healthQuery.isSuccess
        ? "connected"
        : "unreachable";
  const apiDescription = requiresApiBase
    ? "This GitHub Pages deployment only hosts the frontend shell. Set the API base URL to a reachable knives-out server to load projects and run workflows."
    : healthQuery.isSuccess
      ? "The workbench can reach the configured API. Projects and runs will use this endpoint."
      : apiBaseUrl
        ? "The configured API endpoint is not responding yet. Make sure the deployed backend is reachable and allows cross-origin requests."
        : "This static frontend needs a reachable knives-out API when it is not served by `knives-out serve` on the same origin.";

  return (
    <main className="shell">
      <section className="hero-panel">
        <div className="hero-copy">
          <p className="eyebrow">Guided IDE</p>
          <h1>Adversarial API testing, with a sharper workbench.</h1>
          <p className="hero-body">
            Inspect specs, generate attacks, run suites, and triage findings without leaving the
            flow. Everything stays local-first and project-scoped.
          </p>
        </div>
        <form
          className="hero-create"
          onSubmit={(event) => {
            event.preventDefault();
            if (requiresApiBase || !newProjectName.trim()) {
              return;
            }
            createProjectMutation.mutate(newProjectName.trim());
          }}
        >
          <label className="field">
            <span className="field-label">New project</span>
            <input
              className="text-input text-input-large"
              value={newProjectName}
              onChange={(event) => setNewProjectName(event.target.value)}
              placeholder="Name the workbench"
            />
          </label>
          <button
            className="primary-button"
            type="submit"
            disabled={createProjectMutation.isPending || requiresApiBase}
          >
            {createProjectMutation.isPending
              ? "Creating…"
              : requiresApiBase
                ? "Connect API first"
                : "Open workbench"}
          </button>
        </form>
      </section>

      {homeError ? <div className="error-banner">{homeError}</div> : null}

      <ApiConnectionPanel
        apiBaseUrl={apiBaseUrl}
        description={apiDescription}
        onApply={applyApiBase}
        statusLabel={apiStatusLabel}
        statusTone={apiStatusTone}
        title="Choose where the UI talks to the API"
      />

      <section className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Recent projects</p>
            <h2>Pick up where you left off</h2>
          </div>
          <div className="meta-pill">
            {projectListQuery.data?.projects.length ?? 0}
            <span>saved</span>
          </div>
        </div>

        {projectListQuery.isLoading ? <p className="empty-copy">Loading projects…</p> : null}
        {!projectListQuery.isLoading && requiresApiBase ? (
          <div className="empty-state">
            <p>Add a reachable API endpoint above to load saved projects.</p>
            <p>The Pages site only serves the UI. Project drafts and runs live on the API backend.</p>
          </div>
        ) : null}
        {!projectListQuery.isLoading && !requiresApiBase && projectListQuery.isError ? (
          <div className="empty-state">
            <p>Projects could not be loaded from the configured API.</p>
            <p>Check the API endpoint panel above, then retry after the backend is reachable.</p>
          </div>
        ) : null}

        {!projectListQuery.isLoading &&
        !requiresApiBase &&
        !projectListQuery.isError &&
        !projectListQuery.data?.projects.length ? (
          <div className="empty-state">
            <p>No saved projects yet.</p>
            <p>Start with an OpenAPI or GraphQL source and the workbench will hold the drafts.</p>
          </div>
        ) : null}

        <div className="project-grid">
          {projectListQuery.data?.projects.map((project) => (
            <article className="project-card" key={project.id}>
              <div className="project-card-top">
                <p className="project-mode">{project.source_mode.replace('_', ' ')}</p>
                <div className={`status-chip status-${project.last_run_status ?? "idle"}`}>
                  {project.last_run_status ?? "draft"}
                </div>
              </div>
              <Link className="project-card-link" to={`/projects/${project.id}`}>
                <h3>{project.name}</h3>
                <p>{project.source_name ?? "No source loaded yet"}</p>
              </Link>
              <dl className="project-metrics">
                <div>
                  <dt>Step</dt>
                  <dd>{project.active_step}</dd>
                </div>
                <div>
                  <dt>Jobs</dt>
                  <dd>{project.job_count}</dd>
                </div>
                <div>
                  <dt>Findings</dt>
                  <dd>{project.active_flagged_count ?? "—"}</dd>
                </div>
              </dl>
              <div className="project-card-actions">
                <Link className="secondary-button" to={`/projects/${project.id}`}>
                  Open
                </Link>
                <button
                  className="ghost-button"
                  type="button"
                  onClick={() => duplicateProjectMutation.mutate(project.id)}
                  disabled={duplicateProjectMutation.isPending || deleteProjectMutation.isPending}
                >
                  {duplicateProjectMutation.isPending ? "Duplicating…" : "Duplicate"}
                </button>
                <button
                  className="ghost-button"
                  type="button"
                  onClick={() => deleteProjectMutation.mutate(project.id)}
                  disabled={deleteProjectMutation.isPending || duplicateProjectMutation.isPending}
                >
                  Delete
                </button>
              </div>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
