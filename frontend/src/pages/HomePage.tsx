import { startTransition, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { createProject, deleteProject, listProjects } from "../api";

export default function HomePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [newProjectName, setNewProjectName] = useState("Security workbench");

  const projectListQuery = useQuery({
    queryKey: ["projects"],
    queryFn: listProjects,
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
            if (!newProjectName.trim()) {
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
          <button className="primary-button" type="submit" disabled={createProjectMutation.isPending}>
            {createProjectMutation.isPending ? "Creating…" : "Open workbench"}
          </button>
        </form>
      </section>

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

        {!projectListQuery.isLoading && !projectListQuery.data?.projects.length ? (
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
                  onClick={() => deleteProjectMutation.mutate(project.id)}
                  disabled={deleteProjectMutation.isPending}
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
