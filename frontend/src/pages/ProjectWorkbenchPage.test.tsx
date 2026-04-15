import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import ProjectWorkbenchPage from "./ProjectWorkbenchPage";
import type { JobStatusResponse } from "../types";

const projectPayload = {
  id: "project-1",
  name: "Workbench demo",
  source_mode: "openapi",
  active_step: "review",
  created_at: "2026-04-13T20:00:00Z",
  updated_at: "2026-04-13T20:05:00Z",
  graphql_endpoint: "/graphql",
  source: {
    name: "demo.yaml",
    content: "openapi: 3.0.3",
  },
  discover_inputs: [],
  inspect_draft: {
    tag: [],
    exclude_tag: [],
    path: [],
    exclude_path: [],
  },
  generate_draft: {
    operation: [],
    exclude_operation: [],
    method: [],
    exclude_method: [],
    kind: [],
    exclude_kind: [],
    tag: [],
    exclude_tag: [],
    path: [],
    exclude_path: [],
    pack_names: [],
    auto_workflows: false,
    workflow_pack_names: [],
  },
  run_draft: {
    base_url: "",
    headers: {},
    query: {},
    timeout: 10,
    store_artifacts: true,
    auth_plugin_names: [],
    auth_config_yaml: null,
    auth_profile_names: [],
    profile_file_yaml: null,
    profile_names: [],
    operation: [],
    exclude_operation: [],
    method: [],
    exclude_method: [],
    kind: [],
    exclude_kind: [],
    tag: [],
    exclude_tag: [],
    path: [],
    exclude_path: [],
  },
  review_draft: {
    baseline_job_id: null,
    baseline: null,
    suppressions_yaml: null,
    min_severity: "high",
    min_confidence: "medium",
  },
  artifacts: {
    latest_summary: {
      source: "unit",
      base_url: "https://example.com",
      executed_at: "2026-04-13T20:06:00Z",
      baseline_used: false,
      baseline_executed_at: null,
      total_results: 2,
      profile_count: 0,
      profile_names: [],
      active_flagged_count: 2,
      suppressed_flagged_count: 0,
      new_findings_count: 2,
      resolved_findings_count: 0,
      persisting_findings_count: 0,
      persisting_deltas_count: 0,
      auth_failures: 0,
      refresh_attempts: 0,
      response_schema_mismatches: 0,
      graphql_shape_mismatches: 0,
      protocol_counts: { rest: 2 },
      issue_counts: { server_error: 1, response_schema_mismatch: 1 },
      finding_severity_counts: { high: 1, medium: 1 },
      finding_confidence_counts: { high: 2 },
      auth_summary: [],
      top_findings: [],
    },
    latest_verification: {
      passed: false,
      baseline_used: false,
      min_severity: "high",
      min_confidence: "medium",
      current_findings_count: 2,
      new_findings_count: 2,
      resolved_findings_count: 0,
      persisting_findings_count: 0,
      suppressed_current_findings_count: 0,
      current_findings: [
        {
          change: "current",
          attack_id: "atk-login",
          name: "Login failure",
          protocol: "rest",
          kind: "missing_auth",
          method: "POST",
          path: "/login",
          tags: ["auth"],
          issue: "server_error",
          severity: "high",
          confidence: "high",
          status_code: 500,
          url: "https://example.com/login",
          delta_changes: [],
        },
        {
          change: "current",
          attack_id: "atk-order",
          name: "Order mismatch",
          protocol: "rest",
          kind: "wrong_type_param",
          method: "GET",
          path: "/orders",
          tags: ["orders"],
          issue: "response_schema_mismatch",
          severity: "medium",
          confidence: "high",
          status_code: 200,
          url: "https://example.com/orders",
          delta_changes: [],
        },
      ],
      failing_findings: [],
      new_findings: [],
      resolved_findings: [],
      persisting_findings: [],
    },
    latest_results: {
      source: "unit",
      base_url: "https://example.com",
      executed_at: "2026-04-13T20:06:00Z",
      profiles: [],
      auth_events: [],
      results: [],
    },
    latest_markdown_report: "# report",
    latest_html_report: "<!doctype html>",
    last_run_job_id: "job-1",
  },
};

function makeRunJob(overrides: Partial<JobStatusResponse>) {
  return {
    id: "job-1",
    kind: "run",
    status: "completed",
    created_at: "2026-04-13T20:06:00Z",
    started_at: "2026-04-13T20:06:01Z",
    completed_at: "2026-04-13T20:06:04Z",
    base_url: "https://example.com",
    attack_count: 2,
    project_id: "project-1",
    error: null,
    result_available: true,
    artifact_names: [],
    result_summary: projectPayload.artifacts.latest_summary,
    ...overrides,
  };
}

function makeArtifactPayload(overrides?: Record<string, unknown>) {
  return {
    attack: {
      id: "atk-current",
      name: "Artifact attack",
      kind: "wrong_type_param",
      operation_id: "listOrders",
      path: "/orders",
    },
    request: {
      method: "GET",
      url: "https://example.com/orders",
      headers: {
        Authorization: "Bearer dev-token",
      },
      query: {
        limit: 10,
      },
      body: {
        present: false,
        kind: null,
        content_type: null,
        excerpt: null,
      },
    },
    response: {
      status_code: 422,
      error: null,
      duration_ms: 12.5,
      body_excerpt: "invalid input",
    },
    ...overrides,
  };
}

function renderWorkbench() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/projects/project-1"]}>
        <Routes>
          <Route path="/projects/:projectId" element={<ProjectWorkbenchPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ProjectWorkbenchPage", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/projects/project-1")) {
          return Response.json(projectPayload);
        }
        if (url.endsWith("/v1/projects/project-1/jobs")) {
          return Response.json({ project_id: "project-1", jobs: [] });
        }
        throw new Error(`Unhandled fetch for ${url}`);
      }),
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("renders the fixed step rail and disables runs without a generated suite", async () => {
    renderWorkbench();

    expect(await screen.findByText("Workbench demo")).toBeInTheDocument();
    const stepRail = screen.getByRole("navigation", { name: "Workbench steps" });
    for (const stepName of ["source", "inspect", "generate", "run", "review"]) {
      expect(within(stepRail).getByRole("button", { name: new RegExp(stepName, "i") })).toBeInTheDocument();
    }
    expect(screen.getByRole("button", { name: "Run suite" })).toBeDisabled();
  });

  it("filters findings inside the native review workbench", async () => {
    renderWorkbench();

    await screen.findByText("Workbench demo");
    fireEvent.click(screen.getByRole("tab", { name: "Findings" }));

    const table = screen
      .getAllByRole("table")
      .find((candidate) => within(candidate).queryByText("Login failure"));
    if (!table) {
      throw new Error("Expected the findings table to render.");
    }
    expect(within(table).getByText("Login failure")).toBeInTheDocument();
    expect(within(table).getByText("Order mismatch")).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText("search by attack, kind, issue, path"), {
      target: { value: "login" },
    });

    expect(within(table).getByText("Login failure")).toBeInTheDocument();
    expect(within(table).queryByText("Order mismatch")).not.toBeInTheDocument();
  });

  it("duplicates the active project and opens the copied workbench", async () => {
    const duplicatedProject = {
      ...structuredClone(projectPayload),
      id: "project-2",
      name: "Workbench demo copy",
      created_at: "2026-04-13T20:06:00Z",
      updated_at: "2026-04-13T20:06:00Z",
      review_draft: {
        ...structuredClone(projectPayload.review_draft),
        baseline_job_id: null,
      },
      artifacts: {
        ...structuredClone(projectPayload.artifacts),
        last_run_job_id: null,
      },
    };

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (url.endsWith("/v1/projects/project-1") && method === "GET") {
        return Response.json(projectPayload);
      }
      if (url.endsWith("/v1/projects/project-1/jobs") && method === "GET") {
        return Response.json({ project_id: "project-1", jobs: [] });
      }
      if (url.endsWith("/v1/projects/project-1/duplicate") && method === "POST") {
        return Response.json(duplicatedProject);
      }
      if (url.endsWith("/v1/projects/project-2") && method === "GET") {
        return Response.json(duplicatedProject);
      }
      if (url.endsWith("/v1/projects/project-2/jobs") && method === "GET") {
        return Response.json({ project_id: "project-2", jobs: [] });
      }
      throw new Error(`Unhandled fetch for ${method} ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    renderWorkbench();

    await screen.findByText("Workbench demo");
    fireEvent.click(screen.getByRole("button", { name: "Duplicate project" }));

    expect(await screen.findByText("Workbench demo copy")).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.some(
        ([url, init]) =>
          String(url).endsWith("/v1/projects/project-1/duplicate") &&
          ((init as RequestInit | undefined)?.method ?? "GET") === "POST",
      ),
    ).toBe(true);
  });

  it("defaults artifact browsing to the current run and renders a structured preview", async () => {
    const currentJob = makeRunJob({
      id: "job-current",
      artifact_names: ["atk-current.json", "profiles/atk-admin.json"],
    });
    const baselineJob = makeRunJob({
      id: "job-old",
      created_at: "2026-04-13T19:30:00Z",
      started_at: "2026-04-13T19:30:01Z",
      completed_at: "2026-04-13T19:30:04Z",
      artifact_names: ["atk-old.json"],
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        if (url.endsWith("/v1/projects/project-1") && method === "GET") {
          return Response.json({
            ...projectPayload,
            artifacts: {
              ...projectPayload.artifacts,
              last_run_job_id: "job-current",
            },
          });
        }
        if (url.endsWith("/v1/projects/project-1/jobs") && method === "GET") {
          return Response.json({ project_id: "project-1", jobs: [currentJob, baselineJob] });
        }
        if (url.endsWith("/v1/jobs/job-current/artifacts/atk-current.json")) {
          return Response.json(makeArtifactPayload());
        }
        if (url.endsWith("/v1/jobs/job-old/artifacts/atk-old.json")) {
          return Response.json(
            makeArtifactPayload({
              attack: {
                id: "atk-old",
                name: "Older artifact",
                kind: "missing_auth",
                operation_id: "getOrder",
                path: "/orders/1",
              },
            }),
          );
        }
        throw new Error(`Unhandled fetch for ${method} ${url}`);
      }),
    );

    renderWorkbench();

    await screen.findByText("Workbench demo");
    fireEvent.click(screen.getByRole("tab", { name: "Artifacts" }));

    const artifactRunSelect = await screen.findByRole("combobox", { name: "Artifact source run" });
    expect(artifactRunSelect).toHaveValue("job-current");
    expect(screen.getByRole("combobox", { name: "Artifact file" })).toHaveValue("atk-current.json");
    const attackSummary = await screen.findByRole("heading", { name: "Attack summary" });
    expect(attackSummary).toBeInTheDocument();
    expect(within(attackSummary.closest("article") ?? document.body).getByText("Artifact attack")).toBeInTheDocument();
    expect(screen.getByText("Request summary")).toBeInTheDocument();
    expect(screen.getByText("Response summary")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open raw" })).toHaveAttribute(
      "href",
      "/v1/jobs/job-current/artifacts/atk-current.json",
    );
    expect(screen.getByRole("link", { name: "Download" })).toHaveAttribute(
      "href",
      "/v1/jobs/job-current/artifacts/atk-current.json",
    );
  });

  it("falls back artifact browsing to the baseline run when the current run has no artifacts", async () => {
    const currentJob = makeRunJob({
      id: "job-current",
      artifact_names: [],
    });
    const baselineJob = makeRunJob({
      id: "job-baseline",
      created_at: "2026-04-13T19:30:00Z",
      started_at: "2026-04-13T19:30:01Z",
      completed_at: "2026-04-13T19:30:04Z",
      artifact_names: ["atk-baseline.json"],
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        if (url.endsWith("/v1/projects/project-1") && method === "GET") {
          return Response.json({
            ...projectPayload,
            review_draft: {
              ...projectPayload.review_draft,
              baseline_job_id: "job-baseline",
            },
            artifacts: {
              ...projectPayload.artifacts,
              last_run_job_id: "job-current",
            },
          });
        }
        if (url.endsWith("/v1/projects/project-1/jobs") && method === "GET") {
          return Response.json({ project_id: "project-1", jobs: [currentJob, baselineJob] });
        }
        if (url.endsWith("/v1/jobs/job-baseline/artifacts/atk-baseline.json")) {
          return Response.json(
            makeArtifactPayload({
              attack: {
                id: "atk-baseline",
                name: "Baseline artifact",
                kind: "missing_auth",
                operation_id: "getOrder",
                path: "/orders/1",
              },
            }),
          );
        }
        throw new Error(`Unhandled fetch for ${method} ${url}`);
      }),
    );

    renderWorkbench();

    await screen.findByText("Workbench demo");
    fireEvent.click(screen.getByRole("tab", { name: "Artifacts" }));

    expect(await screen.findByRole("combobox", { name: "Artifact source run" })).toHaveValue(
      "job-baseline",
    );
    expect(screen.getByRole("combobox", { name: "Artifact file" })).toHaveValue("atk-baseline.json");
    const attackSummary = await screen.findByRole("heading", { name: "Attack summary" });
    expect(within(attackSummary.closest("article") ?? document.body).getByText("Baseline artifact")).toBeInTheDocument();
  });

  it("switches artifact inspection to a historical run from run history", async () => {
    const currentJob = makeRunJob({
      id: "job-current",
      artifact_names: ["atk-current.json"],
    });
    const olderJob = makeRunJob({
      id: "job-old",
      created_at: "2026-04-13T19:30:00Z",
      started_at: "2026-04-13T19:30:01Z",
      completed_at: "2026-04-13T19:30:04Z",
      artifact_names: ["atk-old.json"],
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        if (url.endsWith("/v1/projects/project-1") && method === "GET") {
          return Response.json({
            ...projectPayload,
            artifacts: {
              ...projectPayload.artifacts,
              last_run_job_id: "job-current",
            },
          });
        }
        if (url.endsWith("/v1/projects/project-1/jobs") && method === "GET") {
          return Response.json({ project_id: "project-1", jobs: [currentJob, olderJob] });
        }
        if (url.endsWith("/v1/jobs/job-current/artifacts/atk-current.json")) {
          return Response.json(makeArtifactPayload());
        }
        if (url.endsWith("/v1/jobs/job-old/artifacts/atk-old.json")) {
          return Response.json(
            makeArtifactPayload({
              attack: {
                id: "atk-old",
                name: "Older artifact",
                kind: "missing_auth",
                operation_id: "getOrder",
                path: "/orders/1",
              },
            }),
          );
        }
        throw new Error(`Unhandled fetch for ${method} ${url}`);
      }),
    );

    renderWorkbench();

    await screen.findByText("Workbench demo");
    fireEvent.click(screen.getByRole("tab", { name: "Artifacts" }));
    let attackSummary = await screen.findByRole("heading", { name: "Attack summary" });
    expect(within(attackSummary.closest("article") ?? document.body).getByText("Artifact attack")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Inspect artifacts from run job-old" }));

    await waitFor(() =>
      expect(screen.getByRole("combobox", { name: "Artifact source run" })).toHaveValue("job-old"),
    );
    expect(screen.getByRole("combobox", { name: "Artifact file" })).toHaveValue("atk-old.json");
    attackSummary = await screen.findByRole("heading", { name: "Attack summary" });
    expect(within(attackSummary.closest("article") ?? document.body).getByText("Older artifact")).toBeInTheDocument();
  });

  it("falls back to a raw preview for invalid artifact payloads and shows fetch errors", async () => {
    const artifactJob = makeRunJob({
      id: "job-current",
      artifact_names: ["broken.json", "missing.json"],
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        if (url.endsWith("/v1/projects/project-1") && method === "GET") {
          return Response.json({
            ...projectPayload,
            artifacts: {
              ...projectPayload.artifacts,
              last_run_job_id: "job-current",
            },
          });
        }
        if (url.endsWith("/v1/projects/project-1/jobs") && method === "GET") {
          return Response.json({ project_id: "project-1", jobs: [artifactJob] });
        }
        if (url.endsWith("/v1/jobs/job-current/artifacts/broken.json")) {
          return new Response("not-json-at-all", {
            status: 200,
            headers: { "Content-Type": "text/plain" },
          });
        }
        if (url.endsWith("/v1/jobs/job-current/artifacts/missing.json")) {
          return Response.json({ detail: "Artifact not found." }, { status: 404 });
        }
        throw new Error(`Unhandled fetch for ${method} ${url}`);
      }),
    );

    renderWorkbench();

    await screen.findByText("Workbench demo");
    fireEvent.click(screen.getByRole("tab", { name: "Artifacts" }));

    expect(await screen.findByText("Raw artifact preview")).toBeInTheDocument();
    expect(screen.getByText("not-json-at-all")).toBeInTheDocument();

    fireEvent.change(screen.getByRole("combobox", { name: "Artifact file" }), {
      target: { value: "missing.json" },
    });

    expect(await screen.findByText("Artifact not found.")).toBeInTheDocument();
  });

  it("uses the configured API base for artifact preview and raw links", async () => {
    window.localStorage.setItem("knives-out.api-base-url", "https://api.example.com");
    const artifactJob = makeRunJob({
      id: "job-current",
      artifact_names: ["profiles/atk-current.json"],
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (url === "https://api.example.com/v1/projects/project-1" && method === "GET") {
        return Response.json({
          ...projectPayload,
          artifacts: {
            ...projectPayload.artifacts,
            last_run_job_id: "job-current",
          },
        });
      }
      if (url === "https://api.example.com/v1/projects/project-1/jobs" && method === "GET") {
        return Response.json({ project_id: "project-1", jobs: [artifactJob] });
      }
      if (url === "https://api.example.com/v1/jobs/job-current/artifacts/profiles/atk-current.json") {
        return Response.json(makeArtifactPayload());
      }
      throw new Error(`Unhandled fetch for ${method} ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    renderWorkbench();

    await screen.findByText("Workbench demo");
    fireEvent.click(screen.getByRole("tab", { name: "Artifacts" }));

    const attackSummary = await screen.findByRole("heading", { name: "Attack summary" });
    expect(within(attackSummary.closest("article") ?? document.body).getByText("Artifact attack")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/v1/jobs/job-current/artifacts/profiles/atk-current.json",
    );
    expect(screen.getByRole("link", { name: "Open raw" })).toHaveAttribute(
      "href",
      "https://api.example.com/v1/jobs/job-current/artifacts/profiles/atk-current.json",
    );
    expect(screen.getByRole("link", { name: "Download" })).toHaveAttribute(
      "href",
      "https://api.example.com/v1/jobs/job-current/artifacts/profiles/atk-current.json",
    );
  });

  it("loads and clears a saved run baseline from the review workspace", async () => {
    let projectState = structuredClone(projectPayload);
    projectState.artifacts.last_run_job_id = "job-current";

    const baselineResults = {
      source: "unit",
      base_url: "https://example.com",
      executed_at: "2026-04-13T19:30:00Z",
      profiles: [],
      auth_events: [],
      results: [],
    };

    const comparisonVerification = {
      ...projectState.artifacts.latest_verification,
      baseline_used: true,
      new_findings_count: 1,
      resolved_findings_count: 1,
      persisting_findings_count: 1,
      current_findings: [
        projectState.artifacts.latest_verification.current_findings[0],
        {
          ...projectState.artifacts.latest_verification.current_findings[1],
          change: "persisting",
          delta_changes: [{ field: "status", baseline: "500", current: "200" }],
        },
      ],
      new_findings: [projectState.artifacts.latest_verification.current_findings[0]],
      resolved_findings: [
        {
          change: "resolved",
          attack_id: "atk-retired",
          name: "Retired finding",
          protocol: "rest",
          kind: "missing_auth",
          method: "GET",
          path: "/legacy",
          tags: ["legacy"],
          issue: "server_error",
          severity: "high",
          confidence: "medium",
          status_code: 500,
          url: "https://example.com/legacy",
          delta_changes: [],
        },
      ],
      persisting_findings: [
        {
          ...projectState.artifacts.latest_verification.current_findings[1],
          change: "persisting",
          delta_changes: [{ field: "status", baseline: "500", current: "200" }],
        },
      ],
    };

    const comparisonSummary = {
      ...projectState.artifacts.latest_summary,
      baseline_used: true,
      baseline_executed_at: baselineResults.executed_at,
      new_findings_count: 1,
      resolved_findings_count: 1,
      persisting_findings_count: 1,
      persisting_deltas_count: 1,
    };

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        if (url.endsWith("/v1/projects/project-1") && method === "GET") {
          return Response.json(projectState);
        }
        if (url.endsWith("/v1/projects/project-1") && method === "PATCH") {
          const patch = JSON.parse(String(init?.body ?? "{}"));
          projectState = {
            ...projectState,
            ...patch,
            review_draft: patch.review_draft ?? projectState.review_draft,
            artifacts: patch.artifacts ?? projectState.artifacts,
          };
          return Response.json(projectState);
        }
        if (url.endsWith("/v1/projects/project-1/jobs")) {
          return Response.json({
            project_id: "project-1",
            jobs: [
              {
                id: "job-current",
                kind: "run",
                status: "completed",
                created_at: "2026-04-13T20:06:00Z",
                started_at: "2026-04-13T20:06:01Z",
                completed_at: "2026-04-13T20:06:04Z",
                base_url: "https://example.com",
                attack_count: 2,
                project_id: "project-1",
                error: null,
                result_available: true,
                artifact_names: ["atk-current.json"],
                result_summary: projectState.artifacts.latest_summary,
              },
              {
                id: "job-baseline",
                kind: "run",
                status: "completed",
                created_at: "2026-04-13T19:30:00Z",
                started_at: "2026-04-13T19:30:01Z",
                completed_at: "2026-04-13T19:30:04Z",
                base_url: "https://example.com",
                attack_count: 2,
                project_id: "project-1",
                error: null,
                result_available: true,
                artifact_names: ["atk-baseline.json"],
                result_summary: {
                  ...projectState.artifacts.latest_summary,
                  executed_at: baselineResults.executed_at,
                  active_flagged_count: 1,
                },
              },
            ],
          });
        }
        if (url.endsWith("/v1/jobs/job-baseline/result")) {
          return Response.json(baselineResults);
        }
        if (url.endsWith("/v1/summary") && method === "POST") {
          const body = JSON.parse(String(init?.body ?? "{}"));
          return Response.json(body.baseline ? comparisonSummary : projectPayload.artifacts.latest_summary);
        }
        if (url.endsWith("/v1/verify") && method === "POST") {
          const body = JSON.parse(String(init?.body ?? "{}"));
          return Response.json(
            body.baseline ? comparisonVerification : projectPayload.artifacts.latest_verification,
          );
        }
        if (url.endsWith("/v1/report") && method === "POST") {
          const body = JSON.parse(String(init?.body ?? "{}"));
          return Response.json({
            format: body.format,
            content: body.baseline
              ? body.format === "markdown"
                ? "# compare"
                : "<!doctype html><p>compare</p>"
              : body.format === "markdown"
                ? "# report"
                : "<!doctype html>",
          });
        }
        throw new Error(`Unhandled fetch for ${method} ${url}`);
      }),
    );

    renderWorkbench();

    await screen.findByText("Workbench demo");
    await screen.findByRole("option", { name: /job-base/i });
    const baselineSelect = screen
      .getAllByRole("combobox", { name: "Baseline run" })
      .at(-1);
    if (!baselineSelect) {
      throw new Error("Expected the baseline selector to render.");
    }
    fireEvent.change(baselineSelect, {
      target: { value: "job-baseline" },
    });

    expect(await screen.findByText("Saved run loaded")).toBeInTheDocument();
    expect(baselineSelect).toHaveValue("job-baseline");
    expect(screen.getByText(/using the selected baseline/i)).toBeInTheDocument();

    const reviewPanels = screen.getAllByRole("tablist", { name: "Review panels" }).at(-1);
    if (!reviewPanels) {
      throw new Error("Expected the review tab list to render.");
    }
    fireEvent.click(within(reviewPanels).getByRole("tab", { name: /Findings/ }));

    await screen.findAllByRole("tablist", { name: "Finding scopes" });
    const findingScopes = screen.getAllByRole("tablist", { name: "Finding scopes" }).at(-1);
    if (!findingScopes) {
      throw new Error("Expected the finding scope tab list to render.");
    }
    fireEvent.click(within(findingScopes).getByRole("tab", { name: /Resolved/ }));

    const findingsTable = screen
      .getAllByRole("table")
      .find((candidate) => within(candidate).queryByText("Retired finding"));
    if (!findingsTable) {
      throw new Error("Expected the resolved findings table to render.");
    }
    expect(within(findingsTable).getByText("Retired finding")).toBeInTheDocument();

    const clearBaselineButton = screen.getAllByRole("button", { name: "Clear baseline" }).at(-1);
    if (!clearBaselineButton) {
      throw new Error("Expected the clear baseline action to render.");
    }
    fireEvent.click(clearBaselineButton);

    const clearedMessages = await screen.findAllByText(/without a comparison baseline/i);
    expect(clearedMessages.at(-1)).toBeInTheDocument();
    expect(baselineSelect).toHaveValue("");

    await new Promise((resolve) => setTimeout(resolve, 700));
  });

  it("uses project-scoped retention actions from the artifacts panel", async () => {
    let projectState: any = structuredClone(projectPayload);
    projectState.artifacts.last_run_job_id = "job-current";
    projectState.review_draft = {
      ...projectState.review_draft,
      baseline_job_id: "job-old",
    };

    const currentJob = {
      id: "job-current",
      kind: "run",
      status: "completed",
      created_at: "2026-04-13T20:06:00Z",
      started_at: "2026-04-13T20:06:01Z",
      completed_at: "2026-04-13T20:06:04Z",
      base_url: "https://example.com",
      attack_count: 2,
      project_id: "project-1",
      error: null,
      result_available: true,
      artifact_names: ["atk-current.json"],
      result_summary: projectState.artifacts.latest_summary,
    };
    const baselineJob = {
      id: "job-old",
      kind: "run",
      status: "completed",
      created_at: "2026-04-13T19:30:00Z",
      started_at: "2026-04-13T19:30:01Z",
      completed_at: "2026-04-13T19:30:04Z",
      base_url: "https://example.com",
      attack_count: 2,
      project_id: "project-1",
      error: null,
      result_available: true,
      artifact_names: ["atk-old.json"],
      result_summary: {
        ...projectState.artifacts.latest_summary,
        executed_at: "2026-04-13T19:30:04Z",
        active_flagged_count: 1,
      },
    };
    let jobs = [currentJob, baselineJob];

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (url.endsWith("/v1/projects/project-1") && method === "GET") {
        return Response.json(projectState);
      }
      if (url.endsWith("/v1/projects/project-1") && method === "PATCH") {
        const patch = JSON.parse(String(init?.body ?? "{}"));
        projectState = {
          ...projectState,
          ...patch,
          review_draft: patch.review_draft ?? projectState.review_draft,
          artifacts: patch.artifacts ?? projectState.artifacts,
        };
        return Response.json(projectState);
      }
      if (url.endsWith("/v1/projects/project-1/jobs") && method === "GET") {
        return Response.json({ project_id: "project-1", jobs });
      }
      if (url.endsWith("/v1/jobs/job-current/artifacts/atk-current.json")) {
        return Response.json(makeArtifactPayload());
      }
      if (url.endsWith("/v1/jobs/job-old/artifacts/atk-old.json")) {
        return Response.json(
          makeArtifactPayload({
            attack: {
              id: "atk-old",
              name: "Older artifact",
              kind: "missing_auth",
              operation_id: "getOrder",
              path: "/orders/1",
            },
          }),
        );
      }
      if (url.endsWith("/v1/projects/project-1/jobs/job-old") && method === "DELETE") {
        jobs = jobs.filter((job) => job.id !== "job-old");
        return Response.json({
          deleted: {
            id: "job-old",
            status: "completed",
            created_at: baselineJob.created_at,
            completed_at: baselineJob.completed_at,
            base_url: baselineJob.base_url,
            attack_count: baselineJob.attack_count,
            error: null,
            result_available: true,
            artifact_names: baselineJob.artifact_names,
          },
        });
      }
      if (url.endsWith("/v1/projects/project-1/jobs/prune") && method === "POST") {
        const body = JSON.parse(String(init?.body ?? "{}"));
        if (body.dry_run) {
          return Response.json({
            dry_run: true,
            matched_count: 1,
            deleted_count: 0,
            jobs: [
              {
                id: currentJob.id,
                status: currentJob.status,
                created_at: currentJob.created_at,
                completed_at: currentJob.completed_at,
                base_url: currentJob.base_url,
                attack_count: currentJob.attack_count,
                error: null,
                result_available: true,
                artifact_names: currentJob.artifact_names,
              },
            ],
          });
        }
        jobs = [];
        return Response.json({
          dry_run: false,
          matched_count: 1,
          deleted_count: 1,
          jobs: [
            {
              id: currentJob.id,
              status: currentJob.status,
              created_at: currentJob.created_at,
              completed_at: currentJob.completed_at,
              base_url: currentJob.base_url,
              attack_count: currentJob.attack_count,
              error: null,
              result_available: true,
              artifact_names: currentJob.artifact_names,
            },
          ],
        });
      }
      if (url.endsWith("/v1/summary") && method === "POST") {
        return Response.json(projectPayload.artifacts.latest_summary);
      }
      if (url.endsWith("/v1/verify") && method === "POST") {
        return Response.json(projectPayload.artifacts.latest_verification);
      }
      if (url.endsWith("/v1/report") && method === "POST") {
        const body = JSON.parse(String(init?.body ?? "{}"));
        return Response.json({
          format: body.format,
          content: body.format === "markdown" ? "# report" : "<!doctype html>",
        });
      }
      throw new Error(`Unhandled fetch for ${method} ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);

    renderWorkbench();

    await screen.findAllByText("Workbench demo");
    const reviewPanels = screen.getAllByRole("tablist", { name: "Review panels" }).at(-1);
    if (!reviewPanels) {
      throw new Error("Expected the review tab list to render.");
    }
    fireEvent.click(within(reviewPanels).getByRole("tab", { name: /Artifacts/ }));

    fireEvent.click(screen.getByRole("button", { name: "Delete run job-old" }));

    const baselineSelect = screen.getAllByRole("combobox", { name: "Baseline run" }).at(-1);
    if (!baselineSelect) {
      throw new Error("Expected the baseline selector to render.");
    }
    await waitFor(() => expect(baselineSelect).toHaveValue(""));

    fireEvent.click(screen.getByRole("button", { name: "Preview matches" }));

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Delete matched runs" })).toBeEnabled(),
    );
    expect(
      fetchMock.mock.calls.some(
        ([url, init]) =>
          String(url).endsWith("/v1/projects/project-1/jobs/prune") &&
          JSON.parse(String((init as RequestInit | undefined)?.body ?? "{}")).dry_run === true,
      ),
    ).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "Delete matched runs" }));

    expect(await screen.findByText("No jobs for this project yet.")).toBeInTheDocument();
    expect(screen.getByText("No artifacts stored for this project yet.")).toBeInTheDocument();
    expect(confirmSpy).toHaveBeenCalledTimes(2);
  });
});
