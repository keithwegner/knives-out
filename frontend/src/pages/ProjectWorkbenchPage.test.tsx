import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import ProjectWorkbenchPage from "./ProjectWorkbenchPage";
import type { ProjectJobsResponse, ProjectRecord, ProjectReviewResponse } from "../types";

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

const baseProjectPayload: ProjectRecord = {
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
    baseline_mode: "job",
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
      top_findings: [
        {
          attack_id: "atk-login",
          name: "Login failure",
          protocol: "rest",
          kind: "missing_auth",
          issue: "server_error",
          severity: "high",
          confidence: "high",
          status_code: 500,
          url: "https://example.com/login",
          schema_status: "not_applicable",
        },
      ],
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
      new_findings: [
        {
          change: "new",
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
          change: "new",
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
    last_run_job_id: "job-2",
  },
};

const baseJobsPayload: ProjectJobsResponse = {
  project_id: "project-1",
  jobs: [
    {
      id: "job-2",
      kind: "run",
      status: "completed",
      created_at: "2026-04-13T20:05:00Z",
      started_at: "2026-04-13T20:05:05Z",
      completed_at: "2026-04-13T20:06:00Z",
      base_url: "https://example.com",
      attack_count: 2,
      project_id: "project-1",
      error: null,
      result_available: true,
      artifact_names: ["atk-login.json"],
      result_summary: {
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
    },
    {
      id: "job-1",
      kind: "run",
      status: "completed",
      created_at: "2026-04-13T19:00:00Z",
      started_at: "2026-04-13T19:00:05Z",
      completed_at: "2026-04-13T19:01:00Z",
      base_url: "https://example.com",
      attack_count: 2,
      project_id: "project-1",
      error: null,
      result_available: true,
      artifact_names: ["atk-order.json"],
      result_summary: {
        source: "unit",
        base_url: "https://example.com",
        executed_at: "2026-04-13T19:01:00Z",
        baseline_used: false,
        baseline_executed_at: null,
        total_results: 2,
        profile_count: 0,
        profile_names: [],
        active_flagged_count: 1,
        suppressed_flagged_count: 0,
        new_findings_count: 0,
        resolved_findings_count: 0,
        persisting_findings_count: 0,
        persisting_deltas_count: 0,
        auth_failures: 0,
        refresh_attempts: 0,
        response_schema_mismatches: 0,
        graphql_shape_mismatches: 0,
        protocol_counts: { rest: 2 },
        issue_counts: { server_error: 1 },
        finding_severity_counts: { high: 1 },
        finding_confidence_counts: { high: 1 },
        auth_summary: [],
        top_findings: [],
      },
    },
  ],
};

function createReviewResponse(options: {
  baselineJobId: string | null;
  waitingForNewRun: boolean;
  baselineUsed: boolean;
}): ProjectReviewResponse {
  const latestResults = clone(baseProjectPayload.artifacts.latest_results!);
  const latestSummary = clone(baseProjectPayload.artifacts.latest_summary!);
  const latestVerification = clone(baseProjectPayload.artifacts.latest_verification!);

  return {
    project_id: "project-1",
    current_job_id: "job-2",
    baseline_mode: "job",
    baseline_job_id: options.baselineJobId,
    baseline_used: options.baselineUsed,
    waiting_for_new_run: options.waitingForNewRun,
    results: latestResults,
    summary: {
      ...latestSummary,
      baseline_used: options.baselineUsed,
      baseline_executed_at: options.baselineJobId ? "2026-04-13T19:01:00Z" : null,
      new_findings_count: options.baselineUsed ? 1 : 2,
      resolved_findings_count: options.baselineUsed ? 1 : 0,
      persisting_findings_count: options.baselineUsed ? 1 : 0,
      persisting_deltas_count: options.baselineUsed ? 1 : 0,
    },
    verification: {
      ...latestVerification,
      baseline_used: options.baselineUsed,
      new_findings_count: options.baselineUsed ? 1 : 2,
      resolved_findings_count: options.baselineUsed ? 1 : 0,
      persisting_findings_count: options.baselineUsed ? 1 : 0,
      new_findings: options.baselineUsed
        ? [clone(latestVerification.new_findings[0])]
        : clone(latestVerification.new_findings),
      resolved_findings: options.baselineUsed
        ? [
            {
              ...clone(latestVerification.new_findings[1]),
              change: "resolved",
            },
          ]
        : [],
      persisting_findings: options.baselineUsed
        ? [
            {
              ...clone(latestVerification.new_findings[0]),
              change: "persisting",
              delta_changes: [
                { field: "status", baseline: "401", current: "500" },
              ],
            },
          ]
        : [],
    },
    markdown_report: "# report",
    html_report: "<!doctype html>",
  };
}

function createEvidenceResponse(attackId: string) {
  if (attackId === "atk-order") {
    return {
      job_id: "job-2",
      attack_id: "atk-order",
      result: {
        type: "request",
        attack_id: "atk-order",
        operation_id: "listOrders",
        kind: "wrong_type_param",
        name: "Order mismatch",
        protocol: "rest",
        method: "GET",
        path: "/orders",
        tags: ["orders"],
        url: "https://example.com/orders",
        status_code: 200,
        flagged: true,
        issue: "response_schema_mismatch",
        severity: "medium",
        confidence: "high",
      },
      artifacts: [
        {
          label: "Request artifact",
          kind: "request",
          artifact_name: "atk-order.json",
          available: false,
          profile: null,
          step_index: null,
        },
      ],
      auth_events: [],
      highlighted_auth_events: [],
    };
  }

  return {
    job_id: "job-2",
    attack_id: "atk-login",
    result: {
      type: "workflow",
      attack_id: "atk-login",
      operation_id: "login",
      kind: "missing_auth",
      name: "Login failure",
      protocol: "rest",
      method: "POST",
      path: "/login",
      tags: ["auth"],
      url: "https://example.com/login",
      status_code: 500,
      flagged: true,
      issue: "server_error",
      severity: "high",
      confidence: "high",
      workflow_steps: [
        {
          name: "Create session",
          operation_id: "createSession",
          method: "POST",
          url: "https://example.com/session",
          status_code: 201,
          duration_ms: 12.5,
          response_excerpt: '{"session":"ok"}',
        },
      ],
      profile_results: [
        {
          profile: "member",
          level: 1,
          anonymous: false,
          url: "https://example.com/login",
          status_code: 403,
          flagged: true,
          issue: "server_error",
          severity: "high",
          confidence: "high",
          workflow_steps: [
            {
              name: "Create session",
              operation_id: "createSession",
              method: "POST",
              url: "https://example.com/session",
              status_code: 201,
            },
          ],
        },
      ],
    },
    artifacts: [
      {
        label: "Workflow terminal artifact",
        kind: "workflow_terminal",
        artifact_name: "atk-login.json",
        available: true,
        profile: null,
        step_index: null,
      },
      {
        label: "Workflow step 1",
        kind: "workflow_step",
        artifact_name: "atk-login-step-01.json",
        available: true,
        profile: null,
        step_index: 1,
      },
      {
        label: "member profile artifact",
        kind: "profile_request",
        artifact_name: "member/atk-login.json",
        available: true,
        profile: "member",
        step_index: null,
      },
    ],
    auth_events: [
      {
        name: "member-login",
        strategy: "cookie",
        phase: "acquire",
        success: true,
        profile: "member",
        status_code: 200,
        error: null,
      },
      {
        name: "admin-login",
        strategy: "cookie",
        phase: "refresh",
        success: false,
        profile: "admin",
        status_code: 401,
        error: "expired",
      },
    ],
    highlighted_auth_events: [
      {
        name: "member-login",
        strategy: "cookie",
        phase: "acquire",
        success: true,
        profile: "member",
        status_code: 200,
        error: null,
      },
    ],
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
    let projectPayload = clone(baseProjectPayload);
    const jobsPayload = clone(baseJobsPayload);
    let baselineRefreshCount = 0;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";

        if (url.endsWith("/v1/projects/project-1") && method === "GET") {
          return Response.json(projectPayload);
        }

        if (url.endsWith("/v1/projects/project-1/jobs") && method === "GET") {
          return Response.json(jobsPayload);
        }

        if (url.endsWith("/v1/projects/project-1") && method === "PATCH") {
          const patch = JSON.parse(String(init?.body ?? "{}"));
          projectPayload = {
            ...projectPayload,
            ...patch,
            review_draft: {
              ...projectPayload.review_draft,
              ...(patch.review_draft ?? {}),
            },
            artifacts: {
              ...projectPayload.artifacts,
              ...(patch.artifacts ?? {}),
            },
          };
          return Response.json(projectPayload);
        }

        if (url.endsWith("/v1/projects/project-1/review") && method === "POST") {
          const body = JSON.parse(String(init?.body ?? "{}"));
          if (body.baseline_mode === "external") {
            return Response.json({
              ...createReviewResponse({
                baselineJobId: projectPayload.review_draft.baseline_job_id ?? null,
                waitingForNewRun: false,
                baselineUsed: false,
              }),
              baseline_mode: "external",
            });
          }
          if (body.baseline_job_id === "job-2") {
            return Response.json(
              createReviewResponse({
                baselineJobId: "job-2",
                waitingForNewRun: true,
                baselineUsed: false,
              }),
            );
          }
          if (body.baseline_job_id === "job-1") {
            baselineRefreshCount += 1;
            const reviewResponse = createReviewResponse({
              baselineJobId: "job-1",
              waitingForNewRun: false,
              baselineUsed: true,
            });
            if (baselineRefreshCount > 1) {
              reviewResponse.verification.current_findings = [
                clone(baseProjectPayload.artifacts.latest_verification!.new_findings[1]),
              ];
              reviewResponse.verification.new_findings = [];
              reviewResponse.verification.persisting_findings = [];
              reviewResponse.verification.current_findings_count = 1;
              reviewResponse.verification.new_findings_count = 0;
              reviewResponse.verification.persisting_findings_count = 0;
              reviewResponse.summary.top_findings = [
                {
                  attack_id: "atk-order",
                  name: "Order mismatch",
                  protocol: "rest",
                  kind: "wrong_type_param",
                  issue: "response_schema_mismatch",
                  severity: "medium",
                  confidence: "high",
                  status_code: 200,
                  url: "https://example.com/orders",
                  schema_status: "not_applicable",
                },
              ];
            }
            return Response.json(reviewResponse);
          }
          return Response.json(
            createReviewResponse({
              baselineJobId: null,
              waitingForNewRun: false,
              baselineUsed: false,
            }),
          );
        }

        if (url.endsWith("/v1/jobs/job-1/result") && method === "GET") {
          return Response.json({
            source: "unit",
            base_url: "https://example.com",
            executed_at: "2026-04-13T19:01:00Z",
            profiles: [],
            auth_events: [],
            results: [],
          });
        }

        if (url.endsWith("/v1/jobs/job-2/findings/atk-login/evidence") && method === "GET") {
          return Response.json(createEvidenceResponse("atk-login"));
        }

        if (url.endsWith("/v1/jobs/job-2/findings/atk-order/evidence") && method === "GET") {
          return Response.json(createEvidenceResponse("atk-order"));
        }

        if (url.endsWith("/v1/jobs/job-2/artifacts/atk-login.json") && method === "GET") {
          return new Response(
            JSON.stringify({
              attack: { id: "atk-login", name: "Login failure" },
              request: {
                method: "POST",
                url: "https://example.com/login",
                headers: { Authorization: "Bearer demo" },
                query: {},
                body: { present: true, kind: "json", excerpt: '{"username":"demo"}' },
              },
              response: {
                status_code: 500,
                error: "server exploded",
                duration_ms: 23.4,
                body_excerpt: '{"error":"boom"}',
              },
            }),
          );
        }

        if (url.endsWith("/v1/jobs/job-2/artifacts/atk-login-step-01.json") && method === "GET") {
          return new Response('{"attack":{"id":"atk-login-step-01"}}');
        }

        if (url.endsWith("/v1/jobs/job-2/artifacts/member/atk-login.json") && method === "GET") {
          return new Response("member artifact text");
        }

        throw new Error(`Unhandled fetch for ${method} ${url}`);
      }),
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("renders the fixed step rail and disables runs without a generated suite", async () => {
    renderWorkbench();

    expect(await screen.findByRole("heading", { name: "Workbench demo" })).toBeInTheDocument();
    const stepRail = screen.getByRole("navigation", { name: "Workbench steps" });
    for (const stepName of ["source", "inspect", "generate", "run", "review"]) {
      expect(
        within(stepRail).getByRole("button", { name: new RegExp(stepName, "i") }),
      ).toBeInTheDocument();
    }
    expect(screen.getByRole("button", { name: "Run suite" })).toBeDisabled();
  });

  it("filters new findings inside the diff-first review tabs", async () => {
    renderWorkbench();

    await screen.findByRole("heading", { name: "Workbench demo" });
    fireEvent.click(screen.getByRole("tab", { name: "New" }));

    const table = screen
      .getAllByRole("table")
      .find((candidate) => within(candidate).queryByText("Login failure"));
    if (!table) {
      throw new Error("Expected the new findings table to render.");
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
      ...structuredClone(baseProjectPayload),
      id: "project-2",
      name: "Workbench demo copy",
      created_at: "2026-04-13T20:06:00Z",
      updated_at: "2026-04-13T20:06:00Z",
      review_draft: {
        ...structuredClone(baseProjectPayload.review_draft),
        baseline_job_id: null,
      },
      artifacts: {
        ...structuredClone(baseProjectPayload.artifacts),
        last_run_job_id: null,
      },
    };

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (url.endsWith("/v1/projects/project-1") && method === "GET") {
        return Response.json(baseProjectPayload);
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

  it("loads and clears a saved run baseline from the review workspace", async () => {
    let projectState = structuredClone(baseProjectPayload);
    projectState.artifacts.last_run_job_id = "job-current";
    const latestVerification = projectState.artifacts.latest_verification;
    if (!latestVerification) {
      throw new Error("Expected latest verification fixture to be present");
    }

    const baselineResults = {
      source: "unit",
      base_url: "https://example.com",
      executed_at: "2026-04-13T19:30:00Z",
      profiles: [],
      auth_events: [],
      results: [],
    };

    const comparisonVerification = {
      ...latestVerification,
      baseline_used: true,
      new_findings_count: 1,
      resolved_findings_count: 1,
      persisting_findings_count: 1,
      current_findings: [
        latestVerification.current_findings[0],
        {
          ...latestVerification.current_findings[1],
          change: "persisting",
          delta_changes: [{ field: "status", baseline: "500", current: "200" }],
        },
      ],
      new_findings: [latestVerification.current_findings[0]],
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
          ...latestVerification.current_findings[1],
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
          return Response.json(
            body.baseline ? comparisonSummary : baseProjectPayload.artifacts.latest_summary,
          );
        }
        if (url.endsWith("/v1/verify") && method === "POST") {
          const body = JSON.parse(String(init?.body ?? "{}"));
          return Response.json(
            body.baseline
              ? comparisonVerification
              : baseProjectPayload.artifacts.latest_verification,
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
  });

  it("refreshes comparison when selecting a baseline and pinning the latest run", async () => {
    renderWorkbench();

    await screen.findByRole("heading", { name: "Workbench demo" });
    fireEvent.change(screen.getByLabelText("Pinned baseline run"), {
      target: { value: "job-1" },
    });

    expect(await screen.findByText("Diffs ready")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByLabelText("Pinned baseline run")).toHaveValue("job-1"),
    );

    fireEvent.click(screen.getByRole("button", { name: "Pin latest run as baseline" }));

    expect(await screen.findByText("Waiting for next run")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByLabelText("Pinned baseline run")).toHaveValue("job-2"),
    );
  });

  it("keeps external baseline JSON as an advanced fallback with validation", async () => {
    renderWorkbench();

    await screen.findByRole("heading", { name: "Workbench demo" });
    fireEvent.click(screen.getByRole("button", { name: "External JSON" }));
    fireEvent.click(screen.getByText("External baseline JSON"));

    const editors = screen.getAllByTestId("code-editor");
    fireEvent.change(editors.at(-1)!, { target: { value: "{" } });
    const refreshButton = await screen.findByRole("button", { name: /Refresh/ });
    fireEvent.click(refreshButton);

    expect(
      await screen.findByText("Fix external baseline JSON before refreshing the review workspace."),
    ).toBeInTheDocument();
  });

  it("opens the evidence drawer from diff findings and loads artifact content lazily", async () => {
    renderWorkbench();

    await screen.findByRole("heading", { name: "Workbench demo" });
    fireEvent.click(screen.getByRole("tab", { name: "New" }));
    fireEvent.click(screen.getByRole("button", { name: "Login failure" }));

    expect(await screen.findByText("Current-run evidence")).toBeInTheDocument();
    expect(await screen.findByText("Workflow terminal artifact")).toBeInTheDocument();
    expect(await screen.findByText("Create session")).toBeInTheDocument();
    expect((await screen.findAllByText("member-login")).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/https:\/\/example.com\/login/)).length).toBeGreaterThan(0);
    expect(await screen.findByText(/server exploded/)).toBeInTheDocument();
  });

  it("keeps resolved findings summary-only and reuses the artifact viewer in the artifacts tab", async () => {
    renderWorkbench();

    await screen.findByRole("heading", { name: "Workbench demo" });
    fireEvent.change(screen.getByLabelText("Pinned baseline run"), {
      target: { value: "job-1" },
    });

    expect(await screen.findByText("Diffs ready")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Resolved" }));

    expect(
      await screen.findByText(
        "Resolved findings are baseline-only in this milestone, so current-run artifact evidence is not available.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Order mismatch" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: "Artifacts" }));
    expect(await screen.findByRole("button", { name: "atk-login.json" })).toBeInTheDocument();
    expect((await screen.findAllByText(/Authorization/)).length).toBeGreaterThan(0);
    expect(await screen.findByText(/server exploded/)).toBeInTheDocument();
  });

  it("closes stale evidence when a refreshed comparison no longer includes the selected finding", async () => {
    renderWorkbench();

    await screen.findByRole("heading", { name: "Workbench demo" });
    fireEvent.change(screen.getByLabelText("Pinned baseline run"), {
      target: { value: "job-1" },
    });
    expect(await screen.findByText("Diffs ready")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Login failure" }));
    expect(await screen.findByText("Current-run evidence")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Refresh analysis" }));

    expect(
      await screen.findByText(
        "Evidence changed with the latest run. Reopen a finding from the refreshed comparison.",
      ),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Close evidence" })).not.toBeInTheDocument(),
    );

    expect(screen.queryByRole("button", { name: "Close evidence" })).not.toBeInTheDocument();
  });

  it("renders imported bundles as review-only workspaces and keeps artifact inspection available", async () => {
    const importedProject = clone(baseProjectPayload);
    importedProject.name = "Imported review bundle";
    importedProject.source_mode = "review_bundle";
    importedProject.source = null;
    importedProject.artifacts.last_run_job_id = "job-import";
    importedProject.artifacts.latest_promoted_suite = null;
    importedProject.artifacts.generated_suite = null;
    importedProject.review_draft = {
      ...importedProject.review_draft,
      baseline_mode: "external",
      baseline: {
        source: "baseline",
        base_url: "https://baseline.example.com",
        executed_at: "2026-04-13T19:00:00Z",
        profiles: [],
        auth_events: [],
        results: [],
      },
    };

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        if (url.endsWith("/v1/projects/project-1") && method === "GET") {
          return Response.json(importedProject);
        }
        if (url.endsWith("/v1/projects/project-1") && method === "PATCH") {
          return Response.json(importedProject);
        }
        if (url.endsWith("/v1/projects/project-1/jobs") && method === "GET") {
          return Response.json({
            project_id: "project-1",
            jobs: [
              {
                id: "job-import",
                kind: "import",
                status: "completed",
                created_at: "2026-04-15T04:00:00Z",
                started_at: "2026-04-15T04:00:00Z",
                completed_at: "2026-04-15T04:00:00Z",
                base_url: "https://example.com",
                attack_count: 2,
                project_id: "project-1",
                error: null,
                result_available: true,
                artifact_names: ["atk-login.json"],
                result_summary: importedProject.artifacts.latest_summary,
              },
            ],
          });
        }
        if (url.endsWith("/v1/jobs/job-import/artifacts/atk-login.json") && method === "GET") {
          return new Response(
            JSON.stringify({
              attack: { id: "atk-login", name: "Login failure" },
              request: {
                method: "POST",
                url: "https://example.com/login",
                headers: { Authorization: "Bearer demo" },
                query: {},
                body: { present: true, kind: "json", excerpt: '{"username":"demo"}' },
              },
              response: {
                status_code: 500,
                error: "server exploded",
                duration_ms: 23.4,
                body_excerpt: '{"error":"boom"}',
              },
            }),
          );
        }
        throw new Error(`Unhandled fetch for ${method} ${url}`);
      }),
    );

    renderWorkbench();

    expect(await screen.findByRole("heading", { name: "Imported review bundle" })).toBeInTheDocument();
    expect(await screen.findByText("Review-only workspace")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Duplicate project" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Promote findings" })).not.toBeInTheDocument();
    expect(screen.queryByText("Choose how this project begins")).not.toBeInTheDocument();
    const stepRail = screen.getByRole("navigation", { name: "Workbench steps" });
    expect(within(stepRail).getByRole("button", { name: /01source/i })).toBeDisabled();
    expect(within(stepRail).getByRole("button", { name: /02inspect/i })).toBeDisabled();
    expect(within(stepRail).getByRole("button", { name: /03generate/i })).toBeDisabled();
    expect(within(stepRail).getByRole("button", { name: /04run/i })).toBeDisabled();

    fireEvent.click(screen.getByRole("tab", { name: "Artifacts" }));
    expect(await screen.findByRole("button", { name: "atk-login.json" })).toBeInTheDocument();
    expect(await screen.findByText(/server exploded/)).toBeInTheDocument();
  });

  it("uses project-scoped retention actions from the artifacts panel", async () => {
    let projectState = clone(baseProjectPayload);
    projectState.review_draft = {
      ...projectState.review_draft,
      baseline_job_id: "job-1",
    };
    let jobs = clone(baseJobsPayload.jobs);

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
      if (url.endsWith("/v1/projects/project-1/review") && method === "POST") {
        return Response.json({
          ...createReviewResponse({
            baselineJobId: projectState.review_draft.baseline_job_id ?? null,
            waitingForNewRun: false,
            baselineUsed: projectState.review_draft.baseline_job_id === "job-1",
          }),
          baseline_job_id: projectState.review_draft.baseline_job_id,
        });
      }
      if (url.endsWith("/v1/projects/project-1/jobs/job-1") && method === "DELETE") {
        const baselineJob = jobs.find((job) => job.id === "job-1");
        if (!baselineJob) {
          throw new Error("Expected the baseline job to exist.");
        }
        jobs = jobs.filter((job) => job.id !== "job-1");
        return Response.json({
          deleted: {
            id: baselineJob.id,
            status: baselineJob.status,
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
        const currentJob = jobs.find((job) => job.id === "job-2");
        const body = JSON.parse(String(init?.body ?? "{}")) as { dry_run?: boolean };
        if (body.dry_run) {
          return Response.json({
            dry_run: true,
            matched_count: currentJob ? 1 : 0,
            deleted_count: 0,
            jobs: currentJob
              ? [
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
                ]
              : [],
          });
        }
        if (!currentJob) {
          return Response.json({
            dry_run: false,
            matched_count: 0,
            deleted_count: 0,
            jobs: [],
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
      if (url.endsWith("/v1/jobs/job-2/artifacts/atk-login.json") && method === "GET") {
        return new Response(
          JSON.stringify({
            attack: { id: "atk-login", name: "Login failure" },
            request: {
              method: "POST",
              url: "https://example.com/login",
              headers: { Authorization: "Bearer demo" },
              query: {},
              body: { present: true, kind: "json", excerpt: '{"username":"demo"}' },
            },
            response: {
              status_code: 500,
              error: "server exploded",
              duration_ms: 23.4,
              body_excerpt: '{"error":"boom"}',
            },
          }),
        );
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

    fireEvent.click(screen.getByRole("button", { name: "Delete run job-1" }));

    const baselineSelect = screen.getByLabelText("Pinned baseline run");
    await waitFor(() => expect(baselineSelect).toHaveValue(""));

    fireEvent.click(screen.getByRole("tab", { name: /Artifacts/ }));
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
    expect(
      screen.getByText("No current compared run is available for artifact inspection."),
    ).toBeInTheDocument();
    expect(confirmSpy).toHaveBeenCalledTimes(2);
  });
});
