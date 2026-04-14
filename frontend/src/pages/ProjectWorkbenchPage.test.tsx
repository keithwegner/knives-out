import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import ProjectWorkbenchPage from "./ProjectWorkbenchPage";

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
});
