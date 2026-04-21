import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useParams } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import CiReviewOpsPage from "./CiReviewOpsPage";
import type {
  EditionStatus,
  ProjectJobsResponse,
  ProjectListResponse,
  ProjectRecord,
} from "../types";

function ProjectRoute() {
  const { projectId } = useParams();
  return <div>{`Opened ${projectId}`}</div>;
}

function renderReviewOpsPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/reviewops"]}>
        <Routes>
          <Route path="/reviewops" element={<CiReviewOpsPage />} />
          <Route path="/projects/:projectId" element={<ProjectRoute />} />
          <Route path="/" element={<div>Home</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const freeEdition: EditionStatus = {
  edition: "free",
  plan: "Free",
  license_state: "missing",
  enabled_capabilities: [],
  locked_capabilities: ["ci_reviewops"],
  customer: null,
  expires_at: null,
  grace_expires_at: null,
  upgrade_url: "https://github.com/keithwegner/knives-out/blob/main/docs/pro.md",
  message: "Running the MIT Free edition.",
  extension_errors: [],
};

const proEdition: EditionStatus = {
  edition: "pro",
  plan: "Pro Team",
  license_state: "valid",
  enabled_capabilities: ["ci_reviewops"],
  locked_capabilities: [],
  customer: "Demo Co",
  expires_at: "2026-12-31T00:00:00Z",
  grace_expires_at: null,
  upgrade_url: "https://github.com/keithwegner/knives-out/blob/main/docs/pro.md",
  message: "CI ReviewOps enabled.",
  extension_errors: [],
};

const projectListPayload: ProjectListResponse = {
  projects: [
    {
      id: "repo-1",
      name: "Storefront service",
      source_mode: "review_bundle",
      active_step: "review",
      created_at: "2026-04-20T18:00:00Z",
      updated_at: "2026-04-20T19:00:00Z",
      source_name: null,
      job_count: 2,
      last_run_job_id: "job-pr-123456",
      last_run_status: "completed",
      last_run_at: "2026-04-20T19:00:00Z",
      active_flagged_count: 3,
    },
  ],
};

const projectPayload: ProjectRecord = {
  id: "repo-1",
  name: "Storefront service",
  source_mode: "review_bundle",
  active_step: "review",
  created_at: "2026-04-20T18:00:00Z",
  updated_at: "2026-04-20T19:00:00Z",
  graphql_endpoint: "/graphql",
  source: null,
  discover_inputs: [],
  inspect_draft: { tag: [], exclude_tag: [], path: [], exclude_path: [] },
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
    baseline_mode: "external",
    baseline_job_id: null,
    baseline: {
      source: "ci",
      base_url: "https://storefront.example.com",
      executed_at: "2026-04-20T18:00:00Z",
      profiles: [],
      auth_events: [],
      results: [],
    },
    suppressions_yaml: null,
    min_severity: "high",
    min_confidence: "medium",
  },
  artifacts: {
    latest_summary: {
      source: "ci",
      base_url: "https://storefront.example.com",
      executed_at: "2026-04-20T19:00:00Z",
      baseline_used: true,
      baseline_executed_at: "2026-04-20T18:00:00Z",
      total_results: 4,
      profile_count: 0,
      profile_names: [],
      active_flagged_count: 3,
      suppressed_flagged_count: 0,
      new_findings_count: 1,
      resolved_findings_count: 1,
      persisting_findings_count: 2,
      persisting_deltas_count: 1,
      auth_failures: 0,
      refresh_attempts: 0,
      response_schema_mismatches: 1,
      graphql_shape_mismatches: 0,
      protocol_counts: { rest: 4 },
      issue_counts: { server_error: 2, response_schema_mismatch: 1 },
      finding_severity_counts: { high: 2, medium: 1 },
      finding_confidence_counts: { high: 3 },
      auth_summary: [],
      top_findings: [],
    },
    latest_verification: {
      passed: false,
      baseline_used: true,
      min_severity: "high",
      min_confidence: "medium",
      current_findings_count: 3,
      new_findings_count: 1,
      resolved_findings_count: 1,
      persisting_findings_count: 2,
      suppressed_current_findings_count: 0,
      current_findings: [],
      failing_findings: [],
      new_findings: [
        {
          change: "new",
          attack_id: "atk-login",
          name: "Login regression",
          protocol: "rest",
          kind: "missing_auth",
          method: "POST",
          path: "/login",
          tags: ["auth"],
          issue: "server_error",
          severity: "high",
          confidence: "high",
          status_code: 500,
          url: "https://storefront.example.com/login",
          delta_changes: [],
        },
      ],
      resolved_findings: [
        {
          change: "resolved",
          attack_id: "atk-legacy",
          name: "Legacy endpoint retired",
          protocol: "rest",
          kind: "missing_auth",
          method: "GET",
          path: "/legacy",
          tags: ["legacy"],
          issue: "server_error",
          severity: "medium",
          confidence: "medium",
          status_code: 404,
          url: "https://storefront.example.com/legacy",
          delta_changes: [],
        },
      ],
      persisting_findings: [
        {
          change: "persisting",
          attack_id: "atk-cart",
          name: "Cart still errors",
          protocol: "rest",
          kind: "wrong_type_param",
          method: "GET",
          path: "/cart",
          tags: ["cart"],
          issue: "server_error",
          severity: "high",
          confidence: "high",
          status_code: 500,
          url: "https://storefront.example.com/cart",
          delta_changes: [{ field: "status", baseline: "401", current: "500" }],
        },
      ],
    },
    latest_results: null,
    latest_markdown_report: "# report",
    latest_html_report: "<!doctype html>",
    last_run_job_id: "job-pr-123456",
  },
};

const jobsPayload: ProjectJobsResponse = {
  project_id: "repo-1",
  jobs: [
    {
      id: "job-pr-123456",
      kind: "import",
      status: "completed",
      created_at: "2026-04-20T19:00:00Z",
      started_at: "2026-04-20T19:00:01Z",
      completed_at: "2026-04-20T19:00:05Z",
      base_url: "https://storefront.example.com",
      attack_count: 4,
      project_id: "repo-1",
      error: null,
      result_available: true,
      artifact_names: ["atk-login.json", "atk-cart.json"],
      result_summary: projectPayload.artifacts.latest_summary,
    },
    {
      id: "job-main-999999",
      kind: "import",
      status: "completed",
      created_at: "2026-04-20T18:00:00Z",
      started_at: "2026-04-20T18:00:01Z",
      completed_at: "2026-04-20T18:00:05Z",
      base_url: "https://storefront.example.com",
      attack_count: 4,
      project_id: "repo-1",
      error: null,
      result_available: true,
      artifact_names: ["atk-legacy.json"],
      result_summary: {
        ...projectPayload.artifacts.latest_summary!,
        active_flagged_count: 2,
        new_findings_count: 0,
        resolved_findings_count: 0,
        persisting_findings_count: 0,
        persisting_deltas_count: 0,
      },
    },
  ],
};

describe("CiReviewOpsPage", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("shows a locked Pro state without requesting project data in Free edition", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/v1/edition")) {
        return Response.json(freeEdition);
      }
      throw new Error(`Unhandled fetch for ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    renderReviewOpsPage();

    expect(
      await screen.findByRole("heading", { name: "Repository and PR comparison views are locked" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Running the MIT Free edition.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open free workbench" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View Pro options" })).toBeInTheDocument();
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(([input]) => String(input).endsWith("/v1/projects")),
      ).toBe(false),
    );
  });

  it("renders imported repository runs, baseline deltas, and evidence links for Pro", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/edition")) {
          return Response.json(proEdition);
        }
        if (url.endsWith("/v1/projects")) {
          return Response.json(projectListPayload);
        }
        if (url.endsWith("/v1/projects/repo-1")) {
          return Response.json(projectPayload);
        }
        if (url.endsWith("/v1/projects/repo-1/jobs")) {
          return Response.json(jobsPayload);
        }
        throw new Error(`Unhandled fetch for ${url}`);
      }),
    );

    renderReviewOpsPage();

    expect(
      await screen.findByRole("heading", { name: "Repository runs and PR comparisons" }),
    ).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: /Storefront service/ })).toBeInTheDocument();
    expect(screen.getByText("Imported CI review bundle")).toBeInTheDocument();
    expect(await screen.findByText(/External baseline from/)).toBeInTheDocument();
    expect(screen.getByText("Login regression")).toBeInTheDocument();
    expect(screen.getByText("Legacy endpoint retired")).toBeInTheDocument();
    expect(screen.getByText("Cart still errors")).toBeInTheDocument();
    expect(screen.getByText("status: 401 -> 500")).toBeInTheDocument();

    const comparisonTable = screen
      .getAllByRole("table")
      .find((table) => within(table).queryByText("Login regression"));
    if (!comparisonTable) {
      throw new Error("Expected comparison table to render.");
    }
    expect(within(comparisonTable).getByText("Baseline only")).toBeInTheDocument();
    const artifactLinks = within(comparisonTable).getAllByRole("link", {
      name: "Stored artifact",
    });
    expect(artifactLinks[0].getAttribute("href")).toContain(
      "/v1/jobs/job-pr-123456/artifacts/atk-login.json",
    );
    const evidenceLinks = within(comparisonTable).getAllByRole("link", {
      name: "Open evidence",
    });
    expect(evidenceLinks[0].getAttribute("href")).toBe(
      "/projects/repo-1?review=evidence&finding=atk-login",
    );
  });
});
