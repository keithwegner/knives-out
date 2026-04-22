import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useParams } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import HomePage from "./HomePage";

function ProjectRoute() {
  const { projectId } = useParams();
  return <div>{`Opened ${projectId}`}</div>;
}

function renderHomePage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/projects/:projectId" element={<ProjectRoute />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("HomePage", () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/healthz")) {
          return Response.json({ status: "ok" });
        }
        if (url.endsWith("/v1/edition")) {
          return Response.json({
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
          });
        }
        if (url.endsWith("/v1/projects")) {
          return Response.json({
            projects: [
              {
                id: "project-1",
                name: "Storefront triage",
                source_mode: "openapi",
                active_step: "review",
                created_at: "2026-04-13T20:00:00Z",
                updated_at: "2026-04-13T20:05:00Z",
                source_name: "storefront.yaml",
                job_count: 2,
                last_run_job_id: "job-1",
                last_run_status: "completed",
                last_run_at: "2026-04-13T20:06:00Z",
                active_flagged_count: 3,
              },
            ],
          });
        }
        throw new Error(`Unhandled fetch for ${url}`);
      }),
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("renders saved projects", async () => {
    renderHomePage();

    expect(await screen.findByText("Storefront triage")).toBeInTheDocument();
    expect(screen.getByText("connected")).toBeInTheDocument();
    expect(screen.getByText("Free edition")).toBeInTheDocument();
    expect(screen.getByText("Get Pro")).toBeInTheDocument();
    expect(screen.getByText("storefront.yaml")).toBeInTheDocument();
    expect(screen.getByText("Resume at")).toBeInTheDocument();
    expect(screen.getByText("review")).toBeInTheDocument();
    expect(screen.getByText("Latest run")).toBeInTheDocument();
    expect(screen.getAllByText("completed").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("Findings")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText(/2 saved runs/)).toBeInTheDocument();
    expect(screen.getByText("Open")).toBeInTheDocument();
    const exportLink = screen.getByRole("link", { name: "Export snapshot" });
    expect(exportLink).toHaveAttribute("download", "knives-out-project-project-1.zip");
    expect(exportLink.getAttribute("href")).toContain("/v1/projects/project-1/snapshot");
  });

  it("creates a project with the selected source mode", async () => {
    let createBody: unknown = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        if (url.endsWith("/healthz")) {
          return Response.json({ status: "ok" });
        }
        if (url.endsWith("/v1/projects") && method === "GET") {
          return Response.json({ projects: [] });
        }
        if (url.endsWith("/v1/projects") && method === "POST") {
          createBody = JSON.parse(String(init?.body ?? "{}"));
          return Response.json({
            id: "project-new",
            name: "GraphQL review",
            source_mode: "graphql",
            active_step: "source",
            created_at: "2026-04-13T20:00:00Z",
            updated_at: "2026-04-13T20:00:00Z",
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
              baseline_mode: "job",
              baseline_job_id: null,
              baseline: null,
              suppressions_yaml: null,
              min_severity: "high",
              min_confidence: "medium",
            },
            artifacts: {},
          });
        }
        throw new Error(`Unhandled fetch for ${method} ${url}`);
      }),
    );

    renderHomePage();

    await screen.findByText("No saved projects yet.");
    expect(screen.getByRole("radio", { name: /OpenAPI/ })).toHaveAttribute(
      "aria-checked",
      "true",
    );

    fireEvent.click(screen.getByRole("radio", { name: /GraphQL/ }));
    fireEvent.change(screen.getByLabelText("New project"), {
      target: { value: "GraphQL review" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Open workbench" }));

    await waitFor(() =>
      expect(createBody).toEqual({ name: "GraphQL review", source_mode: "graphql" }),
    );
  });

  it("duplicates a saved project from the dashboard", async () => {
    let duplicated = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        if (url.endsWith("/healthz")) {
          return Response.json({ status: "ok" });
        }
        if (url.endsWith("/v1/edition")) {
          return Response.json({
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
          });
        }
        if (url.endsWith("/v1/projects") && method === "GET") {
          return Response.json({
            projects: duplicated
              ? [
                  {
                    id: "project-2",
                    name: "Storefront triage copy",
                    source_mode: "openapi",
                    active_step: "review",
                    created_at: "2026-04-13T20:06:00Z",
                    updated_at: "2026-04-13T20:06:00Z",
                    source_name: "storefront.yaml",
                    job_count: 0,
                    last_run_job_id: null,
                    last_run_status: null,
                    last_run_at: null,
                    active_flagged_count: 3,
                  },
                  {
                    id: "project-1",
                    name: "Storefront triage",
                    source_mode: "openapi",
                    active_step: "review",
                    created_at: "2026-04-13T20:00:00Z",
                    updated_at: "2026-04-13T20:05:00Z",
                    source_name: "storefront.yaml",
                    job_count: 2,
                    last_run_job_id: "job-1",
                    last_run_status: "completed",
                    last_run_at: "2026-04-13T20:06:00Z",
                    active_flagged_count: 3,
                  },
                ]
              : [
                  {
                    id: "project-1",
                    name: "Storefront triage",
                    source_mode: "openapi",
                    active_step: "review",
                    created_at: "2026-04-13T20:00:00Z",
                    updated_at: "2026-04-13T20:05:00Z",
                    source_name: "storefront.yaml",
                    job_count: 2,
                    last_run_job_id: "job-1",
                    last_run_status: "completed",
                    last_run_at: "2026-04-13T20:06:00Z",
                    active_flagged_count: 3,
                  },
                ],
          });
        }
        if (url.endsWith("/v1/projects/project-1/duplicate") && method === "POST") {
          duplicated = true;
          return Response.json({
            id: "project-2",
            name: "Storefront triage copy",
            source_mode: "openapi",
            active_step: "review",
            created_at: "2026-04-13T20:06:00Z",
            updated_at: "2026-04-13T20:06:00Z",
            graphql_endpoint: "/graphql",
            source: { name: "storefront.yaml", content: "openapi: 3.0.3" },
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
              baseline_job_id: null,
              baseline: null,
              suppressions_yaml: null,
              min_severity: "high",
              min_confidence: "medium",
            },
            artifacts: {},
          });
        }
        throw new Error(`Unhandled fetch for ${method} ${url}`);
      }),
    );

    renderHomePage();

    await screen.findByText("Storefront triage");
    fireEvent.click(screen.getByRole("button", { name: "Duplicate" }));

    expect(await screen.findByText("Storefront triage copy")).toBeInTheDocument();
  });

  it("imports a review bundle and opens the imported project", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        if (url.endsWith("/healthz")) {
          return Response.json({ status: "ok" });
        }
        if (url.endsWith("/v1/projects") && method === "GET") {
          return Response.json({ projects: [] });
        }
        if (url.endsWith("/v1/projects/import-review-bundle") && method === "POST") {
          expect(init?.body).toBeInstanceOf(FormData);
          return Response.json({
            id: "project-imported",
            name: "Imported review bundle",
            source_mode: "review_bundle",
            active_step: "review",
            created_at: "2026-04-15T04:00:00Z",
            updated_at: "2026-04-15T04:00:00Z",
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
              baseline_mode: "job",
              baseline_job_id: null,
              baseline: null,
              suppressions_yaml: null,
              min_severity: "high",
              min_confidence: "medium",
            },
            artifacts: {},
          });
        }
        throw new Error(`Unhandled fetch for ${method} ${url}`);
      }),
    );

    const { container } = renderHomePage();

    await screen.findByText("No saved projects yet.");
    const bundleInput = container.querySelector('input[aria-label="Review bundle zip"]');
    if (!(bundleInput instanceof HTMLInputElement)) {
      throw new Error("Expected the review bundle input to render.");
    }
    fireEvent.change(bundleInput, {
      target: {
        files: [new File(["zip"], "review-bundle.zip", { type: "application/zip" })],
      },
    });

    expect(await screen.findByText("Opened project-imported")).toBeInTheDocument();
  });

  it("imports a project snapshot and opens the imported project", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        if (url.endsWith("/healthz")) {
          return Response.json({ status: "ok" });
        }
        if (url.endsWith("/v1/edition")) {
          return Response.json({
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
          });
        }
        if (url.endsWith("/v1/projects") && method === "GET") {
          return Response.json({ projects: [] });
        }
        if (url.endsWith("/v1/projects/import-snapshot") && method === "POST") {
          expect(init?.body).toBeInstanceOf(FormData);
          return Response.json({ id: "project-snapshot", name: "Imported snapshot" });
        }
        throw new Error(`Unhandled fetch for ${method} ${url}`);
      }),
    );

    const { container } = renderHomePage();

    await screen.findByText("No saved projects yet.");
    const snapshotInput = container.querySelector('input[aria-label="Project snapshot zip"]');
    if (!(snapshotInput instanceof HTMLInputElement)) {
      throw new Error("Expected the project snapshot input to render.");
    }
    fireEvent.change(snapshotInput, {
      target: {
        files: [new File(["zip"], "project-snapshot.zip", { type: "application/zip" })],
      },
    });

    expect(await screen.findByText("Opened project-snapshot")).toBeInTheDocument();
  });

  it("surfaces project snapshot import validation errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        if (url.endsWith("/healthz")) {
          return Response.json({ status: "ok" });
        }
        if (url.endsWith("/v1/edition")) {
          return Response.json({
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
          });
        }
        if (url.endsWith("/v1/projects") && method === "GET") {
          return Response.json({ projects: [] });
        }
        if (url.endsWith("/v1/projects/import-snapshot") && method === "POST") {
          return Response.json({ detail: "Project snapshot is empty." }, { status: 400 });
        }
        throw new Error(`Unhandled fetch for ${method} ${url}`);
      }),
    );

    const { container } = renderHomePage();

    await screen.findByText("No saved projects yet.");
    const snapshotInput = container.querySelector('input[aria-label="Project snapshot zip"]');
    if (!(snapshotInput instanceof HTMLInputElement)) {
      throw new Error("Expected the project snapshot input to render.");
    }
    fireEvent.change(snapshotInput, {
      target: {
        files: [new File([], "empty.zip", { type: "application/zip" })],
      },
    });

    expect(await screen.findByText("Project snapshot is empty.")).toBeInTheDocument();
  });

  it("saves a custom API endpoint", async () => {
    renderHomePage();

    await screen.findByText("Storefront triage");
    const apiBaseInput = screen.getAllByLabelText("API base URL").at(-1);
    if (!apiBaseInput) {
      throw new Error("Expected the API base URL input to render.");
    }
    fireEvent.change(apiBaseInput, {
      target: { value: "https://api.example.com/" },
    });
    const saveButton = screen.getAllByRole("button", { name: "Save endpoint" }).at(-1);
    if (!saveButton) {
      throw new Error("Expected the save endpoint action to render.");
    }
    fireEvent.click(saveButton);

    expect(window.localStorage.getItem("knives-out.api-base-url")).toBe("https://api.example.com");
  });

  it("shows a concise error when the endpoint returns HTML", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        return new Response("<!DOCTYPE html><html><body>404</body></html>", {
          status: 404,
          statusText: "Not Found",
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }),
    );

    renderHomePage();

    expect(
      await screen.findByText(/returned HTML instead of the JSON API/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/<!DOCTYPE html>/i)).not.toBeInTheDocument();
  });
});
