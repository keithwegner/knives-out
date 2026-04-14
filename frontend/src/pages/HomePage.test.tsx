import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import HomePage from "./HomePage";

function renderHomePage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <HomePage />
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
    vi.unstubAllGlobals();
  });

  it("renders saved projects", async () => {
    renderHomePage();

    expect(await screen.findByText("Storefront triage")).toBeInTheDocument();
    expect(screen.getByText("connected")).toBeInTheDocument();
    expect(screen.getByText("storefront.yaml")).toBeInTheDocument();
    expect(screen.getByText("completed")).toBeInTheDocument();
    expect(screen.getByText("Open")).toBeInTheDocument();
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
