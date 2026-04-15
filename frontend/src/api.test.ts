import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildJobArtifactUrl, fetchJobArtifactText, listProjects } from "./api";

describe("api", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sanitizes HTML error responses", async () => {
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

    try {
      await listProjects();
      throw new Error("Expected listProjects to fail.");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      expect(message).toContain("returned HTML instead of the JSON API");
      expect(message).not.toContain("<!DOCTYPE html>");
    }
  });

  it("builds same-origin artifact URLs with encoded nested artifact paths", () => {
    expect(buildJobArtifactUrl("job-1", "profiles/atk api#.json")).toBe(
      "/v1/jobs/job-1/artifacts/profiles/atk%20api%23.json",
    );
  });

  it("builds artifact URLs against the configured API base", () => {
    window.localStorage.setItem("knives-out.api-base-url", "https://api.example.com/");

    expect(buildJobArtifactUrl("job-1", "atk.json")).toBe(
      "https://api.example.com/v1/jobs/job-1/artifacts/atk.json",
    );
  });

  it("fetches raw artifact text through the configured artifact URL", async () => {
    window.localStorage.setItem("knives-out.api-base-url", "https://api.example.com");
    const fetchMock = vi.fn(async () => {
      return new Response('{"attack":{"id":"atk-1"}}', {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const payload = await fetchJobArtifactText("job-1", "profiles/atk.json");

    expect(payload).toContain('"attack"');
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/v1/jobs/job-1/artifacts/profiles/atk.json",
    );
  });
});
