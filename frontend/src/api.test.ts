import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildProjectSnapshotUrl, importProjectSnapshot, listProjects } from "./api";

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

  it("builds project snapshot URLs", () => {
    expect(buildProjectSnapshotUrl("project 1")).toBe("/v1/projects/project%201/snapshot");
  });

  it("posts project snapshot imports as multipart form data", async () => {
    const submission: { body?: BodyInit | null } = {};
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        submission.body = init?.body;
        return Response.json({ id: "project-imported" });
      }),
    );

    await importProjectSnapshot(new File(["zip"], "snapshot.zip", { type: "application/zip" }));

    const submittedBody = submission.body as unknown;
    expect(submittedBody).toBeInstanceOf(FormData);
    if (!(submittedBody instanceof FormData)) {
      throw new Error("Expected snapshot import body to be FormData.");
    }
    expect(submittedBody.get("snapshot")).toBeInstanceOf(File);
  });
});
