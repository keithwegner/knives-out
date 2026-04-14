import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { listProjects } from "./api";

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
});
