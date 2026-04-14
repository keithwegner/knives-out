import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildApiUrl,
  describeApiBaseUrl,
  getApiBaseUrl,
  normalizeApiBaseUrl,
  persistApiBaseUrl,
} from "./apiConfig";

describe("apiConfig", () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.unstubAllGlobals();
  });

  it("normalizes and persists configured API base URLs", () => {
    expect(normalizeApiBaseUrl(" https://api.example.com/ ")).toBe("https://api.example.com");
    expect(persistApiBaseUrl("https://api.example.com/")).toBe("https://api.example.com");
    expect(getApiBaseUrl()).toBe("https://api.example.com");
    expect(buildApiUrl("/v1/projects")).toBe("https://api.example.com/v1/projects");
  });

  it("clears back to same-origin mode", () => {
    persistApiBaseUrl("https://api.example.com");
    expect(describeApiBaseUrl(getApiBaseUrl())).toBe("https://api.example.com");

    persistApiBaseUrl("");

    expect(getApiBaseUrl()).toBe("");
    expect(buildApiUrl("/healthz")).toBe("/healthz");
    expect(describeApiBaseUrl("")).toBe("same origin");
  });
});
