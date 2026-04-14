const API_BASE_STORAGE_KEY = "knives-out.api-base-url";

function trimTrailingSlash(value: string): string {
  if (!value || value === "/") {
    return value;
  }
  return value.replace(/\/+$/, "");
}

function normalizeBasePath(value: string | null | undefined): string {
  const trimmed = value?.trim() || "/";
  const withLeadingSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withLeadingSlash.endsWith("/") ? withLeadingSlash : `${withLeadingSlash}/`;
}

export function normalizeApiBaseUrl(value: string | null | undefined): string {
  if (!value) {
    return "";
  }
  return trimTrailingSlash(value.trim());
}

export function defaultApiBaseUrl(): string {
  return normalizeApiBaseUrl(import.meta.env.VITE_API_BASE_URL);
}

export function getApiBaseUrl(): string {
  if (typeof window === "undefined") {
    return defaultApiBaseUrl();
  }
  const stored = window.localStorage.getItem(API_BASE_STORAGE_KEY);
  return stored === null ? defaultApiBaseUrl() : normalizeApiBaseUrl(stored);
}

export function persistApiBaseUrl(value: string): string {
  const normalized = normalizeApiBaseUrl(value);
  if (typeof window !== "undefined") {
    if (normalized) {
      window.localStorage.setItem(API_BASE_STORAGE_KEY, normalized);
    } else {
      window.localStorage.removeItem(API_BASE_STORAGE_KEY);
    }
  }
  return normalized;
}

export function describeApiBaseUrl(value: string): string {
  return value || "same origin";
}

export function isStaticHostedShell(
  hostname = typeof window === "undefined" ? "" : window.location.hostname,
  basePath = import.meta.env.BASE_URL,
): boolean {
  const normalizedBasePath = normalizeBasePath(basePath);
  return (
    hostname.endsWith(".github.io") ||
    (normalizedBasePath !== "/" && normalizedBasePath !== "/app/")
  );
}

export function needsConfiguredApiBase(
  apiBaseUrl = getApiBaseUrl(),
  hostname = typeof window === "undefined" ? "" : window.location.hostname,
  basePath = import.meta.env.BASE_URL,
): boolean {
  return !normalizeApiBaseUrl(apiBaseUrl) && isStaticHostedShell(hostname, basePath);
}

export function buildApiUrl(path: string): string {
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  const base = getApiBaseUrl();
  return base ? `${base}${cleanPath}` : cleanPath;
}
