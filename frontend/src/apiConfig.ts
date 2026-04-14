const API_BASE_STORAGE_KEY = "knives-out.api-base-url";

function trimTrailingSlash(value: string): string {
  if (!value || value === "/") {
    return value;
  }
  return value.replace(/\/+$/, "");
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

export function buildApiUrl(path: string): string {
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  const base = getApiBaseUrl();
  return base ? `${base}${cleanPath}` : cleanPath;
}
