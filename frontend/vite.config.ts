import react from "@vitejs/plugin-react";
import { loadEnv } from "vite";
import { defineConfig } from "vitest/config";

function normalizeBasePath(value: string | undefined): string {
  const configured = value?.trim() || "/app/";
  const withLeadingSlash = configured.startsWith("/") ? configured : `/${configured}`;
  return withLeadingSlash.endsWith("/") ? withLeadingSlash : `${withLeadingSlash}/`;
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");

  return {
    base: normalizeBasePath(env.VITE_APP_BASE_PATH),
    plugins: [react()],
    server: {
      port: 4173,
      proxy: {
        "/v1": "http://127.0.0.1:8787",
        "/healthz": "http://127.0.0.1:8787",
      },
    },
    test: {
      environment: "jsdom",
      setupFiles: "./src/test/setup.ts",
    },
  };
});
