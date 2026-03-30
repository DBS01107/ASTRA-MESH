const DEFAULT_API_BASE_URL = "http://localhost:8000";
const LOCALHOST_HOSTNAMES = new Set(["localhost", "127.0.0.1", "0.0.0.0"]);

function trimTrailingSlashes(value: string): string {
  return value.replace(/\/+$/, "");
}

function resolveApiBaseUrl(): string {
  const configured = (process.env.NEXT_PUBLIC_API_URL || "").trim();
  if (!configured) {
    if (typeof window !== "undefined") {
      const host = window.location.hostname || "localhost";
      const protocol = window.location.protocol === "https:" ? "https:" : "http:";
      return trimTrailingSlashes(`${protocol}//${host}:8000`);
    }
    return DEFAULT_API_BASE_URL;
  }

  if (typeof window === "undefined") {
    return trimTrailingSlashes(configured);
  }

  try {
    const parsed = new URL(configured);
    const browserHost = window.location.hostname || "localhost";

    // If build-time config points to localhost, adapt to the browser host for remote clients.
    if (LOCALHOST_HOSTNAMES.has(parsed.hostname) && !LOCALHOST_HOSTNAMES.has(browserHost)) {
      parsed.hostname = browserHost;
      if (!parsed.port) {
        parsed.port = "8000";
      }
      if (window.location.protocol === "https:" && parsed.protocol === "http:") {
        parsed.protocol = "https:";
      }
      return trimTrailingSlashes(parsed.toString());
    }
  } catch {
    // Keep configured value when it is not a valid absolute URL.
  }

  return trimTrailingSlashes(configured);
}

const API_BASE_URL = resolveApiBaseUrl();

export function apiUrl(path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${API_BASE_URL}${normalizedPath}`;
}
