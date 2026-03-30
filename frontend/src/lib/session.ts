const SESSION_STORAGE_KEY = "astra_session_id";
const SESSION_OWNER_KEY = "astra_session_owner";

function generateSessionId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  const randomPart = Math.random().toString(36).slice(2, 10);
  return `sess-${Date.now()}-${randomPart}`;
}

export function getClientSessionId(): string {
  if (typeof window === "undefined") {
    return "default";
  }

  const tabOwner = String(window.performance?.timeOrigin || Date.now());
  const existing = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
  const owner = window.sessionStorage.getItem(SESSION_OWNER_KEY);
  if (existing && owner === tabOwner) {
    return existing;
  }

  const created = generateSessionId();
  window.sessionStorage.setItem(SESSION_STORAGE_KEY, created);
  window.sessionStorage.setItem(SESSION_OWNER_KEY, tabOwner);
  return created;
}

export function withSession(path: string, sessionId: string): string {
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}session_id=${encodeURIComponent(sessionId)}`;
}

export function resetClientSessionId(): void {
  if (typeof window === "undefined") {
    return;
  }
  window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
  window.sessionStorage.removeItem(SESSION_OWNER_KEY);
}
