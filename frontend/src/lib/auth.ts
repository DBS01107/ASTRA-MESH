const AUTH_TOKEN_KEY = "astra_auth_token";

export interface AuthUser {
  id: number;
  username: string;
  email?: string | null;
  is_active?: boolean;
  created_at?: string | null;
}

export function getAuthToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(AUTH_TOKEN_KEY);
}

export function setAuthToken(token: string): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(AUTH_TOKEN_KEY, token);
}

export function clearAuthToken(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(AUTH_TOKEN_KEY);
}

export function authHeaders(token: string): HeadersInit {
  return {
    Authorization: `Bearer ${token}`,
  };
}

export function withAuth(path: string, token: string): string {
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}auth_token=${encodeURIComponent(token)}`;
}
