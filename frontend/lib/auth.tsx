import React, { createContext, useContext, useMemo, useState } from "react";
import type { UserRole } from "~backend/shared/types";

interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  mustChangePassword?: boolean;
}

interface AuthSession {
  token: string;
  user: AuthUser;
}

interface AuthContextValue {
  session: AuthSession | null;
  user: AuthUser | null;
  token: string | null;
  setSession: (session: AuthSession | null) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const storageKey = "cellqos.auth";

function readStoredSession(): AuthSession | null {
  if (typeof window === "undefined") return null;
  const raw = window.localStorage.getItem(storageKey);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AuthSession;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSessionState] = useState<AuthSession | null>(() => readStoredSession());

  const setSession = (next: AuthSession | null) => {
    setSessionState(next);
    if (typeof window === "undefined") return;
    if (next) {
      window.localStorage.setItem(storageKey, JSON.stringify(next));
    } else {
      window.localStorage.removeItem(storageKey);
    }
  };

  const logout = () => setSession(null);

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      user: session?.user ?? null,
      token: session?.token ?? null,
      setSession,
      logout,
    }),
    [session]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}

function normalizeApiBaseUrl(value: string): string {
  // Allow callers to pass "/" or "http(s)://host/" without creating "//path" URLs.
  const trimmed = value.trim();
  if (!trimmed || trimmed === "/") return "";
  return trimmed.replace(/\/+$/, "");
}

/**
 * API base URL strategy:
 * - Dev default: talk directly to backend on localhost:4000
 * - Prod default: same-origin (nginx proxies API routes to backend)
 * - Override anytime with VITE_API_BASE_URL (e.g. staging / different host)
 */
export const apiBaseUrl = (() => {
  const envValue = import.meta.env.VITE_API_BASE_URL;
  if (typeof envValue === "string" && envValue.trim() !== "") {
    return normalizeApiBaseUrl(envValue);
  }
  // Production: same-origin via nginx, but under /api to avoid route collisions with SPA pages.
  return import.meta.env.PROD ? "/api" : "http://localhost:4000/api";
})();
