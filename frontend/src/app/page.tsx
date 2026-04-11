"use client";

import React, { useEffect, useState } from "react";
import AuthPanel from "@/components/auth/AuthPanel";
import AttackPathGraph from "@/components/dashboard/AttackPathGraph";
import ExplainPanel from "@/components/dashboard/ExplainPanel";
import ScanTerminal from "@/components/dashboard/ScanTerminal";
import Sidebar from "@/components/layout/Sidebar";
import TourGuide from "@/components/dashboard/TourGuide";
import { apiUrl } from "@/lib/api";
import { authHeaders, AuthUser, clearAuthToken, getAuthToken, setAuthToken, withAuth } from "@/lib/auth";
import { getClientSessionId, resetClientSessionId, withSession } from "@/lib/session";

export default function Home() {
  const [graph, setGraph] = useState<any>({ nodes: [], edges: [] });
  const [logs, setLogs] = useState<string[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);

  const [authLoading, setAuthLoading] = useState(true);
  const [authToken, setAuthTokenState] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);

  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [explainCollapsed, setExplainCollapsed] = useState(false);
  const [sidebarWidth, setSidebarWidth] = useState(320);
  const [explainWidth, setExplainWidth] = useState(320);
  const [resizingSide, setResizingSide] = useState<"left" | "right" | null>(null);

  useEffect(() => {
    const bootstrapAuth = async () => {
      const token = getAuthToken();
      if (!token) { setAuthLoading(false); return; }
      try {
        const res = await fetch(apiUrl("/api/auth/me"), { headers: authHeaders(token) });
        if (!res.ok) throw new Error("Session expired");
        const payload = await res.json();
        if (!payload.user) throw new Error("Invalid auth payload");
        setAuthTokenState(token);
        setCurrentUser(payload.user as AuthUser);
        resetClientSessionId();
        setSessionId(getClientSessionId());
      } catch {
        clearAuthToken();
        setAuthTokenState(null);
        setCurrentUser(null);
      } finally {
        setAuthLoading(false);
      }
    };
    bootstrapAuth();
  }, []);

  const handleAuthenticated = (token: string, user: AuthUser) => {
    setAuthToken(token);
    setAuthTokenState(token);
    setCurrentUser(user);
    setLogs([]);
    setGraph({ nodes: [], edges: [] });
    resetClientSessionId();
    setSessionId(getClientSessionId());
    setAuthLoading(false);
  };

  const handleLogout = () => {
    clearAuthToken();
    setAuthTokenState(null);
    setCurrentUser(null);
    setLogs([]);
    setGraph({ nodes: [], edges: [] });
    setSessionId(null);
    resetClientSessionId();
  };

  const handleSessionTerminated = () => {
    setLogs([]);
    setGraph({ nodes: [], edges: [] });
    resetClientSessionId();
    setSessionId(getClientSessionId());
  };

  useEffect(() => {
    if (!resizingSide) return;

    const handlePointerMove = (event: PointerEvent) => {
      if (resizingSide === "left") {
        const nextWidth = Math.min(420, Math.max(240, event.clientX - 8));
        setSidebarWidth(nextWidth);
        return;
      }
      const nextWidth = Math.min(420, Math.max(240, window.innerWidth - event.clientX - 8));
      setExplainWidth(nextWidth);
    };

    const stopResizing = () => setResizingSide(null);

    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", stopResizing);
    window.addEventListener("pointercancel", stopResizing);
    document.body.style.userSelect = "none";
    document.body.style.cursor = "col-resize";

    return () => {
      window.removeEventListener("pointermove", handlePointerMove);
      window.removeEventListener("pointerup", stopResizing);
      window.removeEventListener("pointercancel", stopResizing);
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
    };
  }, [resizingSide]);

  useEffect(() => {
    if (!sessionId || !authToken) return;
    setLogs([]);
    const es = new EventSource(apiUrl(withAuth(withSession("/api/scan/stream", sessionId), authToken)));
    es.onmessage = (e) => { if (e.data?.trim()) setLogs(p => [...p, e.data]); };
    es.addEventListener("complete", (e) => {
      setLogs(p => [...p, `[SERVER] Scan completed (${(e as MessageEvent).data || "completed"}).`]);
    });
    es.onerror = (err) => { if (es.readyState !== EventSource.CLOSED) console.error("SSE Error:", err); };
    return () => es.close();
  }, [sessionId, authToken]);

  useEffect(() => {
    if (!sessionId || !authToken) return;
    let timer: any;
    const fetchData = async () => {
      try {
        const res = await fetch(apiUrl(withSession("/graph", sessionId)), { headers: authHeaders(authToken) });
        if (res.status === 401) { handleLogout(); return; }
        setGraph(await res.json());
      } catch { console.error("Backend offline - Retrying..."); }
      finally { timer = setTimeout(fetchData, 3000); }
    };
    fetchData();
    return () => clearTimeout(timer);
  }, [sessionId, authToken]);

  if (authLoading) {
    return (
      <div className="h-screen w-screen bg-[#02030a] flex items-center justify-center font-mono">
        <div className="text-cyan-400 animate-pulse tracking-[1em] text-xs uppercase">Validating_Identity...</div>
      </div>
    );
  }

  if (!currentUser || !authToken) return <AuthPanel onAuthenticated={handleAuthenticated} />;

  if (!sessionId) {
    return (
      <div className="h-screen w-screen bg-[#02030a] flex items-center justify-center font-mono">
        <div className="text-cyan-400 animate-pulse tracking-[1em] text-xs uppercase">Initializing_Astra_Core...</div>
      </div>
    );
  }

  return (
    <div className="h-screen w-screen bg-[#02030a] text-[#eaeaf0] flex overflow-hidden cyber-grid p-2">
      {/* Left sidebar */}
      <Sidebar
        sessionId={sessionId}
        authToken={authToken}
        currentUser={currentUser}
        onLogout={handleLogout}
        onCollapse={setSidebarCollapsed}
        width={sidebarWidth}
        onSessionTerminated={handleSessionTerminated}
      />

      {!sidebarCollapsed && (
        <div
          onPointerDown={(event) => {
            event.preventDefault();
            setResizingSide("left");
          }}
          className="w-2 flex-shrink-0 cursor-col-resize group flex items-center justify-center"
          title="Resize left panel"
        >
          <div className={`h-[96%] w-[3px] rounded-full transition-colors ${resizingSide === "left" ? "bg-cyan-400/80" : "bg-indigo-500/25 group-hover:bg-cyan-400/50"}`} />
        </div>
      )}

      {/* Main content */}
      <main className="flex-1 flex flex-col gap-2 overflow-hidden min-w-0 px-1">
        {/* Topbar */}
        <header id="tour-topbar" className="h-10 glass flex items-center justify-between px-5 border-b border-indigo-500/20 flex-shrink-0">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 bg-cyan-400 rounded-full shadow-[0_0_8px_#22d3ee] animate-pulse" />
            <span className="text-[10px] font-black tracking-widest text-white uppercase">ASTRA_OS // SOC_COMMAND</span>
          </div>
          <div className="text-[10px] text-cyan-400/60 font-mono uppercase tracking-wider">
            user: {currentUser.username}
          </div>
        </header>

        {/* Graph + Terminal */}
        <div className="flex-1 flex flex-col gap-2 overflow-hidden min-h-0">
          {/* Attack graph — takes remaining space */}
          <div id="tour-graph" className="flex-1 glass relative overflow-hidden bg-black/40 scanline min-h-0">
            <AttackPathGraph initialData={graph} />
          </div>

          {/* Terminal — collapsible, sits below graph */}
          <div id="tour-terminal">
            <ScanTerminal logs={logs} />
          </div>
        </div>
      </main>

      {!explainCollapsed && (
        <div
          onPointerDown={(event) => {
            event.preventDefault();
            setResizingSide("right");
          }}
          className="w-2 flex-shrink-0 cursor-col-resize group flex items-center justify-center"
          title="Resize right panel"
        >
          <div className={`h-[96%] w-[3px] rounded-full transition-colors ${resizingSide === "right" ? "bg-cyan-400/80" : "bg-indigo-500/25 group-hover:bg-cyan-400/50"}`} />
        </div>
      )}

      {/* Right panel */}
      <ExplainPanel
        logs={logs}
        sessionId={sessionId}
        authToken={authToken}
        onCollapse={setExplainCollapsed}
        width={explainWidth}
      />

      <TourGuide currentUser={currentUser} />
    </div>
  );
}
