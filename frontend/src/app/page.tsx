"use client";

import React, { useEffect, useState } from "react";
import AuthPanel from "@/components/auth/AuthPanel";
import AttackPathGraph from "@/components/dashboard/AttackPathGraph";
import ExplainPanel from "@/components/dashboard/ExplainPanel";
import ScanTerminal from "@/components/dashboard/ScanTerminal";
import Sidebar from "@/components/layout/Sidebar";
import FindingsTable from "@/components/dashboard/FindingsTable";
import Metrics from "@/components/dashboard/Metrics";
import RiskChart from "@/components/dashboard/RiskChart";
import ActivityFeed from "@/components/dashboard/ActivityFeed";
import { apiUrl } from "@/lib/api";
import { authHeaders, AuthUser, clearAuthToken, getAuthToken, setAuthToken, withAuth } from "@/lib/auth";
import { getClientSessionId, resetClientSessionId, withSession } from "@/lib/session";

import ResizablePane from "@/components/ui/ResizablePane";
import TourGuide from "@/components/dashboard/TourGuide";

export default function Home() {
  const [graph, setGraph] = useState<any>({ nodes: [], edges: [] });
  const [logs, setLogs] = useState<string[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);

  const [authLoading, setAuthLoading] = useState(true);
  const [authToken, setAuthTokenState] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);

  const [viewMode, setViewMode] = useState<"graph" | "dashboard">("graph");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [explainCollapsed, setExplainCollapsed] = useState(false);

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
      <ResizablePane minWidth={240} maxWidth={420} initialWidth={320} side="left" isCollapsed={sidebarCollapsed}>
        <Sidebar
          sessionId={sessionId}
          authToken={authToken}
          currentUser={currentUser}
          onLogout={handleLogout}
          onCollapse={setSidebarCollapsed}
          onSessionTerminated={handleSessionTerminated}
        />
      </ResizablePane>

      {/* Main content */}
      <main className="flex-1 flex flex-col gap-2 overflow-hidden min-w-0 px-1">
        {/* Topbar */}
        <header id="tour-topbar" className="h-10 glass flex items-center justify-between px-5 border-b border-indigo-500/20 flex-shrink-0">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 bg-cyan-400 rounded-full shadow-[0_0_8px_#22d3ee] animate-pulse" />
              <span className="text-[10px] font-black tracking-widest text-white uppercase">ASTRA_OS // SOC_COMMAND</span>
            </div>
            
            {/* View Toggles */}
            <div className="flex items-center bg-black/40 border border-cyan-500/20 rounded p-0.5 ml-4">
              <button 
                onClick={() => setViewMode("graph")}
                className={`px-3 py-1 text-[10px] font-bold tracking-widest uppercase rounded transition-colors ${viewMode === "graph" ? "bg-cyan-500/20 text-cyan-300" : "text-slate-400 hover:text-white"}`}
              >
                Graph Trace
              </button>
              <button 
                onClick={() => setViewMode("dashboard")}
                className={`px-3 py-1 text-[10px] font-bold tracking-widest uppercase rounded transition-colors ${viewMode === "dashboard" ? "bg-cyan-500/20 text-cyan-300" : "text-slate-400 hover:text-white"}`}
              >
                Analytics
              </button>
            </div>
          </div>
          <div className="text-[10px] text-cyan-400/60 font-mono uppercase tracking-wider">
            user: {currentUser.username}
          </div>
        </header>

        {/* Content Area */}
        <div className="flex-1 flex flex-col gap-2 overflow-hidden min-h-0">
          {viewMode === "graph" ? (
            <>
              {/* Attack graph — takes remaining space */}
              <div id="tour-graph" className="flex-1 glass relative overflow-hidden bg-black/40 scanline min-h-0">
                <AttackPathGraph initialData={graph} />
              </div>

              {/* Terminal — collapsible, sits below graph */}
              <div id="tour-terminal">
                <ScanTerminal logs={logs} />
              </div>
            </>
          ) : (
            <div className="flex-1 flex flex-col gap-2 p-2 overflow-auto ps-custom">
              {/* Dashboard Analytics View */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                <div className="glass p-4 rounded min-h-[150px]">
                  <Metrics title="Ingres Risk Delta" color="#22d3ee" />
                </div>
                <div className="glass p-4 rounded min-h-[150px]">
                  <RiskChart />
                </div>
                <div className="glass p-4 rounded min-h-[150px]">
                  <Metrics title="Network Anomalies" color="#f59e0b" />
                </div>
              </div>
              
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-2 flex-1 min-h-[300px]">
                <div className="glass p-4 rounded lg:col-span-2 overflow-hidden flex flex-col">
                  <h3 className="text-sm font-semibold text-cyan-300 mb-3 uppercase tracking-widest">Active Findings</h3>
                  <div className="flex-1 overflow-auto ps-custom">
                    <FindingsTable />
                  </div>
                </div>
                <div className="glass p-4 rounded overflow-hidden flex flex-col">
                  <h3 className="text-sm font-semibold text-cyan-300 mb-3 uppercase tracking-widest">Chron Feed</h3>
                  <div className="flex-1 overflow-auto ps-custom bg-black/20 rounded p-2">
                    <ActivityFeed />
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Right panel */}
      <ResizablePane minWidth={240} maxWidth={420} initialWidth={320} side="right" isCollapsed={explainCollapsed}>
        <ExplainPanel
          logs={logs}
          sessionId={sessionId}
          authToken={authToken}
          onCollapse={setExplainCollapsed}
        />
      </ResizablePane>

      <TourGuide currentUser={currentUser} />
    </div>
  );
}
