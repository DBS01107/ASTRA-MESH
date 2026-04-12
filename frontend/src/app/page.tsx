"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
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
import { useToast } from "@/components/ui/Toast";

export default function Home() {
  const { toast } = useToast();
  const [graph, setGraph] = useState<any>({ nodes: [], edges: [] });
  const [riskHistory, setRiskHistory] = useState<{time: string, threat: number}[]>([]);
  const currentThreatRef = useRef<number>(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);

  const [authLoading, setAuthLoading] = useState(true);
  const [authToken, setAuthTokenState] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);

  const [viewMode, setViewMode] = useState<"graph" | "dashboard">("graph");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [explainCollapsed, setExplainCollapsed] = useState(false);

  // AI pre-fill from graph node → chat
  const [pendingAIMessage, setPendingAIMessage] = useState<string | null>(null);
  const handleAskAI = useCallback((ctx: string) => setPendingAIMessage(ctx), []);

  // Vertical split between graph and terminal (percentage 0-100)
  const [graphPct, setGraphPct] = useState(65);
  const [terminalCollapsed, setTerminalCollapsed] = useState(false);
  const isVResizing = useRef(false);
  const vSplitRef = useRef<HTMLDivElement>(null);

  const handleVPointerDown = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    isVResizing.current = true;
    document.body.style.userSelect = "none";
    document.body.style.cursor = "row-resize";

    const onMove = (ev: PointerEvent) => {
      if (!isVResizing.current || !vSplitRef.current) return;
      const container = vSplitRef.current.parentElement;
      if (!container) return;
      const rect = container.getBoundingClientRect();
      const pct = Math.min(85, Math.max(20, ((ev.clientY - rect.top) / rect.height) * 100));
      setGraphPct(pct);
    };
    const onUp = () => {
      isVResizing.current = false;
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  }, []);

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
    toast("Logged out successfully.", "info");
  };

  const handleSessionTerminated = () => {
    setLogs([]);
    setGraph({ nodes: [], edges: [] });
    resetClientSessionId();
    setSessionId(getClientSessionId());
    toast("Session terminated. New session initialized.", "warning");
  };

  useEffect(() => {
    if (!sessionId || !authToken) return;
    setLogs([]);
    const es = new EventSource(apiUrl(withAuth(withSession("/api/scan/stream", sessionId), authToken)));
    es.onmessage = (e) => { if (e.data?.trim()) setLogs(p => [...p, e.data]); };
    es.addEventListener("complete", (e) => {
      setLogs(p => [...p, `[SERVER] Scan completed (${(e as MessageEvent).data || "completed"}).`]);
      toast("Scan completed successfully.", "success");
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

  // Compute total dynamic threat score organically whenever the graph data changes
  useEffect(() => {
    if (!graph?.nodes) return;
    
    let currentThreat = 0;
    graph.nodes.forEach((n: any) => {
      if (n.type === 'vulnerability' || n.type === 'finding' || n.data?.cvss || n.data?.severity) {
        let risk = n.data?.severity || 'UNKNOWN';
        const cvss = parseFloat(n.data?.cvss);
        if (!n.data?.severity && !isNaN(cvss)) {
          if (cvss >= 9.0) risk = 'CRITICAL';
          else if (cvss >= 7.0) risk = 'HIGH';
          else if (cvss >= 4.0) risk = 'MEDIUM';
          else risk = 'LOW';
        }
        
        const r = risk.toUpperCase();
        if (r === 'CRITICAL') currentThreat += 100;
        if (r === 'HIGH') currentThreat += 75;
        if (r === 'MEDIUM') currentThreat += 30;
        if (r === 'LOW') currentThreat += 10;
        if (r === 'UNKNOWN') currentThreat += 5;
      } else {
        // Base assets contribute tiny fractional points as attack surface width
        currentThreat += 1;
      }
    });

    currentThreatRef.current = currentThreat;
  }, [graph]);

  // Constantly sweep the chart like an EKG monitor to animate the graph over time
  useEffect(() => {
    const interval = setInterval(() => {
      const now = new Date();
      const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
      
      setRiskHistory(prev => {
        const next = [...prev, { time: timeStr, threat: currentThreatRef.current }];
        return next.slice(-30); // Keep last 30 seconds of rolling history
      });
    }, 1000);
    return () => clearInterval(interval);
  }, []);


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
              {/* Attack graph — flex-1 when terminal is collapsed, fixed % when expanded */}
              <div
                id="tour-graph"
                className={`glass relative overflow-hidden bg-black/40 scanline transition-all duration-300 ${
                  terminalCollapsed ? "flex-1 min-h-0" : "flex-shrink-0"
                }`}
                style={terminalCollapsed ? undefined : { height: `${graphPct}%` }}
              >
                <AttackPathGraph initialData={graph} onAskAI={handleAskAI} />
              </div>

              {/* Vertical resize handle — hidden when terminal is collapsed */}
              {!terminalCollapsed && (
                <div
                  ref={vSplitRef}
                  onPointerDown={handleVPointerDown}
                  className="h-2 flex-shrink-0 cursor-row-resize group flex items-center justify-center z-10 relative"
                  title="Resize terminal"
                >
                  <div className="w-[96%] h-[3px] rounded-full transition-colors bg-indigo-500/25 group-hover:bg-cyan-400/50" />
                </div>
              )}

              {/* Terminal — controlled collapse lifted to page level */}
              <ScanTerminal
                logs={logs}
                isCollapsed={terminalCollapsed}
                onCollapse={setTerminalCollapsed}
              />
            </>
          ) : (
            <div className="flex-1 flex flex-col gap-2 p-2 overflow-auto ps-custom">
              {/* Dashboard Analytics View */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                <div className="glass p-4 rounded min-h-[150px]">
                  <Metrics title="Aggregate Threat Horizon" color="#22d3ee" history={riskHistory} />
                </div>
                <div className="glass p-4 rounded min-h-[150px]">
                  <RiskChart nodes={graph.nodes || []} />
                </div>
                <div className="glass p-4 rounded min-h-[150px]">
                  <Metrics title="Network Anomalies" color="#f59e0b" history={riskHistory} />
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-2 flex-1 min-h-[300px]">
                <div className="glass p-4 rounded lg:col-span-2 overflow-hidden flex flex-col">
                  <h3 className="text-sm font-semibold text-cyan-300 mb-3 uppercase tracking-widest">Active Findings</h3>
                  <div className="flex-1 overflow-auto ps-custom">
                    <FindingsTable nodes={graph.nodes || []} />
                  </div>
                </div>
                <div className="glass p-4 rounded overflow-hidden flex flex-col">
                  <h3 className="text-sm font-semibold text-cyan-300 mb-3 uppercase tracking-widest">Chron Feed</h3>
                  <div className="flex-1 overflow-auto ps-custom bg-black/20 rounded p-2">
                    <ActivityFeed logs={logs} />
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
          pendingAIMessage={pendingAIMessage}
          onPendingAIMessageConsumed={() => setPendingAIMessage(null)}
        />
      </ResizablePane>

      <TourGuide currentUser={currentUser} />
    </div>
  );
}
