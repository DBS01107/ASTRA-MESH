"use client";
import React, { useState, useEffect } from "react";
import { apiUrl } from "@/lib/api";
import { authHeaders, AuthUser } from "@/lib/auth";
import { withSession } from "@/lib/session";
import {
  ChevronLeft, ChevronRight, Target, Cpu, Shield,
  BarChart2, Download, LogOut, User, Layers, Square, Power
} from "lucide-react";
import Scrollable from "@/components/ui/Scrollable";
import { useToast } from "@/components/ui/Toast";

interface Scanner { name: string; enabled: boolean; }
interface CheckCoverageSummary { total: number; detected: number; covered: number; uncovered: number; }
interface CheckCoverageGroup { id: string; label: string; total: number; detected: number; covered: number; uncovered: number; }
interface CheckCoverageItem { id: string; name: string; group: string; group_label: string; status: "detected" | "covered" | "uncovered"; tools: string[]; matched_tools: string[]; }
interface CheckCoverageResponse { summary: CheckCoverageSummary; groups: CheckCoverageGroup[]; checks: CheckCoverageItem[]; }
interface SidebarProps {
  sessionId: string;
  authToken: string;
  currentUser: AuthUser;
  onLogout: () => void;
  onCollapse?: (collapsed: boolean) => void;
  width?: number;
  onSessionTerminated?: () => void;
}
interface ScanSummary { session_id: string; target: string; status: string; finding_count: number; updated_at?: string; }

export default function Sidebar({ sessionId, authToken, currentUser, onLogout, onCollapse, width = 320, onSessionTerminated }: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("dynamic");
  const [loading, setLoading] = useState(false);
  const [stopLoading, setStopLoading] = useState(false);
  const [terminateLoading, setTerminateLoading] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [scanners, setScanners] = useState<Scanner[]>([]);
  const [selectedScanners, setSelectedScanners] = useState<Set<string>>(new Set());
  const [checkCoverage, setCheckCoverage] = useState<CheckCoverageResponse | null>(null);
  const [coverageLoading, setCoverageLoading] = useState(false);
  const [recentScans, setRecentScans] = useState<ScanSummary[]>([]);

  const toggle = () => {
    const next = !collapsed;
    setCollapsed(next);
    onCollapse?.(next);
  };

  const { toast } = useToast();

  useEffect(() => {
    fetch(apiUrl("/api/scanners"), { headers: authHeaders(authToken) })
      .then(r => r.json())
      .then((data: Scanner[]) => {
        setScanners(data);
        setSelectedScanners(new Set(data.map(s => s.name)));
      })
      .catch(() => {});
  }, [authToken]);

  const selectedScannerCsv = Array.from(selectedScanners).sort().join(",");

  useEffect(() => {
    if (!sessionId) return;
    setCoverageLoading(true);
    fetch(apiUrl(`/api/checks/coverage?scanners=${encodeURIComponent(selectedScannerCsv || "__none__")}&session_id=${encodeURIComponent(sessionId)}`), { headers: authHeaders(authToken) })
      .then(r => r.json())
      .then((data: CheckCoverageResponse) => setCheckCoverage(data))
      .catch(() => {})
      .finally(() => setCoverageLoading(false));
  }, [selectedScannerCsv, sessionId, authToken]);

  useEffect(() => {
    if (!authToken) return;
    const load = async () => {
      try {
        const res = await fetch(apiUrl("/api/scans?limit=8"), { headers: authHeaders(authToken) });
        if (!res.ok) return;
        const data = await res.json();
        setRecentScans((data.scans || []) as ScanSummary[]);
      } catch {}
    };
    load();
    const iv = setInterval(load, 8000);
    return () => clearInterval(iv);
  }, [authToken]);

  const toggleScanner = (name: string) => {
    setSelectedScanners(prev => {
      const s = new Set(prev);
      s.has(name) ? s.delete(name) : s.add(name);
      return s;
    });
  };

  const handleDownloadReport = async () => {
    if (!sessionId || reportLoading) return;
    setReportLoading(true);
    try {
      const res = await fetch(apiUrl(withSession("/api/report/pdf", sessionId)), { headers: authHeaders(authToken) });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || "Report generation failed.");
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      const match = (res.headers.get("Content-Disposition") || "").match(/filename=\\"?([^\\";]+)\\"?/i);
      a.href = url; a.download = match?.[1] || "astra-report.pdf";
      document.body.appendChild(a); a.click(); a.remove();
      window.URL.revokeObjectURL(url);
      toast("Report downloaded successfully.", "success");
    } catch (err: any) {
      toast(err?.message || "Unable to download PDF report.", "error");
    } finally {
      setReportLoading(false);
    }
  };

  const handleRun = async () => {
    if (!target || !sessionId) return;
    setLoading(true);
    try {
      const res = await fetch(apiUrl("/api/scan"), {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders(authToken) },
        body: JSON.stringify({ target, mode, scanners: Array.from(selectedScanners).join(","), session_id: sessionId }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || data.error || "Failed to initialize scan.");
      toast(data.message || "Scan started.", "success");
    } catch (err: any) {
      toast(err?.message || "Failed to reach scanner backend.", "error");
    } finally {
      setLoading(false);
    }
  };

  const handleStopScan = async () => {
    if (!sessionId || !authToken || stopLoading) return;
    setStopLoading(true);
    try {
      const res = await fetch(apiUrl(withSession("/api/scan/stop", sessionId)), {
        method: "POST",
        headers: authHeaders(authToken),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || data.message || "Unable to stop scan.");
      toast(data.message || "Scan stop requested.", "warning");
    } catch (err: any) {
      toast(err?.message || "Unable to stop scan.", "error");
    } finally {
      setStopLoading(false);
    }
  };

  const handleTerminateSession = async () => {
    if (!sessionId || !authToken || terminateLoading) return;
    const confirmed = window.confirm("Terminate this session and clear its live state?");
    if (!confirmed) return;

    setTerminateLoading(true);
    try {
      const res = await fetch(apiUrl(withSession("/api/session", sessionId)), {
        method: "DELETE",
        headers: authHeaders(authToken),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || data.message || "Unable to terminate session.");
      setTarget("");
      setCheckCoverage(null);
      setRecentScans(prev => prev.filter(scan => scan.session_id !== sessionId));
      toast(data.message || "Session terminated.", "warning");
      onSessionTerminated?.();
    } catch (err: any) {
      toast(err?.message || "Unable to terminate session.", "error");
    } finally {
      setTerminateLoading(false);
    }
  };

  const statusColor = (status: string) => {
    if (status === "running") return "text-amber-400";
    if (status === "complete") return "text-emerald-400";
    if (status === "completed") return "text-emerald-400";
    if (status === "stopped") return "text-rose-300";
    if (status === "failed") return "text-rose-400";
    if (status === "error") return "text-rose-400";
    return "text-slate-400";
  };

  /* ── Collapsed rail ── */
  if (collapsed) {
    return (
      <div className="relative flex flex-col items-center py-4 gap-4 w-14 glass border-r border-indigo-500/20 flex-shrink-0 transition-all duration-300">
        <button onClick={toggle} className="p-1.5 rounded hover:bg-indigo-500/20 text-cyan-400 transition-colors" title="Expand panel">
          <ChevronRight size={16} />
        </button>
        <div className="w-px h-4 bg-indigo-500/20" />
        <button title="Target" className="p-2 rounded hover:bg-indigo-500/20 text-slate-400 hover:text-cyan-400 transition-colors"><Target size={15} /></button>
        <button title="Modules" className="p-2 rounded hover:bg-indigo-500/20 text-slate-400 hover:text-cyan-400 transition-colors"><Cpu size={15} /></button>
        <button title="Coverage" className="p-2 rounded hover:bg-indigo-500/20 text-slate-400 hover:text-cyan-400 transition-colors"><Shield size={15} /></button>
        <button title="History" className="p-2 rounded hover:bg-indigo-500/20 text-slate-400 hover:text-cyan-400 transition-colors"><BarChart2 size={15} /></button>
        <div className="flex-1" />
        <button
          onClick={handleStopScan}
          title="Stop Scan"
          disabled={stopLoading || !sessionId || !authToken}
          className="p-2 rounded hover:bg-amber-500/20 text-amber-400/70 hover:text-amber-400 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <Square size={15} />
        </button>
        <button
          onClick={handleTerminateSession}
          title="Terminate Session"
          disabled={terminateLoading || !sessionId || !authToken}
          className="p-2 rounded hover:bg-rose-500/20 text-rose-400/70 hover:text-rose-400 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <Power size={15} />
        </button>
        <button onClick={handleDownloadReport} title="Download Report" disabled={reportLoading} className="p-2 rounded hover:bg-emerald-500/20 text-emerald-400/70 hover:text-emerald-400 transition-colors"><Download size={15} /></button>
        <button onClick={onLogout} title="Logout" className="p-2 rounded hover:bg-rose-500/20 text-rose-400/70 hover:text-rose-400 transition-colors"><LogOut size={15} /></button>
      </div>
    );
  }

  /* ── Expanded panel ── */
  return (
    <div
      className="relative glass flex flex-col h-full border-r border-indigo-500/20 flex-shrink-0 transition-all duration-300 overflow-hidden"
      style={{ width }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-indigo-500/15 flex-shrink-0">
        <div className="flex items-center gap-2">
          <Layers size={14} className="text-cyan-400" />
          <span className="text-[10px] font-black tracking-widest text-cyan-400 uppercase">ASTRA // CONFIG</span>
        </div>
        <button onClick={toggle} className="p-1 rounded hover:bg-indigo-500/20 text-slate-400 hover:text-cyan-400 transition-colors">
          <ChevronLeft size={15} />
        </button>
      </div>

      {/* Scrollable body */}
      <Scrollable className="flex-1 px-5 py-4 space-y-5 custom-scrollbar">

        {/* Target */}
        <div id="tour-target">
          <label className="flex items-center gap-1.5 text-[10px] text-slate-400 uppercase tracking-widest mb-1.5">
            <Target size={11} className="text-cyan-400" /> Target
          </label>
          <input
            value={target}
            onChange={e => setTarget(e.target.value)}
            className="w-full bg-slate-900/60 border border-indigo-500/25 rounded px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:border-cyan-400/60 focus:outline-none transition-colors"
            placeholder="scanme.nmap.org"
          />
        </div>

        {/* Mode */}
        <div>
          <p className="text-[10px] text-slate-400 uppercase tracking-widest mb-2 flex items-center gap-1.5">
            <Cpu size={11} className="text-cyan-400" /> Mode
          </p>
          <div className="flex gap-3">
            {["dynamic", "static"].map(m => (
              <button
                key={m}
                onClick={() => setMode(m)}
                className={`flex-1 py-1.5 text-[10px] uppercase tracking-wider rounded border transition-all ${mode === m
                  ? "bg-cyan-400/15 border-cyan-400/60 text-cyan-300 font-bold"
                  : "border-slate-700 text-slate-500 hover:border-slate-500 hover:text-slate-300"}`}
              >
                {m}
              </button>
            ))}
          </div>
        </div>

        {/* Modules */}
        <div id="tour-modules">
          <p className="text-[10px] text-slate-400 uppercase tracking-widest mb-2 flex items-center gap-1.5">
            <Shield size={11} className="text-cyan-400" /> Modules
          </p>
          <Scrollable className="space-y-0.5 bg-slate-900/40 rounded border border-indigo-500/15 p-2 h-40">
            {scanners.length === 0 ? (
              <div className="text-[9px] text-slate-600 italic px-1">Connecting to module registry...</div>
            ) : (
              scanners.map(s => (
                <label key={s.name} className="flex items-center gap-2 cursor-pointer hover:bg-indigo-500/10 px-2 py-1 rounded transition-colors">
                  <input type="checkbox" checked={selectedScanners.has(s.name)} onChange={() => toggleScanner(s.name)} className="accent-cyan-400 w-3 h-3" />
                  <span className="text-[10px] font-mono text-slate-300">{s.name}</span>
                </label>
              ))
            )}
          </Scrollable>
          <div className="mt-1.5 flex justify-between text-[9px] text-slate-600 px-1">
            <span>{selectedScanners.size} / {scanners.length} selected</span>
          </div>
        </div>

        {/* Coverage */}
        <div>
          <p className="text-[10px] text-slate-400 uppercase tracking-widest mb-2 flex items-center gap-1.5">
            <BarChart2 size={11} className="text-cyan-400" /> Coverage
          </p>
          <div className="bg-slate-900/40 rounded border border-indigo-500/15 p-3 text-[9px] font-mono space-y-2">
            {coverageLoading || !checkCoverage ? (
              <div className="text-slate-600 italic">Calculating coverage...</div>
            ) : (
              <>
                <div className="grid grid-cols-3 gap-2">
                  {[
                    { label: "Total", val: checkCoverage.summary.total, color: "text-cyan-400 border-cyan-400/20" },
                    { label: "Detected", val: checkCoverage.summary.detected, color: "text-emerald-400 border-emerald-400/20" },
                    { label: "Covered", val: checkCoverage.summary.covered, color: "text-amber-400 border-amber-400/20" },
                  ].map(({ label, val, color }) => (
                    <div key={label} className={`border rounded p-2 ${color}`}>
                      <div className="text-[8px] opacity-70 uppercase">{label}</div>
                      <div className="text-sm font-bold">{val}</div>
                    </div>
                  ))}
                </div>
                <div className="space-y-1 pt-1">
                  {checkCoverage.groups.map(g => (
                    <div key={g.id} className="flex justify-between border-b border-white/5 pb-1">
                      <span className="text-slate-400 truncate">{g.label}</span>
                      <span className="text-cyan-400 ml-2 flex-shrink-0">{g.detected + g.covered}/{g.total}</span>
                    </div>
                  ))}
                </div>
                {checkCoverage.summary.uncovered > 0 ? (
                  <div className="pt-1">
                    <div className="text-rose-400/80 uppercase tracking-wider mb-1 text-[8px]">Uncovered</div>
                    {checkCoverage.checks.filter(i => i.status === "uncovered").slice(0, 4).map(i => (
                      <div key={i.id} className="text-rose-300/70 truncate">— {i.name}</div>
                    ))}
                  </div>
                ) : (
                  <div className="text-emerald-400/80 text-[8px] uppercase">All checks mapped.</div>
                )}
              </>
            )}
          </div>
        </div>

        {/* Recent scans */}
        <div>
          <p className="text-[10px] text-slate-400 uppercase tracking-widest mb-2 flex items-center gap-1.5">
            <User size={11} className="text-cyan-400" /> Recent Scans
          </p>
          <Scrollable className="bg-slate-900/40 rounded border border-indigo-500/15 p-2 space-y-1 h-28">
            {recentScans.length === 0 ? (
              <div className="text-[9px] text-slate-600 italic px-1">No scans yet.</div>
            ) : (
              recentScans.map(scan => (
                <div key={scan.session_id} className="flex justify-between items-center px-1 py-0.5 border-b border-white/5">
                  <span className="text-[9px] text-slate-400 truncate max-w-[150px]" title={scan.target}>{scan.target || scan.session_id}</span>
                  <span className={`text-[9px] font-mono ml-2 flex-shrink-0 ${statusColor(scan.status)}`}>{scan.status}</span>
                </div>
              ))
            )}
          </Scrollable>
        </div>
      </Scrollable>

      {/* Footer actions */}
      <div id="tour-actions" className="px-5 py-4 space-y-2 border-t border-indigo-500/15 flex-shrink-0">
        <button
          onClick={handleRun}
          disabled={loading || !sessionId || !target || selectedScanners.size === 0 || !authToken}
          className="w-full py-2.5 rounded text-[10px] uppercase tracking-widest font-bold bg-cyan-500/15 border border-cyan-400/50 text-cyan-300 hover:bg-cyan-400/25 hover:border-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {loading ? "Initializing..." : "Scan Now"}
        </button>
        <button
          onClick={handleStopScan}
          disabled={stopLoading || !sessionId || !authToken}
          className="w-full py-2 rounded text-[10px] uppercase tracking-widest font-bold border border-amber-500/40 text-amber-300/85 hover:bg-amber-500/15 hover:text-amber-200 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {stopLoading ? "Stopping..." : "Stop Scan"}
        </button>
        <button
          onClick={handleTerminateSession}
          disabled={terminateLoading || !sessionId || !authToken}
          className="w-full py-2 rounded text-[10px] uppercase tracking-widest font-bold border border-rose-500/40 text-rose-400/80 hover:bg-rose-500/20 hover:text-rose-300 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {terminateLoading ? "Terminating..." : "Terminate Session"}
        </button>
        <button
          onClick={handleDownloadReport}
          disabled={reportLoading || !sessionId || !authToken}
          className="w-full py-2 rounded text-[10px] uppercase tracking-widest font-bold border border-emerald-500/40 text-emerald-400/80 hover:bg-emerald-500/15 hover:text-emerald-300 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {reportLoading ? "Building..." : "↓ Download Report"}
        </button>
        <button
          onClick={onLogout}
          className="w-full py-2 rounded text-[10px] uppercase tracking-widest font-bold border border-rose-500/30 text-rose-400/70 hover:bg-rose-500/15 hover:text-rose-300 transition-all"
        >
          Logout · {currentUser.username}
        </button>
      </div>
    </div>
  );
}
