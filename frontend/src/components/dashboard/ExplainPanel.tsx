"use client";
import { useState, useEffect } from "react";
import { Brain, MessageSquare, ChevronRight, ChevronLeft } from "lucide-react";
import AIChat from "./AIChat";
import Scrollable from "@/components/ui/Scrollable";
import { apiUrl } from "@/lib/api";
import { authHeaders } from "@/lib/auth";
import { withSession } from "@/lib/session";

interface ExplainPanelProps {
  logs: string[];
  sessionId: string;
  authToken: string;
  onCollapse?: (collapsed: boolean) => void;
  width?: number;
}

export default function ExplainPanel({ logs, sessionId, authToken, onCollapse, width = 320 }: ExplainPanelProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [activeTab, setActiveTab] = useState<"reasoning" | "chat">("reasoning");
  const [reasoning, setReasoning] = useState("Waiting for active scan analysis...");

  const toggle = () => {
    const next = !collapsed;
    setCollapsed(next);
    onCollapse?.(next);
  };

  useEffect(() => {
    if (!sessionId) return;
    const fetch_ = async () => {
      try {
        const res = await fetch(apiUrl(withSession("/ai/reasoning", sessionId)), { headers: authHeaders(authToken) });
        const data = await res.json();
        if (data.reasoning) setReasoning(data.reasoning);
      } catch {}
    };
    fetch_();
    const iv = setInterval(fetch_, 3000);
    return () => clearInterval(iv);
  }, [sessionId, authToken]);

  /* ── Collapsed rail ── */
  if (collapsed) {
    return (
      <div className="flex flex-col items-center py-4 gap-4 w-14 glass border-l border-indigo-500/20 flex-shrink-0 transition-all duration-300 h-full">
        <button onClick={toggle} className="p-1.5 rounded hover:bg-indigo-500/20 text-cyan-400 transition-colors" title="Expand panel">
          <ChevronLeft size={16} />
        </button>
        <div className="w-px h-4 bg-indigo-500/20" />
        <button
          onClick={() => { setActiveTab("reasoning"); toggle(); }}
          title="Reasoning Engine"
          className="p-2 rounded hover:bg-indigo-500/20 text-slate-400 hover:text-cyan-400 transition-colors"
        >
          <Brain size={15} />
        </button>
        <button
          onClick={() => { setActiveTab("chat"); toggle(); }}
          title="AI Chat"
          className="p-2 rounded hover:bg-indigo-500/20 text-slate-400 hover:text-cyan-400 transition-colors"
        >
          <MessageSquare size={15} />
        </button>
      </div>
    );
  }

  /* ── Expanded panel ── */
  return (
    <div
      id="tour-explain"
      className="glass h-full flex flex-col border-l border-indigo-500/20 flex-shrink-0 transition-all duration-300 overflow-hidden"
      style={{ width }}
    >
      {/* Tabs + collapse */}
      <div className="flex items-center border-b border-indigo-500/15 flex-shrink-0">
        <button
          onClick={() => setActiveTab("reasoning")}
          className={`flex-1 flex items-center justify-center gap-1.5 py-3 text-[10px] font-bold tracking-widest uppercase transition-colors ${
            activeTab === "reasoning"
              ? "text-cyan-400 border-b-2 border-cyan-400 bg-cyan-400/10"
              : "text-slate-500 hover:text-slate-300 hover:bg-white/5"
          }`}
        >
          <Brain size={13} /> Reasoning
        </button>
        <button
          onClick={() => setActiveTab("chat")}
          className={`flex-1 flex items-center justify-center gap-1.5 py-3 text-[10px] font-bold tracking-widest uppercase transition-colors ${
            activeTab === "chat"
              ? "text-cyan-400 border-b-2 border-cyan-400 bg-cyan-400/10"
              : "text-slate-500 hover:text-slate-300 hover:bg-white/5"
          }`}
        >
          <MessageSquare size={13} /> AI Chat
        </button>
        <button onClick={toggle} className="px-3 py-3 text-slate-500 hover:text-cyan-400 transition-colors flex-shrink-0">
          <ChevronRight size={15} />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-4">
        {activeTab === "reasoning" ? (
          <div className="h-full flex flex-col gap-3">
            <Scrollable className="flex-1 bg-slate-900/50 rounded border border-indigo-500/15 p-4 text-xs text-slate-300 leading-relaxed font-mono">
              {reasoning}
            </Scrollable>
            <button className="w-full py-2.5 rounded bg-cyan-500/15 border border-cyan-400/50 text-cyan-300 text-[10px] font-bold uppercase tracking-widest hover:bg-cyan-400/25 transition-all flex-shrink-0">
              Execute Remediation
            </button>
          </div>
        ) : (
          <AIChat logs={logs} sessionId={sessionId} authToken={authToken} />
        )}
      </div>
    </div>
  );
}
