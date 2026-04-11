"use client";
import React, { useEffect, useRef, useState } from "react";
import { Terminal, ChevronDown, ChevronUp } from "lucide-react";
import Scrollable from "@/components/ui/Scrollable";

interface ScanTerminalProps {
  logs: string[];
}

const LOG_COLORS: { pattern: RegExp; cls: string }[] = [
  { pattern: /\[error\]|\[fail\]|error:|exception/i, cls: "text-rose-400" },
  { pattern: /\[warn\]|warning/i, cls: "text-amber-400" },
  { pattern: /\[ai\]|\[llm\]/i, cls: "text-violet-400" },
  { pattern: /\[server\]|complete/i, cls: "text-cyan-400" },
  { pattern: /cve-\d{4}-\d+/i, cls: "text-orange-400" },
];

function colorLine(log: string): string {
  for (const { pattern, cls } of LOG_COLORS) {
    if (pattern.test(log)) return cls;
  }
  return "text-emerald-400/90";
}

export default function ScanTerminal({ logs }: ScanTerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    if (!collapsed && terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs, collapsed]);

  return (
    <div className={`glass flex flex-col transition-all duration-300 ${collapsed ? "h-10" : "flex-1"} overflow-hidden`}>
      {/* Header — always visible, click to toggle */}
      <button
        onClick={() => setCollapsed(p => !p)}
        className="flex items-center justify-between px-4 h-10 border-b border-indigo-500/20 hover:bg-indigo-500/10 transition-colors flex-shrink-0 w-full text-left"
      >
        <div className="flex items-center gap-2">
          <Terminal size={13} className="text-cyan-400" />
          <span className="text-[10px] font-black tracking-widest text-slate-200 uppercase">Live Log Output</span>
          {logs.length > 0 && (
            <span className="ml-2 px-1.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 text-[8px] font-mono">
              {logs.length}
            </span>
          )}
        </div>
        {collapsed
          ? <ChevronDown size={13} className="text-slate-500" />
          : <ChevronUp size={13} className="text-slate-500" />
        }
      </button>

      {/* Log body */}
      {!collapsed && (
        <Scrollable
          containerRef={terminalRef}
          className="flex-1 p-4 font-mono text-[10px] leading-relaxed bg-black/50 space-y-0.5"
        >
          {logs.length === 0 ? (
            <div className="text-slate-600 italic">Waiting for scan to start...</div>
          ) : (
            logs.map((log, i) => (
              <div key={i} className={colorLine(log)}>
                {log}
              </div>
            ))
          )}
        </Scrollable>
      )}
    </div>
  );
}
