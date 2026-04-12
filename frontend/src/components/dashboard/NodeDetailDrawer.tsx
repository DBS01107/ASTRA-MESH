"use client";
import React, { useEffect, useState } from "react";
import { X, Shield, Cpu, Globe, Hash, AlertTriangle, Terminal, ExternalLink, ChevronRight } from "lucide-react";
import Scrollable from "@/components/ui/Scrollable";

interface NodeDetailDrawerProps {
  node: any | null;
  onClose: () => void;
  onAskAI?: (context: string) => void;
}

/* ─── Severity helpers (mirrors AssetNode logic) ─────────────────────────── */
function getSeverity(data: any): string | null {
  if (data.severity) return data.severity.toUpperCase();
  if (data.cvss !== undefined) {
    const v = parseFloat(data.cvss);
    if (!isNaN(v)) {
      if (v >= 9.0) return "CRITICAL";
      if (v >= 7.0) return "HIGH";
      if (v >= 4.0) return "MEDIUM";
      return "LOW";
    }
  }
  if (data.riskScore !== undefined) {
    if (data.riskScore >= 90) return "CRITICAL";
    if (data.riskScore >= 70) return "HIGH";
    if (data.riskScore >= 40) return "MEDIUM";
    return "LOW";
  }
  return null;
}

const SEV_BADGE: Record<string, string> = {
  CRITICAL: "bg-rose-500/20 text-rose-300 border border-rose-500/50",
  HIGH:     "bg-orange-500/20 text-orange-300 border border-orange-500/50",
  MEDIUM:   "bg-amber-500/20 text-amber-300 border border-amber-500/50",
  LOW:      "bg-emerald-500/20 text-emerald-300 border border-emerald-500/50",
};

const TYPE_ICON: Record<string, React.ReactNode> = {
  vulnerability: <Shield size={13} className="text-rose-400" />,
  finding:       <AlertTriangle size={13} className="text-amber-400" />,
  host:          <Globe size={13} className="text-cyan-400" />,
  service:       <Cpu size={13} className="text-violet-400" />,
  web_service:   <Globe size={13} className="text-indigo-400" />,
  port:          <Hash size={13} className="text-slate-400" />,
  open_port:     <Hash size={13} className="text-emerald-400" />,
};

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  if (!value) return null;
  return (
    <div className="flex justify-between items-start gap-3 py-2 border-b border-white/5">
      <span className="text-[10px] uppercase tracking-widest text-slate-500 shrink-0 font-mono">{label}</span>
      <span className="text-[11px] text-slate-200 font-mono text-right break-all">{value}</span>
    </div>
  );
}

export default function NodeDetailDrawer({ node, onClose, onAskAI }: NodeDetailDrawerProps) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (node) {
      // brief delay so CSS transition fires
      const t = requestAnimationFrame(() => setVisible(true));
      return () => cancelAnimationFrame(t);
    } else {
      setVisible(false);
    }
  }, [node]);

  if (!node) return null;

  const data = node.data ?? {};
  const severity = getSeverity(data);
  const nodeType = node.type || data.type || "asset";

  const buildAIContext = () => {
    const parts = [
      `Node: ${data.label || node.id}`,
      `Type: ${nodeType}`,
      severity ? `Severity: ${severity}` : null,
      data.cvss ? `CVSS: ${data.cvss}` : null,
      data.port ? `Port: ${data.port}` : null,
      data.service ? `Service: ${data.service}` : null,
      data.description ? `Description: ${data.description}` : null,
      data.cve ? `CVE: ${data.cve}` : null,
    ].filter(Boolean).join(". ");
    return parts;
  };

  // Extract all extra metadata as key-value pairs
  const knownKeys = new Set(["label", "id", "severity", "cvss", "riskScore", "type", "port", "service", "description", "cve", "url", "tech", "version", "protocol", "vendor"]);
  const extraKeys = Object.keys(data).filter(k => !knownKeys.has(k) && data[k] !== undefined && data[k] !== null && data[k] !== "");

  return (
    <>
      {/* Backdrop */}
      <div
        className={`absolute inset-0 z-30 transition-opacity duration-300 ${visible ? "opacity-100" : "opacity-0"}`}
        style={{ background: "rgba(2,3,10,0.45)", backdropFilter: "blur(2px)" }}
        onClick={onClose}
      />

      {/* Drawer panel */}
      <div
        className={`absolute right-0 top-0 bottom-0 z-40 w-72 flex flex-col
          bg-[#0a0c18]/95 border-l border-indigo-500/25
          backdrop-blur-xl shadow-[−8px_0_40px_rgba(0,0,0,0.8)]
          transition-transform duration-300 ease-out
          ${visible ? "translate-x-0" : "translate-x-full"}
        `}
      >
        {/* Header */}
        <div className="flex items-start justify-between px-4 pt-4 pb-3 border-b border-indigo-500/20 flex-shrink-0">
          <div className="flex items-center gap-2">
            {TYPE_ICON[nodeType] ?? <Cpu size={13} className="text-cyan-400" />}
            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">{nodeType}</div>
              <div className="text-sm font-bold text-white break-words max-w-[180px] leading-tight mt-0.5">
                {data.label || node.id || "Unknown"}
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-white/10 text-slate-500 hover:text-white transition-colors shrink-0 mt-0.5"
          >
            <X size={14} />
          </button>
        </div>

        {/* Severity badge */}
        {severity && (
          <div className="px-4 py-2.5 flex-shrink-0 border-b border-white/5">
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold tracking-widest uppercase ${SEV_BADGE[severity] ?? ""}`}>
              <AlertTriangle size={10} />
              {severity}
            </span>
          </div>
        )}

        {/* Fields */}
        <Scrollable className="flex-1 px-4 py-2 min-h-0">
          <Row label="Node ID"    value={node.id} />
          <Row label="CVSS"       value={data.cvss} />
          <Row label="Risk Score" value={data.riskScore} />
          <Row label="Port"       value={data.port} />
          <Row label="Protocol"   value={data.protocol} />
          <Row label="Service"    value={data.service} />
          <Row label="Version"    value={data.version} />
          <Row label="Technology" value={data.tech} />
          <Row label="Vendor"     value={data.vendor} />
          <Row label="URL"        value={data.url ? (
            <a href={data.url} target="_blank" rel="noreferrer" className="text-cyan-400 hover:underline flex items-center gap-1">
              {data.url.length > 30 ? data.url.slice(0, 30) + "…" : data.url}
              <ExternalLink size={10} />
            </a>
          ) : null} />
          <Row label="CVE"        value={data.cve ? (
            <a href={`https://nvd.nist.gov/vuln/detail/${data.cve}`} target="_blank" rel="noreferrer" className="text-rose-400 hover:underline flex items-center gap-1">
              {data.cve} <ExternalLink size={10} />
            </a>
          ) : null} />

          {/* Description */}
          {data.description && (
            <div className="py-3 border-b border-white/5">
              <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1.5 font-mono">Description</div>
              <div className="text-[11px] text-slate-300 leading-relaxed">{data.description}</div>
            </div>
          )}

          {/* Extra fields */}
          {extraKeys.map(k => (
            <Row key={k} label={k} value={String(data[k])} />
          ))}
        </Scrollable>

        {/* Footer actions */}
        {onAskAI && (
          <div className="px-4 py-3 border-t border-indigo-500/20 flex-shrink-0 space-y-2">
            <button
              onClick={() => { onAskAI(buildAIContext()); onClose(); }}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg
                bg-violet-500/15 border border-violet-500/40 text-violet-300
                text-[10px] font-bold uppercase tracking-widest
                hover:bg-violet-500/25 hover:border-violet-400 transition-all"
            >
              <Terminal size={12} />
              Ask AI about this node
              <ChevronRight size={12} />
            </button>
          </div>
        )}
      </div>
    </>
  );
}
