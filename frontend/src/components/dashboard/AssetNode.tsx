// src/components/dashboard/AssetNode.tsx
import { Handle, Position } from 'reactflow';

/* ─── Severity resolution ────────────────────────────────────────────────── */
function resolveSeverity(data: any): string | null {
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

/* ─── Per-severity visual styles ─────────────────────────────────────────── */
const SEV_NODE_STYLE: Record<string, { border: string; glow: string; badge: string }> = {
  CRITICAL: {
    border: "border-rose-500",
    glow:   "shadow-[0_0_16px_rgba(244,63,94,0.45)] hover:shadow-[0_0_22px_rgba(244,63,94,0.65)]",
    badge:  "text-rose-400",
  },
  HIGH: {
    border: "border-orange-400",
    glow:   "shadow-[0_0_14px_rgba(251,146,60,0.35)] hover:shadow-[0_0_20px_rgba(251,146,60,0.55)]",
    badge:  "text-orange-400",
  },
  MEDIUM: {
    border: "border-amber-400",
    glow:   "shadow-[0_0_12px_rgba(251,191,36,0.25)] hover:shadow-[0_0_18px_rgba(251,191,36,0.45)]",
    badge:  "text-amber-400",
  },
  LOW: {
    border: "border-emerald-400",
    glow:   "shadow-[0_0_10px_rgba(52,211,153,0.2)] hover:shadow-[0_0_16px_rgba(52,211,153,0.4)]",
    badge:  "text-emerald-400",
  },
};

const DEFAULT_STYLE = {
  border: "border-indigo-500/40",
  glow:   "shadow-[0_0_8px_rgba(99,102,241,0.15)] hover:shadow-[0_0_14px_rgba(99,102,241,0.35)]",
  badge:  "text-slate-400",
};

export default function AssetNode({ data, selected }: any) {
  const severity = resolveSeverity(data);
  const style = severity ? (SEV_NODE_STYLE[severity] ?? DEFAULT_STYLE) : DEFAULT_STYLE;

  return (
    <div
      className={`
        p-2 rounded border w-[130px]
        bg-[#0f172a]/90 text-white backdrop-blur
        flex flex-col items-center justify-center text-center
        cursor-pointer active:cursor-grabbing
        transition-all duration-200
        ${style.border} ${style.glow}
        ${selected ? "ring-2 ring-cyan-400/70 ring-offset-1 ring-offset-[#0f172a]" : ""}
      `}
    >
      {/* Target handle */}
      <Handle type="target" position={Position.Top} className="!bg-white w-1.5 h-1.5" />

      {/* Label */}
      <div className="text-[9px] font-bold leading-tight break-words whitespace-pre-wrap uppercase w-full">
        {data.label || data.id || 'Unknown'}
      </div>

      {/* Severity / CVSS badge */}
      {(severity || data.cvss) && (
        <div className={`mt-1 text-[8px] font-mono font-bold tracking-wider uppercase opacity-80 ${style.badge}`}>
          {severity ?? `CVSS: ${data.cvss}`}
        </div>
      )}

      {/* Source handle */}
      <Handle type="source" position={Position.Bottom} className="!bg-white w-1.5 h-1.5" />
    </div>
  );
}