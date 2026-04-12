"use client";
import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { CheckCircle, AlertTriangle, XCircle, Info, X } from "lucide-react";

/* ─── Types ─────────────────────────────────────────────────────────────── */
export type ToastVariant = "success" | "error" | "warning" | "info";

export interface Toast {
  id: string;
  message: string;
  variant: ToastVariant;
  duration?: number; // ms, default 4000
}

interface ToastContextValue {
  toast: (message: string, variant?: ToastVariant, duration?: number) => void;
}

/* ─── Context ────────────────────────────────────────────────────────────── */
const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used inside <ToastProvider>");
  return ctx;
}

/* ─── Config ─────────────────────────────────────────────────────────────── */
const VARIANT_STYLES: Record<ToastVariant, { border: string; icon: React.ReactNode; bar: string }> = {
  success: {
    border: "border-emerald-500/50",
    icon: <CheckCircle size={15} className="text-emerald-400 shrink-0 mt-0.5" />,
    bar: "bg-emerald-400",
  },
  error: {
    border: "border-rose-500/50",
    icon: <XCircle size={15} className="text-rose-400 shrink-0 mt-0.5" />,
    bar: "bg-rose-400",
  },
  warning: {
    border: "border-amber-500/50",
    icon: <AlertTriangle size={15} className="text-amber-400 shrink-0 mt-0.5" />,
    bar: "bg-amber-400",
  },
  info: {
    border: "border-cyan-500/50",
    icon: <Info size={15} className="text-cyan-400 shrink-0 mt-0.5" />,
    bar: "bg-cyan-400",
  },
};

/* ─── Single Toast Item ───────────────────────────────────────────────────── */
function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: (id: string) => void }) {
  const [visible, setVisible] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const duration = toast.duration ?? 4000;
  const cfg = VARIANT_STYLES[toast.variant];

  // Mount animation
  useEffect(() => {
    const t = requestAnimationFrame(() => setVisible(true));
    return () => cancelAnimationFrame(t);
  }, []);

  // Auto-dismiss
  useEffect(() => {
    const t = setTimeout(() => dismiss(), duration);
    return () => clearTimeout(t);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [duration]);

  const dismiss = () => {
    setLeaving(true);
    setTimeout(() => onDismiss(toast.id), 300);
  };

  return (
    <div
      className={`
        relative flex items-start gap-3 px-4 py-3 rounded-xl border text-sm
        bg-[#0d0f1e]/90 backdrop-blur-xl
        shadow-[0_8px_32px_rgba(0,0,0,0.7)]
        ${cfg.border}
        transition-all duration-300 ease-out
        ${visible && !leaving ? "opacity-100 translate-x-0" : "opacity-0 translate-x-8"}
        min-w-[280px] max-w-[380px]
        overflow-hidden
      `}
    >
      {/* Progress bar */}
      <div
        className={`absolute bottom-0 left-0 h-[2px] ${cfg.bar} opacity-60`}
        style={{
          animation: `toast-progress ${duration}ms linear forwards`,
        }}
      />

      {cfg.icon}
      <span className="flex-1 text-slate-200 text-[12px] leading-relaxed font-mono break-words">
        {toast.message}
      </span>
      <button
        onClick={dismiss}
        className="text-slate-500 hover:text-slate-300 transition-colors shrink-0 mt-0.5 ml-1"
      >
        <X size={13} />
      </button>
    </div>
  );
}

/* ─── Provider + Portal ───────────────────────────────────────────────────── */
export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const counterRef = useRef(0);

  const toast = useCallback((message: string, variant: ToastVariant = "info", duration?: number) => {
    const id = `toast-${++counterRef.current}`;
    setToasts(prev => [...prev, { id, message, variant, duration }]);
  }, []);

  const dismiss = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}

      {/* Portal — fixed overlay */}
      <div
        className="fixed bottom-6 right-6 z-[9999] flex flex-col-reverse gap-2 pointer-events-none"
        aria-live="polite"
      >
        {toasts.map(t => (
          <div key={t.id} className="pointer-events-auto">
            <ToastItem toast={t} onDismiss={dismiss} />
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
