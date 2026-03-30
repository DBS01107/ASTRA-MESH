export default function LivePulse() {
  return (
    <div className="flex items-center gap-2 px-3 py-1 glass border-cyan-400/30">
      <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 pulse-glow" />
      <span className="text-[9px] text-cyan-400 font-mono uppercase tracking-tighter">
        ASTRA_AI: ACTIVE_REASONING
      </span>
    </div>
  );
}