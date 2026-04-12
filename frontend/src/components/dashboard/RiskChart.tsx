"use client";

export default function RiskChart({ nodes = [] }: { nodes: any[] }) {
  let critical = 0, high = 0, medium = 0, low = 0, unknown = 0;

  nodes.forEach(n => {
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
      if (r === 'CRITICAL' || r === 'P1') critical++;
      else if (r === 'HIGH' || r === 'P2') high++;
      else if (r === 'MEDIUM' || r === 'P3') medium++;
      else if (r === 'LOW' || r === 'INFO' || r === 'P4') low++;
      else unknown++;
    }
  });

  return (
    <div className="glass p-5 glow h-full">
      <h3 className="text-sm font-semibold text-cyan-300 mb-3 uppercase tracking-widest">
        Risk Distribution
      </h3>

      <div className="flex flex-col gap-2 text-sm font-mono mt-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-rose-400">
            <span className="w-3 h-3 bg-red-500 rounded-full animate-pulse shadow-[0_0_8px_#ef4444]" />
            CRITICAL
          </div>
          <span className="font-bold text-white">{critical}</span>
        </div>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-orange-400">
            <span className="w-3 h-3 bg-orange-400 rounded-full shadow-[0_0_8px_#f97316]" />
            HIGH
          </div>
          <span className="font-bold text-white">{high}</span>
        </div>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-amber-400">
            <span className="w-3 h-3 bg-amber-400 rounded-full shadow-[0_0_8px_#fbbf24]" />
            MEDIUM
          </div>
          <span className="font-bold text-white">{medium}</span>
        </div>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-cyan-400">
            <span className="w-3 h-3 bg-cyan-400 rounded-full shadow-[0_0_8px_#22d3ee]" />
            LOW / INFO
          </div>
          <span className="font-bold text-white">{low}</span>
        </div>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-slate-400">
            <span className="w-3 h-3 bg-slate-500 rounded-full shadow-[0_0_8px_#64748b]" />
            UNKNOWN
          </div>
          <span className="font-bold text-white">{unknown}</span>
        </div>
      </div>
    </div>
  );
}
