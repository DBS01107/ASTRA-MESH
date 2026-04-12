"use client";
import React, { useMemo } from 'react';

interface Finding {
  severity: string;
  color: string;
}

export default function RiskHeatmap({ nodes = [] }: { nodes: any[] }) {
  const findings = useMemo(() => {
    const list: Finding[] = [];
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
        let color = "bg-slate-500/30"; // Default
        if (r === 'CRITICAL' || r === 'P1') color = "bg-rose-500 shadow-[0_0_8px_#f43f5e]";
        else if (r === 'HIGH' || r === 'P2') color = "bg-orange-500 shadow-[0_0_6px_#f97316]";
        else if (r === 'MEDIUM' || r === 'P3') color = "bg-amber-500";
        else if (r === 'LOW' || r === 'INFO' || r === 'P4') color = "bg-cyan-500";
        
        list.push({ severity: r, color });
      }
    });

    // Sort by severity importance so "hotter" items appear first in the grid
    const order: Record<string, number> = { 'CRITICAL': 0, 'P1': 0, 'HIGH': 1, 'P2': 1, 'MEDIUM': 2, 'P3': 2, 'LOW': 3, 'INFO': 3, 'P4': 3, 'UNKNOWN': 4 };
    return list.sort((a, b) => (order[a.severity] ?? 99) - (order[b.severity] ?? 99));
  }, [nodes]);

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-[10px] font-bold tracking-widest text-muted uppercase">Risk Distribution Heatmap</h3>
        <div className="flex gap-1.5">
           <div className="w-1.5 h-1.5 bg-rose-500 rounded-sm" title="Critical" />
           <div className="w-1.5 h-1.5 bg-orange-500 rounded-sm" title="High" />
           <div className="w-1.5 h-1.5 bg-amber-500 rounded-sm" title="Medium" />
           <div className="w-1.5 h-1.5 bg-cyan-500 rounded-sm" title="Low" />
        </div>
      </div>
      
      <div className="flex-1 overflow-hidden">
        {findings.length === 0 ? (
          <div className="h-full flex items-center justify-center text-[10px] text-slate-500 italic">
            No risk data available
          </div>
        ) : (
          <div className="flex flex-wrap gap-1 content-start h-full p-0.5 custom-scrollbar overflow-y-auto">
            {findings.map((f, i) => (
              <div 
                key={i} 
                className={`w-3 h-3 rounded-sm transition-all hover:scale-125 hover:brightness-125 cursor-help ${f.color}`}
                title={f.severity}
              />
            ))}
          </div>
        )}
      </div>
      
      <div className="mt-2 text-[9px] text-slate-500 font-mono flex justify-between items-center">
        <span>TOTAL_FINDINGS: {findings.length}</span>
        <span className="opacity-50 uppercase tracking-tighter italic">Sector_Heat_Map // v1.0</span>
      </div>
    </div>
  );
}
