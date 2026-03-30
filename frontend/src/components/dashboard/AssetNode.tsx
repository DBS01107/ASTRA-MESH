// src/components/dashboard/AssetNode.tsx
import { Shield, Activity } from 'lucide-react';

export default function AssetNode({ data }: any) {
  return (
    <div className="glass p-3 min-w-[180px] group transition-all hover:border-neon/50">
      <div className="flex justify-between items-start mb-2">
        <div className={`p-1.5 rounded bg-black/50 border ${data.critical ? 'border-red-500 text-red-500' : 'border-neon text-neon'}`}>
          <Shield size={14} />
        </div>
        <div className="text-[10px] font-mono text-muted uppercase">ID: {data.id}</div>
      </div>
      
      <div className="text-xs font-bold text-text mb-1">{data.label}</div>
      
      {/* Visual Risk Meter */}
      <div className="w-full h-1 bg-white/5 rounded-full overflow-hidden mt-2">
        <div 
          className={`h-full ${data.critical ? 'bg-red-500 pulse' : 'bg-neon'}`} 
          style={{ width: `${data.riskScore || 40}%` }} 
        />
      </div>
      
      <div className="mt-2 flex justify-between items-center text-[9px] font-mono">
        <span className="text-muted italic">THREAT LEVEL</span>
        <span className={data.critical ? 'text-red-500' : 'text-neon'}>{data.riskScore}%</span>
      </div>
    </div>
  );
}