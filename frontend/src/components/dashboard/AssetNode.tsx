// src/components/dashboard/AssetNode.tsx
import { Handle, Position } from 'reactflow';

export default function AssetNode({ data }: any) {
  // Explicitly map string outputs based on strict CVSS/Ranking payload mappings
  let severity = data.severity;

  if (!severity) {
    if (data.cvss !== undefined) {
      const cvssScore = parseFloat(data.cvss);
      if (!isNaN(cvssScore)) {
        if (cvssScore >= 9.0) severity = 'CRITICAL';
        else if (cvssScore >= 7.0) severity = 'HIGH';
        else if (cvssScore >= 4.0) severity = 'MEDIUM';
        else severity = 'LOW';
      } else {
        severity = 'MEDIUM'; // Fallback if CVSS exists but is structurally invalid text
      }
    } else if (data.riskScore !== undefined) {
      if (data.riskScore >= 90) severity = 'CRITICAL';
      else if (data.riskScore >= 70) severity = 'HIGH';
      else if (data.riskScore >= 40) severity = 'MEDIUM';
      else severity = 'LOW';
    }
  }

  // Determine if severity is strictly vital enough to render based on user preference
  const isSevere = severity?.toUpperCase() === 'CRITICAL' || 
                   severity?.toUpperCase() === 'HIGH' || 
                   severity?.toUpperCase() === 'P1' || 
                   severity?.toUpperCase() === 'P2';

  return (
    <div className={`p-2 rounded border border-white/20 w-[120px] bg-[#0f172a]/90 text-white backdrop-blur shadow flex flex-col items-center justify-center text-center cursor-grab active:cursor-grabbing`}>
      {/* Target handle for Grid layout */}
      <Handle type="target" position={Position.Top} className="!bg-white w-1.5 h-1.5" />

      {/* Force rendering of full text dynamically driving node height organically */}
      <div className="text-[9px] font-bold leading-tight break-words whitespace-pre-wrap uppercase w-full">
        {data.label || data.id || 'Unknown'}
      </div>

      {/* Strict rendering only for severe threats or explicitly designated CVSS items */}
      {(isSevere || data.cvss) && (
        <div className="mt-1 text-[8px] font-mono font-bold tracking-wider uppercase opacity-70 text-red-400">
          {isSevere ? severity : `CVSS: ${data.cvss}`}
        </div>
      )}

      {/* Source handle for Grid layout */}
      <Handle type="source" position={Position.Bottom} className="!bg-white w-1.5 h-1.5" />
    </div>
  );
}