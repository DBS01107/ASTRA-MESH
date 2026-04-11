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

  return (
    <div className={`p-2 rounded border border-white/20 w-[120px] bg-[#0f172a]/90 text-white backdrop-blur shadow flex flex-col items-center justify-center text-center cursor-grab active:cursor-grabbing`}>
      {/* Target handle for Grid layout */}
      <Handle type="target" position={Position.Top} className="!bg-white w-1.5 h-1.5" />

      {/* Force rendering of full text dynamically driving node height organically */}
      <div className="text-[9px] font-bold leading-tight break-words whitespace-pre-wrap uppercase w-full">
        {data.label || data.id || 'Unknown'}
      </div>

      {/* Optional rendering based entirely on CVSS rating presence OR direct parsed explicit severities */}
      {(severity || data.cvss) && (
        <div className="mt-1 text-[8px] font-mono font-bold tracking-wider uppercase opacity-70">
          {severity ? severity : `CVSS: ${data.cvss}`}
        </div>
      )}

      {/* Source handle for Grid layout */}
      <Handle type="source" position={Position.Bottom} className="!bg-white w-1.5 h-1.5" />
    </div>
  );
}