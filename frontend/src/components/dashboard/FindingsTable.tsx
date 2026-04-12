export default function FindingsTable({ nodes = [] }: { nodes: any[] }) {
  // Organically filter the graph nodes exclusively for vulnerabilities or severe items
  const findings = nodes
    .filter(n => n.type === 'vulnerability' || n.type === 'finding' || n.data?.cvss || n.data?.severity)
    .map(n => {
      let risk = n.data?.severity || 'UNKNOWN';
      const cvss = parseFloat(n.data?.cvss);
      if (!n.data?.severity && !isNaN(cvss)) {
        if (cvss >= 9.0) risk = 'CRITICAL';
        else if (cvss >= 7.0) risk = 'HIGH';
        else if (cvss >= 4.0) risk = 'MEDIUM';
        else risk = 'LOW';
      }

      return {
        id: n.data?.id || n.id || 'N/A',
        target: n.data?.label || 'Asset',
        risk: risk.toUpperCase(),
        status: 'Active'
      };
    })
    .sort((a, b) => {
      // Sort critically severity to the literal top of the list!
      const rank: any = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0 };
      return (rank[b.risk] || 0) - (rank[a.risk] || 0);
    });

  return (
    <div className="h-full flex flex-col">
      <table className="w-full text-left text-[10px] font-mono border-collapse">
        <thead>
          <tr className="bg-white/5 text-cyan-500 uppercase">
            <th className="p-3 border-b border-cyan-500/20">Identifier</th>
            <th className="p-3 border-b border-cyan-500/20">Asset</th>
            <th className="p-3 border-b border-cyan-500/20">Risk</th>
            <th className="p-3 border-b border-cyan-500/20">State</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-white/5">
          {findings.length === 0 && (
            <tr>
              <td colSpan={4} className="p-4 text-center text-slate-500 italic">No vulnerabilities found yet.</td>
            </tr>
          )}
          {findings.map((f, i) => (
            <tr key={i} className="hover:bg-cyan-500/5 transition-colors">
              <td className="p-3 text-white truncate max-w-[150px]" title={f.id}>{f.id}</td>
              <td className="p-3 text-cyan-400/80 truncate max-w-[150px]" title={f.target}>{f.target}</td>
              <td className="p-3">
                <span className={f.risk === "CRITICAL" || f.risk === "HIGH" ? "text-red-500 font-bold" : "text-amber-500"}>
                  {f.risk}
                </span>
              </td>
              <td className="p-3 opacity-60 italic">{f.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}