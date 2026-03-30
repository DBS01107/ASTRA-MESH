export default function FindingsTable() {
  const data = [
    { id: "CVE-2024-001", target: "WEB_SRV_01", risk: "CRITICAL", status: "Active" },
    { id: "CVE-2023-992", target: "DB_NODE_B", risk: "HIGH", status: "Scanning" },
    { id: "CVE-2024-118", target: "LB_EXTERNAL", risk: "MEDIUM", status: "Mitigated" },
  ];

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
          {data.map((f, i) => (
            <tr key={i} className="hover:bg-cyan-500/5 transition-colors">
              <td className="p-3 text-white">{f.id}</td>
              <td className="p-3 text-cyan-400/80">{f.target}</td>
              <td className="p-3">
                <span className={f.risk === "CRITICAL" ? "text-red-500 font-bold" : "text-amber-500"}>
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