"use client";

const logs = [
  "Port 443 exposed – checking TLS config",
  "API endpoint leaked via OpenAPI",
  "Privilege escalation path detected",
  "Database reachable via lateral movement"
];

export default function ActivityFeed() {
  return (
    <div className="glass p-5 h-[260px] overflow-hidden">
      <h3 className="text-sm font-semibold text-cyan-300 mb-3">
        Live Scan Logs
      </h3>

      <ul className="space-y-2 text-xs text-zinc-300">
        {logs.map((log, i) => (
          <li
            key={i}
            className="flex items-center gap-2 animate-pulse"
          >
            ▶ {log}
          </li>
        ))}
      </ul>
    </div>
  );
}
