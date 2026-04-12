"use client";

export default function ActivityFeed({ logs }: { logs: string[] }) {
  // Show the most recent 12 logs in chronological order (newest at top) organically
  const recentLogs = [...logs].reverse().slice(0, 12);

  return (
    <div className="glass p-5 h-[260px] overflow-hidden">
      <h3 className="text-sm font-semibold text-cyan-300 mb-3">
        Live Scan Logs
      </h3>

      <ul className="space-y-2 text-xs text-zinc-300">
        {recentLogs.length === 0 && <li className="italic text-slate-500">Awaiting scan initialization...</li>}
        {recentLogs.map((log, i) => (
          <li
            key={i}
            className={`flex items-center gap-2 truncate ${i === 0 ? 'animate-pulse text-cyan-400' : ''}`}
            title={log}
          >
            ▶ {log}
          </li>
        ))}
      </ul>
    </div>
  );
}
