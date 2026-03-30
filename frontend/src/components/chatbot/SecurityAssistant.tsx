"use client";

import { useState, useEffect } from "react";

const logs = [
  "Analyzing exposed attack surfaces…",
  "Correlating vulnerabilities with assets…",
  "Detected privilege escalation path",
  "Recommending remediation steps",
];

export default function SecurityAssistant() {
  const [line, setLine] = useState(0);

  useEffect(() => {
    const i = setInterval(() => {
      setLine((l) => (l + 1) % logs.length);
    }, 1800);
    return () => clearInterval(i);
  }, []);

  return (
    <div className="h-full flex flex-col">
      <h3 className="text-lg font-semibold text-cyan-300 mb-2">
        🤖 AI Security Assistant
      </h3>

      <div className="flex-1 text-sm text-cyan-200 animate-pulse">
        {logs[line]}
      </div>

      <input
        placeholder="Ask AI about this scan…"
        className="mt-4 bg-black/40 border border-cyan-400/30 rounded-md px-3 py-2 text-sm outline-none focus:border-cyan-400"
      />
    </div>
  );
}
