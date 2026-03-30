"use client";

export default function RiskChart() {
  return (
    <div className="glass p-5 glow">
      <h3 className="text-sm font-semibold text-cyan-300 mb-3">
        Risk Distribution
      </h3>

      <div className="flex gap-4 text-sm">
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 bg-red-500 rounded-full animate-pulse" />
          Critical
        </div>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 bg-yellow-400 rounded-full animate-pulse" />
          High
        </div>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 bg-green-500 rounded-full animate-pulse" />
          Medium
        </div>
      </div>
    </div>
  );
}
