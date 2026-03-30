"use client";

import { useState } from "react";
import { apiUrl } from "@/lib/api";
import { getClientSessionId } from "@/lib/session";

export default function AiChat({ logs, sessionId }: { logs: string[]; sessionId?: string }) {
  const [q, setQ] = useState("");
  const [messages, setMessages] = useState<string[]>([
    "ASTRA AI ready."
  ]);

  const ask = async () => {
    setMessages(m => [...m, "You: " + q]);

    const res = await fetch(apiUrl("/ai/explain"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        logs: logs.slice(-20), // last 20 lines only
        question: q,
        session_id: sessionId || getClientSessionId()
      })
    });

    const data = await res.json();
    setMessages(m => [...m, "AI: " + data.answer]);
    setQ("");
  };

  return (
    <div className="mt-6">
      <h3 className="font-bold mb-2">ASTRA AI Assistant</h3>

      <div className="bg-neutral-900 p-3 h-40 overflow-auto text-sm">
        {messages.map((m, i) => (
          <div key={i}>{m}</div>
        ))}
      </div>

      <div className="flex mt-2 gap-2">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          className="flex-1 bg-black border border-white/20 p-2"
          placeholder="Ask about vulnerabilities..."
        />
        <button
          onClick={ask}
          className="bg-white text-black px-4"
        >
          Ask
        </button>
      </div>
    </div>
  );
}
