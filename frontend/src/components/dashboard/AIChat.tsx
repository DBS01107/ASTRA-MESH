"use client";
import React, { useState } from 'react';
import { Send, Terminal, Loader2, Bot } from 'lucide-react';
import Scrollable from "@/components/ui/Scrollable";
import { apiUrl } from "@/lib/api";
import { authHeaders } from "@/lib/auth";

interface AIChatProps {
    logs: string[];
    sessionId: string;
    authToken: string;
}

export default function AIChat({ logs = [], sessionId, authToken }: AIChatProps) {
    const chatRef = React.useRef<HTMLDivElement>(null);
    const [messages, setMessages] = useState<{ role: 'user' | 'assistant', content: string }[]>([
        { role: 'assistant', content: "I'm monitoring the scan logs. Ask me anything about the findings." }
    ]);
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);

    React.useEffect(() => {
        if (chatRef.current) {
            chatRef.current.scrollTop = chatRef.current.scrollHeight;
        }
    }, [messages]);

    const handleSend = async () => {
        if (!input.trim() || loading) return;

        const userMsg = input;
        setMessages(prev => [...prev, { role: 'user', content: userMsg }]);
        setInput('');
        setLoading(true);

        try {
            const res = await fetch(apiUrl("/ai/explain"), {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    ...authHeaders(authToken),
                },
                body: JSON.stringify({
                    question: userMsg,
                    logs: logs.slice(-50), // Send last 50 logs for context
                    session_id: sessionId
                })
            });
            const data = await res.json();

            setMessages(prev => [...prev, {
                role: 'assistant',
                content: data.answer || "I couldn't analyze that properly."
            }]);
        } catch (err) {
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: "Error connecting to AI Reasoning Engine."
            }]);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex flex-col h-[calc(100vh-12rem)] max-h-[500px]">
            {/* Messages Area */}
            <Scrollable 
                containerRef={chatRef}
                className="flex-1 space-y-3 p-2 font-mono text-xs"
            >
                {messages.map((msg, idx) => (
                    <div key={idx} className={`flex gap-2 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                        {msg.role === 'assistant' && <Bot size={14} className="text-[#22d3ee] mt-1 shrink-0" />}
                        <div className={`p-2 max-w-[85%] rounded ${msg.role === 'user'
                                ? 'bg-[#22d3ee]/10 border border-[#22d3ee]/20 text-cyan-50'
                                : 'bg-black/40 border border-white/10 text-gray-300'
                            }`}>
                            {msg.content}
                        </div>
                    </div>
                ))}
                {loading && (
                    <div className="flex gap-2">
                        <Loader2 size={14} className="animate-spin text-[#22d3ee]" />
                        <span className="text-gray-500 italic">Analyzing...</span>
                    </div>
                )}
            </Scrollable>

            {/* Input Area */}
            <div className="mt-2 flex gap-2 border-t border-white/10 pt-2">
                <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                    placeholder="Ask about open ports..."
                    className="flex-1 bg-black/40 border border-white/10 px-3 py-2 text-xs text-white focus:outline-none focus:border-[#22d3ee] font-mono"
                />
                <button
                    onClick={handleSend}
                    disabled={loading}
                    className="bg-[#22d3ee]/20 hover:bg-[#22d3ee]/40 p-2 text-[#22d3ee] transition-colors border border-[#22d3ee]/20"
                >
                    <Send size={14} />
                </button>
            </div>
        </div>
    );
}
