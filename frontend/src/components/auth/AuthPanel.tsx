"use client";

import React, { useState } from "react";
import { apiUrl } from "@/lib/api";
import { AuthUser } from "@/lib/auth";
import { Github, Linkedin } from "lucide-react";

interface AuthPanelProps {
  onAuthenticated: (token: string, user: AuthUser) => void;
}

const CREATORS = [
  {
    name: "Devang Sonawane",
    github: "https://github.com/DBS01107",
    linkedin: "https://linkedin.com/in/devang-sonawane-73925a1b4/",
  },
  {
    name: "Sarthak Pujari",
    github: "https://github.com/Sarthakzzzzz",
    linkedin: "https://linkedin.com/in/sarthakzzzzz/",
  },
  {
    name: "Adwait Bangale",
    github: "https://github.com/toxicated53",
    linkedin: "https://www.linkedin.com/in/adwait-bangale-330710288/",
  },
  {
    name: "Ved Asawa",
    github: "https://github.com/A-C-I-D",
    linkedin: "https://www.linkedin.com/in/ved-asawa/",
  },
  {
    name: "Snehal Jagtap",
    github: "https://github.com/CyberSirenDev",
    linkedin: "https://www.linkedin.com/in/snehal-jagtap-0293b62b8",
  }
];

export default function AuthPanel({ onAuthenticated }: AuthPanelProps) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!username.trim() || !password) {
      setError("Username and password are required.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const endpoint = mode === "login" ? "/api/auth/login" : "/api/auth/register";
      const payload: Record<string, string> = {
        username: username.trim(),
        password,
      };
      if (mode === "register" && email.trim()) {
        payload.email = email.trim();
      }

      const res = await fetch(apiUrl(endpoint), {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.detail || "Authentication failed.");
      }

      if (!data.access_token || !data.user) {
        throw new Error("Authentication response is incomplete.");
      }

      onAuthenticated(data.access_token, data.user as AuthUser);
    } catch (err: any) {
      setError(err?.message || "Authentication failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="h-screen w-screen bg-[#02030a] text-[#eaeaf0] flex items-center justify-center cyber-grid">
      <div className="w-full max-w-4xl glass border border-[#22d3ee]/25 p-4 lg:p-6 scale-[0.7] origin-center">
        <div className="grid gap-4 lg:grid-cols-[minmax(240px,300px)_1fr] items-center">
          <section>
            <h1 className="text-[13px] font-black tracking-[0.25em] text-[#22d3ee] uppercase mb-4">
              ASTRA Access Control
            </h1>

            <div className="flex mb-3 border border-[#22d3ee]/20">
              <button
                onClick={() => setMode("login")}
                className={`flex-1 py-2 text-[10px] uppercase tracking-[0.2em] font-bold ${
                  mode === "login"
                className={`flex-1 py-2 text-[10px] uppercase tracking-[0.2em] font-bold ${mode === "login"
                    ? "bg-[#22d3ee] text-black"
                    : "text-[#22d3ee]/80 hover:bg-[#22d3ee]/10"
                }`}
                  }`}
              >
                Login
              </button>
              <button
                onClick={() => setMode("register")}
                className={`flex-1 py-2 text-[10px] uppercase tracking-[0.2em] font-bold ${
                  mode === "register"
                className={`flex-1 py-2 text-[10px] uppercase tracking-[0.2em] font-bold ${mode === "register"
                    ? "bg-[#22d3ee] text-black"
                    : "text-[#22d3ee]/80 hover:bg-[#22d3ee]/10"
                }`}
                  }`}
              >
                Register
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-[10px] uppercase tracking-[0.16em] text-[#22d3ee]/70">
                  Username
                </label>
                <input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full mt-1 bg-black/40 border border-[#22d3ee]/20 p-2 text-[12px] focus:border-[#22d3ee] outline-none"
                  placeholder="operator"
                />
              </div>

              {mode === "register" && (
                <div>
                  <label className="text-[10px] uppercase tracking-[0.16em] text-[#22d3ee]/70">
                    Email (Optional)
                  </label>
                  <input
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full mt-1 bg-black/40 border border-[#22d3ee]/20 p-2 text-[12px] focus:border-[#22d3ee] outline-none"
                    placeholder="operator@example.com"
                  />
                </div>
              )}

              <div>
                <label className="text-[10px] uppercase tracking-[0.16em] text-[#22d3ee]/70">
                  Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full mt-1 bg-black/40 border border-[#22d3ee]/20 p-2 text-[12px] focus:border-[#22d3ee] outline-none"
                  placeholder="At least 8 characters"
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      submit();
                    }
                  }}
                />
              </div>

              {error && (
                <div className="text-[11px] text-rose-300 border border-rose-300/30 bg-rose-500/10 p-2">
                  {error}
                </div>
              )}

              <button
                onClick={submit}
                disabled={loading}
                className={`w-full border border-[#22d3ee] py-3 text-[10px] uppercase tracking-[0.2em] font-bold hover:bg-[#22d3ee] hover:text-black transition-all ${
                  loading ? "opacity-60 cursor-not-allowed" : "pulse-glow"
                }`}
                className={`w-full border border-[#22d3ee] py-3 text-[10px] uppercase tracking-[0.2em] font-bold hover:bg-[#22d3ee] hover:text-black transition-all ${loading ? "opacity-60 cursor-not-allowed" : "pulse-glow"
              >
                {loading ? "Authenticating..." : mode === "login" ? "Login" : "Create Account"}
              </button>
            </div>
          </section>

          <section className="border border-[#22d3ee]/15 bg-black/20 rounded-md p-3">
            <p className="text-[9px] uppercase tracking-[0.2em] text-[#22d3ee]/75">Creators</p>

            <div className="mt-2 flex justify-between gap-2">
              {CREATORS.map((creator) => (
                <div
                  key={creator.name}
                  className="border border-[#22d3ee]/15 bg-black/25 px-2 py-1 rounded-md flex-shrink-0"
                >
                  <p className="text-[11px] font-semibold text-[#eaeaf0]">{creator.name}</p>
                  <div className="mt-1 flex items-center gap-1 text-[9px]">
                    <a
                      href={creator.github}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-[#22d3ee]/80 hover:text-[#22d3ee] transition-colors"
                    >
                      <Github size={12} />
                      GitHub
                    </a>
                    <a
                      href={creator.linkedin}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-[#22d3ee]/80 hover:text-[#22d3ee] transition-colors"
                    >
                      <Linkedin size={12} />
                      LinkedIn
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
