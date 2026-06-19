"use client";

import { useEffect, useRef, useState } from "react";
import { PageHeader } from "@/components/ui";
import { api } from "@/lib/api";

type Msg = { role: "user" | "assistant"; content: string; ai?: boolean };

const SUGGESTIONS = [
  "Show today's most dangerous incidents",
  "Which users are the riskiest?",
  "What are the active threats right now?",
  "Which systems are most at risk?",
];

export default function ChatPage() {
  const [messages, setMessages] = useState<Msg[]>([
    { role: "assistant", content: "Hi — I'm Sentinel. Ask me anything about your security posture.", ai: false },
  ]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function send(text: string) {
    if (!text.trim() || busy) return;
    setMessages((m) => [...m, { role: "user", content: text }]);
    setInput("");
    setBusy(true);
    try {
      const res = await api.chat(text);
      setMessages((m) => [...m, { role: "assistant", content: res.answer, ai: res.ai_generated }]);
    } catch {
      setMessages((m) => [...m, { role: "assistant", content: "Sorry, something went wrong.", ai: false }]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Security Assistant" subtitle="Ask questions in plain language — answers come from live data" />
      <div className="card flex h-[calc(100vh-13rem)] flex-col">
        <div className="flex-1 space-y-4 overflow-y-auto pr-1">
          {messages.map((m, i) => (
            <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
              <div
                className={`max-w-[80%] whitespace-pre-wrap rounded-2xl px-4 py-2.5 text-sm ${
                  m.role === "user"
                    ? "bg-accent/20 text-accent-soft"
                    : "border border-ink-700 bg-ink-850 text-slate-200"
                }`}
              >
                {m.content}
                {m.role === "assistant" && m.ai === false && (
                  <div className="mt-1 text-[10px] uppercase tracking-wide text-slate-500">rule-based</div>
                )}
              </div>
            </div>
          ))}
          {busy && <div className="text-xs text-slate-500">Sentinel is thinking…</div>}
          <div ref={endRef} />
        </div>

        <div className="mt-3 flex flex-wrap gap-1.5">
          {SUGGESTIONS.map((s) => (
            <button key={s} className="pill bg-ink-800 text-slate-400 hover:text-slate-100" onClick={() => send(s)}>
              {s}
            </button>
          ))}
        </div>

        <form
          className="mt-3 flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            send(input);
          }}
        >
          <input
            className="flex-1 rounded-xl border border-ink-600 bg-ink-950 px-3 py-2.5 text-sm outline-none focus:border-accent/60"
            placeholder="Ask about incidents, users, threats…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
          <button className="btn btn-accent" disabled={busy}>
            Send
          </button>
        </form>
      </div>
    </>
  );
}
