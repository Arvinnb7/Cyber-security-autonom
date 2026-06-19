"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      await api.login(username, password);
      router.replace("/");
    } catch {
      setError("Invalid credentials");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="grid min-h-screen place-items-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 grid h-14 w-14 place-items-center rounded-2xl bg-accent/15 text-2xl text-accent-soft shadow-glow">
            ◬
          </div>
          <h1 className="text-2xl font-semibold text-white">Sentinel</h1>
          <p className="mt-1 text-sm text-slate-400">Autonomous Security Operations</p>
        </div>
        <form onSubmit={submit} className="card space-y-4">
          <div>
            <label className="mb-1 block text-xs text-slate-400">Username</label>
            <input
              className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent/60"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">Password</label>
            <input
              type="password"
              className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent/60"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          {error && <p className="text-sm text-risk-critical">{error}</p>}
          <button className="btn btn-accent w-full" disabled={loading}>
            {loading ? "Signing in…" : "Sign in"}
          </button>
          <p className="text-center text-xs text-slate-500">Demo credentials: admin / admin</p>
        </form>
      </div>
    </div>
  );
}
