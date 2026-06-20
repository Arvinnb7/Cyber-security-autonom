"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api";
import { useLang } from "@/lib/i18n";

export default function LoginPage() {
  const router = useRouter();
  const { t, lang, setLang } = useLang();
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
      setError(t("login.invalid"));
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
          <p className="mt-1 text-sm text-slate-400">{t("login.subtitle")}</p>
        </div>
        <form onSubmit={submit} className="card space-y-4">
          <div>
            <label className="mb-1 block text-xs text-slate-400">{t("login.username")}</label>
            <input
              className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent/60"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">{t("login.password")}</label>
            <input
              type="password"
              className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent/60"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          {error && <p className="text-sm text-risk-critical">{error}</p>}
          <button className="btn btn-accent w-full" disabled={loading}>
            {loading ? t("login.signingin") : t("login.signin")}
          </button>
          <p className="text-center text-xs text-slate-500">{t("login.demo")}</p>
          <button
            type="button"
            onClick={() => setLang(lang === "fa" ? "en" : "fa")}
            className="mx-auto block text-xs text-slate-500 hover:text-accent-soft"
          >
            🌐 {t("lang.toggle")}
          </button>
        </form>
      </div>
    </div>
  );
}
