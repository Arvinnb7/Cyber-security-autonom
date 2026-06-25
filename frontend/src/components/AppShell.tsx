"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api, clearToken, getToken } from "@/lib/api";
import { useLang } from "@/lib/i18n";

const NAV = [
  { href: "/", key: "nav.dashboard", icon: "▤" },
  { href: "/incidents", key: "nav.incidents", icon: "◆" },
  { href: "/detections", key: "nav.detections", icon: "◈" },
  { href: "/users", key: "nav.users", icon: "◉" },
  { href: "/integrations", key: "nav.integrations", icon: "⚯" },
  { href: "/chat", key: "nav.chat", icon: "✦" },
  { href: "/reports", key: "nav.reports", icon: "▥" },
];

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { t, lang, setLang } = useLang();
  const [ready, setReady] = useState(false);
  const [mode, setMode] = useState<string | null>(null);
  const [switching, setSwitching] = useState(false);
  const isLogin = pathname === "/login";

  useEffect(() => {
    if (!isLogin && !getToken()) {
      router.replace("/login");
      return;
    }
    setReady(true);
    if (!isLogin) api.getMode().then((m) => setMode(m.data_mode)).catch(() => {});
  }, [isLogin, pathname, router]);

  async function toggleMode() {
    if (!mode || switching) return;
    setSwitching(true);
    try {
      await api.setMode(mode === "demo" ? "live" : "demo");
      // Full reload so every page refetches the now-active dataset.
      window.location.reload();
    } catch {
      setSwitching(false);
    }
  }

  if (isLogin) return <>{children}</>;
  if (!ready) return null;

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-64 flex-col border-r border-ink-800 bg-ink-900/60 p-4 backdrop-blur md:flex">
        <div className="mb-8 flex items-center gap-3 px-2">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-accent/15 text-lg text-accent-soft shadow-glow">
            ◬
          </div>
          <div>
            <div className="text-lg font-semibold tracking-tight text-white">Sentinel</div>
            <div className="text-[11px] uppercase tracking-widest text-slate-500">{t("brand.tag")}</div>
          </div>
        </div>
        <nav className="flex flex-1 flex-col gap-1">
          {NAV.map((item) => {
            const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
            return (
              <Link key={item.href} href={item.href} className={`nav-link ${active ? "nav-link-active" : ""}`}>
                <span className="w-4 text-center opacity-70">{item.icon}</span>
                {t(item.key)}
              </Link>
            );
          })}
        </nav>
        {mode && (
          <div className="mt-2 rounded-xl border border-ink-700/60 bg-ink-850/60 p-2.5">
            <div className="mb-1.5 flex items-center gap-2 px-1 text-xs">
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{ background: mode === "live" ? "#34d399" : "#fb923c" }}
              />
              <span className="text-slate-300">{mode === "live" ? t("mode.live") : t("mode.demo")}</span>
            </div>
            <button className="btn w-full py-1.5 text-xs" onClick={toggleMode} disabled={switching}>
              {switching ? t("mode.switching") : mode === "demo" ? t("mode.toLive") : t("mode.toDemo")}
            </button>
          </div>
        )}
        <button
          className="nav-link mt-2"
          onClick={() => setLang(lang === "fa" ? "en" : "fa")}
          title="Change language / تغییر زبان"
        >
          <span className="w-4 text-center opacity-70">🌐</span> {t("lang.toggle")}
        </button>
        <button
          className="nav-link"
          onClick={() => {
            clearToken();
            router.replace("/login");
          }}
        >
          <span className="w-4 text-center opacity-70">⎋</span> {t("nav.signout")}
        </button>
      </aside>

      <main className="flex-1 px-5 py-6 md:px-8 md:py-8">
        <div className="mx-auto max-w-7xl">{children}</div>
      </main>
    </div>
  );
}
