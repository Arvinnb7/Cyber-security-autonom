"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { clearToken, getToken } from "@/lib/api";

const NAV = [
  { href: "/", label: "Dashboard", icon: "▤" },
  { href: "/incidents", label: "Incidents", icon: "◆" },
  { href: "/users", label: "Users & Assets", icon: "◉" },
  { href: "/chat", label: "Security Assistant", icon: "✦" },
  { href: "/reports", label: "Weekly Reports", icon: "▥" },
];

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const isLogin = pathname === "/login";

  useEffect(() => {
    if (!isLogin && !getToken()) {
      router.replace("/login");
      return;
    }
    setReady(true);
  }, [isLogin, pathname, router]);

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
            <div className="text-[11px] uppercase tracking-widest text-slate-500">Autonomous SOC</div>
          </div>
        </div>
        <nav className="flex flex-1 flex-col gap-1">
          {NAV.map((item) => {
            const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
            return (
              <Link key={item.href} href={item.href} className={`nav-link ${active ? "nav-link-active" : ""}`}>
                <span className="w-4 text-center opacity-70">{item.icon}</span>
                {item.label}
              </Link>
            );
          })}
        </nav>
        <button
          className="nav-link mt-2 text-left"
          onClick={() => {
            clearToken();
            router.replace("/login");
          }}
        >
          <span className="w-4 text-center opacity-70">⎋</span> Sign out
        </button>
      </aside>

      <main className="flex-1 px-5 py-6 md:px-8 md:py-8">
        <div className="mx-auto max-w-7xl">{children}</div>
      </main>
    </div>
  );
}
