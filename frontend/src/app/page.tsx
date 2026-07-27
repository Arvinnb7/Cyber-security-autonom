"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import RiskGauge from "@/components/RiskGauge";
import { AiBadge, PageHeader, RiskPill, Spinner, StatusPill } from "@/components/ui";
import { api } from "@/lib/api";
import { detName, useLang } from "@/lib/i18n";
import { useMe } from "@/lib/me";

export default function Dashboard() {
  const { t, lang } = useLang();
  const { isAdmin } = useMe();
  const [data, setData] = useState<any>(null);
  const [aiOn, setAiOn] = useState(false);
  const [busy, setBusy] = useState(false);
  const [health, setHealth] = useState<any>(null);
  const [sla, setSla] = useState<any>(null);

  // Live threat state — the only thing that genuinely changes minute to minute.
  const load = useCallback(async () => {
    const [overview, meta] = await Promise.all([api.overview(), api.meta().catch(() => null)]);
    setData(overview);
    if (meta) setAiOn(meta.ai_enabled);
  }, []);

  // Platform health and SLA move slowly and are far more expensive to compute,
  // so they get their own much slower tick rather than riding the fast poll.
  const loadSlow = useCallback(async () => {
    const [sys, slaData] = await Promise.all([
      api.systemHealth().catch(() => null),
      api.slaMetrics().catch(() => null),
    ]);
    setHealth(sys);
    setSla(slaData);
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 10000); // live threat refresh
    return () => clearInterval(t);
  }, [load]);

  useEffect(() => {
    loadSlow();
    const t = setInterval(loadSlow, 60000); // health + SLA
    return () => clearInterval(t);
  }, [loadSlow]);

  async function inject() {
    setBusy(true);
    try {
      await api.injectScenario();
      await load();
    } finally {
      setBusy(false);
    }
  }

  if (!data) return <Spinner />;

  const { org_risk, stats, active_threats, by_severity, top_incidents, risky_users, risky_assets } = data;
  const SEV = [
    ["critical", "#f43f5e"],
    ["high", "#fb923c"],
    ["medium", "#facc15"],
    ["low", "#34d399"],
  ] as const;

  const incTitle = (i: any) =>
    detName(i.det_id, lang, i.title) + (lang === "fa" && i.actor_username ? ` — ${i.actor_username}` : "");

  return (
    <>
      <PageHeader
        title={t("dash.title")}
        subtitle={t("dash.subtitle")}
        right={
          <div className="flex items-center gap-2">
            <AiBadge on={aiOn} />
            {isAdmin && (
              <button className="btn" onClick={inject} disabled={busy}>
                {busy ? t("dash.simulating") : t("dash.simulate")}
              </button>
            )}
          </div>
        }
      />

      {health?.state === "degraded" && (
        <div className="mb-4 rounded-xl border border-risk-critical/40 bg-risk-critical/10 p-4">
          <div className="flex items-center gap-2 font-medium text-risk-critical">
            <span>⚠</span> {t("health.degraded")}
          </div>
          <ul className="mt-2 space-y-1 text-xs text-slate-300">
            {(health.issues || []).map((i: any) => (
              <li key={i.key}>
                <span className="font-medium">{i.title}</span> — <span className="text-slate-400">{i.detail}</span>
              </li>
            ))}
          </ul>
          <div className="mt-2 text-[11px] text-slate-400">{t("health.warning")}</div>
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="card lg:col-span-1">
          <div className="mb-2 text-sm font-medium text-slate-300">{t("dash.overall")}</div>
          <RiskGauge score={org_risk.score} />
          <div className="mt-2 grid grid-cols-2 gap-3 text-center">
            <Metric label={t("dash.activeIncidents")} value={org_risk.active_incidents} />
            <Metric label={t("dash.eventsIngested")} value={stats.total_events} />
          </div>
          <div className="mt-4">
            <div className="mb-2 text-xs uppercase tracking-wide text-slate-500">{t("dash.bySeverity")}</div>
            <div className="grid grid-cols-4 gap-2">
              {SEV.map(([label, color]) => (
                <div key={label} className="rounded-lg border border-ink-700/60 bg-ink-850/60 py-2 text-center">
                  <div className="text-lg font-semibold" style={{ color }}>
                    {by_severity?.[label] ?? 0}
                  </div>
                  <div className="text-[10px] uppercase tracking-wide text-slate-500">{t(`sev.${label}`)}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="card lg:col-span-2">
          <div className="mb-3 text-sm font-medium text-slate-300">{t("dash.activeThreats")}</div>
          <div className="grid gap-3 sm:grid-cols-2">
            {active_threats.length === 0 && <p className="text-sm text-slate-500">{t("dash.noThreats")}</p>}
            {active_threats.map((th: any) => (
              <div key={`${th.det_id}-${th.threat_type}`} className="rounded-xl border border-ink-700/60 bg-ink-850/60 p-4">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-white">{detName(th.det_id, lang, th.threat_type)}</span>
                  <RiskPill score={th.max_score} />
                </div>
                <div className="mt-1 text-xs text-slate-400">
                  <span className="font-mono text-accent-soft">{th.det_id}</span> · {th.count} {t("dash.activeCount")}
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 grid grid-cols-3 gap-3">
            <Metric label={t("dash.totalIncidents")} value={stats.total_incidents} />
            <Metric label={t("dash.resolved")} value={stats.resolved_incidents} />
            <Metric label={t("dash.pendingActions")} value={stats.pending_actions} />
          </div>
        </div>
      </div>

      {sla && (
        <div className="card mt-5">
          <div className="mb-3 flex items-baseline justify-between">
            <span className="text-sm font-medium text-slate-300">{t("sla.title")}</span>
            <span className="text-[11px] text-slate-500">{t("sla.window")}</span>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Metric label={t("sla.mtta")} value={fmtMinutes(sla.mtta_minutes)} />
            <Metric label={t("sla.mttr")} value={fmtMinutes(sla.mttr_minutes)} />
            <Metric
              label={t("sla.autonomous")}
              value={sla.autonomous_pct === null || sla.autonomous_pct === undefined ? "—" : `${sla.autonomous_pct}%`}
            />
            <Metric
              label={t("sla.fpRate")}
              value={sla.false_positive_rate === null || sla.false_positive_rate === undefined
                ? "—" : `${sla.false_positive_rate}%`}
            />
          </div>
        </div>
      )}

      <div className="mt-5 grid gap-5 lg:grid-cols-3">
        <div className="card">
          <SectionTitle>{t("dash.riskyUsers")}</SectionTitle>
          <ul className="space-y-2">
            {risky_users.map((u: any) => (
              <li key={u.username} className="flex items-center justify-between text-sm">
                <div>
                  <div className="text-slate-200">{u.display_name}</div>
                  <div className="text-xs text-slate-500">
                    {u.department} {u.is_blocked && <span className="text-risk-critical">· {t("common.blocked")}</span>}
                  </div>
                </div>
                <RiskPill score={u.risk_score} />
              </li>
            ))}
          </ul>
        </div>

        <div className="card">
          <SectionTitle>{t("dash.riskySystems")}</SectionTitle>
          <ul className="space-y-2">
            {risky_assets.map((a: any) => (
              <li key={a.name} className="flex items-center justify-between text-sm">
                <div>
                  <div className="font-mono text-slate-200">{a.name}</div>
                  <div className="text-xs text-slate-500">
                    {a.asset_type} · {t("common.sensitivity")} {a.sensitivity}/5
                  </div>
                </div>
                <RiskPill score={a.risk_score} />
              </li>
            ))}
          </ul>
        </div>

        <div className="card">
          <SectionTitle>{t("dash.topIncidents")}</SectionTitle>
          <ul className="space-y-2">
            {top_incidents.map((i: any) => (
              <li key={i.id}>
                <Link
                  href={`/incidents/${i.id}`}
                  className="flex items-center justify-between rounded-lg px-2 py-1.5 text-sm hover:bg-ink-800"
                >
                  <div className="min-w-0">
                    <div className="truncate text-slate-200">{incTitle(i)}</div>
                    <div className="text-xs text-slate-500">
                      {Math.round(i.confidence * 100)}% {t("common.confidence")}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <StatusPill status={i.status} />
                    <RiskPill score={i.final_score} />
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </>
  );
}

function fmtMinutes(v: number | null | undefined): string {
  if (v === null || v === undefined) return "—";
  if (v < 60) return `${Math.round(v)}m`;
  return `${(v / 60).toFixed(1)}h`;
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-xl border border-ink-700/60 bg-ink-850/60 p-3">
      <div className="text-xl font-semibold text-white">{value}</div>
      <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return <div className="mb-3 text-sm font-medium text-slate-300">{children}</div>;
}
