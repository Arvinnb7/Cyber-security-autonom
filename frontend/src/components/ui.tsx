"use client";

import { riskBand, riskColor } from "@/lib/api";
import { useLang } from "@/lib/i18n";

export function PageHeader({ title, subtitle, right }: { title: string; subtitle?: string; right?: React.ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-white">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-400">{subtitle}</p>}
      </div>
      {right}
    </div>
  );
}

export function RiskPill({ score }: { score: number }) {
  const { t } = useLang();
  const color = riskColor(score);
  return (
    <span className="pill" style={{ background: `${color}22`, color }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {t(`band.${riskBand(score)}`)} · {Math.round(score)}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const { t } = useLang();
  const map: Record<string, string> = {
    open: "#f43f5e",
    investigating: "#fb923c",
    resolved: "#34d399",
    dismissed: "#64748b",
    pending: "#facc15",
    executed: "#34d399",
    rejected: "#64748b",
  };
  const color = map[status] || "#94a3b8";
  return (
    <span className="pill" style={{ background: `${color}22`, color }}>
      {t(`status.${status}`)}
    </span>
  );
}

export function ScoreBar({ label, value }: { label: string; value: number }) {
  const color = riskColor(value);
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs">
        <span className="text-slate-400">{label}</span>
        <span className="font-mono" style={{ color }}>{Math.round(value)}</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-ink-800">
        <div className="h-full rounded-full transition-all" style={{ width: `${value}%`, background: color }} />
      </div>
    </div>
  );
}

export function Spinner() {
  return (
    <div className="flex items-center justify-center py-20 text-slate-500">
      <span className="h-5 w-5 animate-spin rounded-full border-2 border-ink-600 border-t-accent" />
    </div>
  );
}

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#facc15",
  low: "#34d399",
};

export function SeverityPill({ severity }: { severity: string }) {
  const { t } = useLang();
  const color = SEVERITY_COLORS[severity] || "#94a3b8";
  return (
    <span className="pill" style={{ background: `${color}22`, color }}>
      {t(`sev.${severity}`)}
    </span>
  );
}

export function ApprovalPill({ level }: { level: string }) {
  const { t } = useLang();
  const color = SEVERITY_COLORS[level] || "#94a3b8";
  return (
    <span className="pill" style={{ background: `${color}1a`, color }} title="Human approval required">
      ⚖ {t("badge.approval")}: {t(`sev.${level}`)}
    </span>
  );
}

export function AiBadge({ on }: { on: boolean }) {
  const { t } = useLang();
  return (
    <span className="pill" style={{ background: on ? "#38bdf822" : "#64748b22", color: on ? "#7dd3fc" : "#94a3b8" }}>
      {on ? t("badge.claude") : t("badge.rulebased")}
    </span>
  );
}
