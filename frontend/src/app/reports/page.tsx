"use client";

import { useEffect, useState } from "react";
import { AiBadge, PageHeader, Spinner } from "@/components/ui";
import { api } from "@/lib/api";

export default function ReportsPage() {
  const [reports, setReports] = useState<any[] | null>(null);
  const [active, setActive] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    const list = await api.reports();
    setReports(list);
    if (list.length && !active) setActive(await api.report(list[0].id));
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function generate() {
    setBusy(true);
    try {
      const r = await api.generateReport();
      setActive(r);
      await load();
    } finally {
      setBusy(false);
    }
  }

  if (!reports) return <Spinner />;

  return (
    <>
      <PageHeader
        title="Weekly Reports"
        subtitle="Auto-generated executive summaries: what happened, what's resolved, what needs action"
        right={
          <button className="btn btn-accent" onClick={generate} disabled={busy}>
            {busy ? "Generating…" : "＋ Generate now"}
          </button>
        }
      />
      <div className="grid gap-5 lg:grid-cols-4">
        <div className="card lg:col-span-1">
          <h2 className="mb-3 text-sm font-medium text-slate-300">History</h2>
          {reports.length === 0 && <p className="text-sm text-slate-500">No reports yet. Generate one.</p>}
          <div className="space-y-1.5">
            {reports.map((r) => (
              <button
                key={r.id}
                onClick={async () => setActive(await api.report(r.id))}
                className={`w-full rounded-lg px-3 py-2 text-left text-sm hover:bg-ink-800 ${
                  active?.id === r.id ? "bg-ink-800 text-accent-soft" : "text-slate-300"
                }`}
              >
                <div>{new Date(r.period_end).toLocaleDateString()}</div>
                <div className="text-xs text-slate-500">{r.stats?.total_incidents ?? 0} incidents</div>
              </button>
            ))}
          </div>
        </div>

        <div className="card lg:col-span-3">
          {active ? (
            <>
              <div className="mb-4 flex items-center justify-between">
                <span className="text-xs text-slate-500">
                  {new Date(active.period_start).toLocaleDateString()} →{" "}
                  {new Date(active.period_end).toLocaleDateString()}
                </span>
                <AiBadge on={active.ai_generated} />
              </div>
              <MiniMarkdown text={active.content_md} />
            </>
          ) : (
            <p className="text-sm text-slate-500">Select or generate a report.</p>
          )}
        </div>
      </div>
    </>
  );
}

function MiniMarkdown({ text }: { text: string }) {
  const lines = (text || "").split("\n");
  return (
    <div className="space-y-2 text-sm leading-relaxed text-slate-200">
      {lines.map((line, i) => {
        if (line.startsWith("# ")) return <h1 key={i} className="text-xl font-semibold text-white">{line.slice(2)}</h1>;
        if (line.startsWith("## ")) return <h2 key={i} className="mt-4 text-base font-semibold text-accent-soft">{line.slice(3)}</h2>;
        if (line.startsWith("### ")) return <h3 key={i} className="mt-2 font-medium text-slate-100">{line.slice(4)}</h3>;
        if (line.startsWith("- ")) return <li key={i} className="ml-5 list-disc text-slate-300">{bold(line.slice(2))}</li>;
        if (line.trim() === "") return <div key={i} className="h-1" />;
        return <p key={i}>{bold(line)}</p>;
      })}
    </div>
  );
}

function bold(s: string): React.ReactNode {
  const parts = s.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((p, i) =>
    p.startsWith("**") && p.endsWith("**") ? (
      <strong key={i} className="text-white">{p.slice(2, -2)}</strong>
    ) : (
      <span key={i}>{p}</span>
    )
  );
}
