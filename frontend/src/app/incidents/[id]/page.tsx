"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { AiBadge, ApprovalPill, PageHeader, RiskPill, ScoreBar, SeverityPill, Spinner, StatusPill } from "@/components/ui";
import { api, threatLabel } from "@/lib/api";

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const incidentId = Number(id);
  const [inc, setInc] = useState<any>(null);
  const [actions, setActions] = useState<any[]>([]);
  const [confirm, setConfirm] = useState<{ type: string; label: string; target: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const [detail, avail] = await Promise.all([api.incident(incidentId), api.availableActions()]);
    setInc(detail);
    setActions(avail.actions);
  }, [incidentId]);

  useEffect(() => {
    load();
  }, [load]);

  async function runAction() {
    if (!confirm) return;
    setBusy(true);
    try {
      const created = await api.requestAction(confirm.type, confirm.target, incidentId);
      await api.approveAction(created.id); // manager confirmed in this dialog
      setConfirm(null);
      await load();
    } finally {
      setBusy(false);
    }
  }

  async function setStatus(status: string) {
    await api.setIncidentStatus(incidentId, status);
    await load();
  }

  if (!inc) return <Spinner />;

  const s = inc.scores;
  const summary = inc.ai_summary || {};
  const defaultTarget = inc.actor_username || inc.target_asset || "";

  return (
    <>
      <PageHeader
        title={inc.title}
        subtitle={`${inc.det_id} · ${threatLabel(inc.threat_type)} · detected ${new Date(inc.created_at).toLocaleString()}`}
        right={
          <div className="flex items-center gap-2">
            <SeverityPill severity={inc.severity} />
            <ApprovalPill level={inc.human_approval_required} />
            <Link href="/incidents" className="btn">
              ← Back
            </Link>
          </div>
        }
      />

      <div className="grid gap-5 lg:grid-cols-3">
        {/* Left: AI narrative + exec summary + timeline */}
        <div className="space-y-5 lg:col-span-2">
          <div className="card">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-medium text-slate-300">Analyst assessment</h2>
              <div className="flex items-center gap-2">
                <AiBadge on={inc.ai_generated} />
                <span className="pill bg-accent/15 text-accent-soft">
                  {summary.likelihood_pct ?? Math.round(inc.confidence * 100)}% likely
                </span>
              </div>
            </div>
            <p className="text-[15px] leading-relaxed text-slate-200">{inc.ai_analysis}</p>
          </div>

          <div className="card">
            <h2 className="mb-3 text-sm font-medium text-slate-300">Executive summary</h2>
            <div className="grid gap-3 sm:grid-cols-2">
              <SummaryCell label="What happened" value={summary.what_happened} />
              <SummaryCell label="Why it matters" value={summary.why_it_matters} />
              <SummaryCell label="Supporting evidence" value={summary.evidence} />
              <SummaryCell label="Potential damage" value={summary.potential_damage} />
              <SummaryCell label="Recommended action" value={summary.recommended_action} accent />
              <SummaryCell label="Human approval" value={summary.human_approval_required} />
            </div>
          </div>

          <div className="card">
            <h2 className="mb-3 text-sm font-medium text-slate-300">Evidence & matched factors</h2>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <div className="mb-2 text-[11px] uppercase tracking-wide text-slate-500">Required evidence</div>
                <ul className="space-y-1 text-sm">
                  {(inc.evidence || []).map((e: any) => (
                    <li key={e.field} className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-slate-400">{e.field}</span>
                      <span className={e.observed ? "text-slate-200" : "text-slate-600"}>
                        {e.observed ? (
                          <span className="truncate" title={e.value}>{e.value}</span>
                        ) : (
                          "—"
                        )}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <div className="mb-2 text-[11px] uppercase tracking-wide text-slate-500">
                  Scoring factors (→ threat score)
                </div>
                <ul className="space-y-1 text-sm">
                  {Object.entries(inc.matched_factors || {}).map(([k, v]: any) => (
                    <li key={k} className="flex items-center justify-between gap-2">
                      <span className="text-slate-300">{threatLabel(k)}</span>
                      <span className="font-mono text-accent-soft">+{v as number}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          <div className="card">
            <h2 className="mb-3 text-sm font-medium text-slate-300">Attack timeline</h2>
            <ol className="relative space-y-4 border-l border-ink-700 pl-5">
              {inc.timeline.map((e: any, idx: number) => (
                <li key={idx} className="relative">
                  <span className="absolute -left-[1.46rem] top-1 h-2.5 w-2.5 rounded-full bg-accent" />
                  <div className="text-xs text-slate-500">{new Date(e.time).toLocaleString()}</div>
                  <div className="text-sm text-slate-200">
                    <span className="font-medium text-white">{threatLabel(e.action)}</span>{" "}
                    via <span className="font-mono text-accent-soft">{e.source}</span>
                  </div>
                  <div className="text-xs text-slate-400">
                    {e.actor && <>actor {e.actor} </>}
                    {e.location && <>· {e.location} </>}
                    {e.asset && <>· {e.asset}</>}
                  </div>
                </li>
              ))}
            </ol>
          </div>
        </div>

        {/* Right: scores + response */}
        <div className="space-y-5">
          <div className="card">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-medium text-slate-300">Risk scores</h2>
              <RiskPill score={s.final_score} />
            </div>
            <div className="space-y-3">
              <ScoreBar label="Threat severity" value={s.threat_score} />
              <ScoreBar label="User risk" value={s.user_risk} />
              <ScoreBar label="Asset risk" value={s.asset_risk} />
              <ScoreBar label="Business impact" value={s.business_impact} />
              <div className="mt-2 border-t border-ink-700 pt-3">
                <ScoreBar label="FINAL SCORE" value={s.final_score} />
              </div>
            </div>
          </div>

          <div className="card">
            <h2 className="mb-3 text-sm font-medium text-slate-300">Response (needs approval)</h2>
            <div className="grid grid-cols-2 gap-2">
              {actions.map((a) => (
                <button
                  key={a.type}
                  className="btn"
                  onClick={() => setConfirm({ type: a.type, label: a.label, target: defaultTarget })}
                >
                  {a.label}
                </button>
              ))}
            </div>
            {inc.actions?.length > 0 && (
              <div className="mt-4 space-y-1.5 border-t border-ink-700 pt-3 text-xs">
                <div className="text-slate-500">Audit trail</div>
                {inc.actions.map((a: any) => (
                  <div key={a.id} className="flex items-center justify-between">
                    <span className="text-slate-300">
                      {threatLabel(a.action_type)} → {a.target}
                    </span>
                    <StatusPill status={a.status} />
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="card">
            <h2 className="mb-3 text-sm font-medium text-slate-300">Triage</h2>
            <div className="flex flex-wrap gap-2">
              <button className="btn" onClick={() => setStatus("investigating")}>Investigating</button>
              <button className="btn btn-accent" onClick={() => setStatus("resolved")}>Resolve</button>
              <button className="btn" onClick={() => setStatus("dismissed")}>Dismiss</button>
            </div>
            <div className="mt-3 text-xs text-slate-500">
              Current status: <StatusPill status={inc.status} />
            </div>
          </div>
        </div>
      </div>

      {confirm && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" onClick={() => setConfirm(null)}>
          <div className="card w-full max-w-md" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-lg font-semibold text-white">Confirm: {confirm.label}</h3>
            <p className="mt-2 text-sm text-slate-400">
              This response action requires manager approval before it is executed.
            </p>
            <label className="mt-4 block text-xs text-slate-400">Target</label>
            <input
              className="mt-1 w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent/60"
              value={confirm.target}
              onChange={(e) => setConfirm({ ...confirm, target: e.target.value })}
            />
            <div className="mt-5 flex justify-end gap-2">
              <button className="btn" onClick={() => setConfirm(null)}>Cancel</button>
              <button className="btn btn-danger" onClick={runAction} disabled={busy || !confirm.target}>
                {busy ? "Executing…" : "Approve & execute"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function SummaryCell({ label, value, accent }: { label: string; value?: string; accent?: boolean }) {
  return (
    <div className={`rounded-xl border p-3 ${accent ? "border-accent/30 bg-accent/10" : "border-ink-700/60 bg-ink-850/60"}`}>
      <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 text-sm text-slate-200">{value || "—"}</div>
    </div>
  );
}
