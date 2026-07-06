"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { AiBadge, ApprovalPill, PageHeader, RiskPill, ScoreBar, SeverityPill, Spinner, StatusPill } from "@/components/ui";
import { api, threatLabel } from "@/lib/api";
import { detName, useLang } from "@/lib/i18n";
import { useMe } from "@/lib/me";

export default function IncidentDetail() {
  const { t, lang } = useLang();
  const { isAdmin, isAnalystUp } = useMe();
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
  const title = detName(inc.det_id, lang, inc.title) + (lang === "fa" && inc.actor_username ? ` — ${inc.actor_username}` : "");

  return (
    <>
      <PageHeader
        title={title}
        subtitle={`${inc.det_id} · ${detName(inc.det_id, lang, threatLabel(inc.threat_type))} · ${t("det.detected")} ${new Date(inc.created_at).toLocaleString()}`}
        right={
          <div className="flex items-center gap-2">
            <SeverityPill severity={inc.severity} />
            <ApprovalPill level={inc.human_approval_required} />
            <Link href="/incidents" className="btn">
              {t("det.back")}
            </Link>
          </div>
        }
      />

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="space-y-5 lg:col-span-2">
          <div className="card">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-medium text-slate-300">{t("det.assessment")}</h2>
              <div className="flex items-center gap-2">
                <AiBadge on={inc.ai_generated} />
                <span className="pill bg-accent/15 text-accent-soft">
                  {summary.likelihood_pct ?? Math.round(inc.confidence * 100)}% {t("det.likely")}
                </span>
              </div>
            </div>
            <p className="text-[15px] leading-relaxed text-slate-200">{inc.ai_analysis}</p>
          </div>

          <div className="card">
            <h2 className="mb-3 text-sm font-medium text-slate-300">{t("det.execSummary")}</h2>
            <div className="grid gap-3 sm:grid-cols-2">
              <SummaryCell label={t("sum.what")} value={summary.what_happened} />
              <SummaryCell label={t("sum.why")} value={summary.why_it_matters} />
              <SummaryCell label={t("sum.evidence")} value={summary.evidence} />
              <SummaryCell label={t("sum.damage")} value={summary.potential_damage} />
              <SummaryCell label={t("sum.action")} value={summary.recommended_action} accent />
              <SummaryCell label={t("sum.approval")} value={summary.human_approval_required} />
            </div>
          </div>

          <div className="card">
            <h2 className="mb-3 text-sm font-medium text-slate-300">{t("det.evidenceFactors")}</h2>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <div className="mb-2 text-[11px] uppercase tracking-wide text-slate-500">{t("det.requiredEvidence")}</div>
                <ul className="space-y-1 text-sm">
                  {(inc.evidence || []).map((e: any) => (
                    <li key={e.field} className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-slate-400">{e.field}</span>
                      <span className={e.observed ? "text-slate-200" : "text-slate-600"}>
                        {e.observed ? <span className="truncate" title={e.value}>{e.value}</span> : "—"}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <div className="mb-2 text-[11px] uppercase tracking-wide text-slate-500">{t("det.scoringFactors")}</div>
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
            <h2 className="mb-3 text-sm font-medium text-slate-300">{t("det.timeline")}</h2>
            <ol className="timeline-rail relative space-y-4 border-l border-ink-700 ps-5">
              {inc.timeline.map((e: any, idx: number) => (
                <li key={idx} className="relative">
                  <span className="timeline-dot absolute -left-[1.46rem] top-1 h-2.5 w-2.5 rounded-full bg-accent" />
                  <div className="text-xs text-slate-500">{new Date(e.time).toLocaleString()}</div>
                  <div className="text-sm text-slate-200">
                    <span className="font-medium text-white">{threatLabel(e.action)}</span>{" "}
                    {t("common.via")} <span className="font-mono text-accent-soft">{e.source}</span>
                  </div>
                  <div className="text-xs text-slate-400">
                    {e.actor && <>{t("common.actor")} {e.actor} </>}
                    {e.location && <>· {e.location} </>}
                    {e.asset && <>· {e.asset}</>}
                  </div>
                </li>
              ))}
            </ol>
          </div>
        </div>

        <div className="space-y-5">
          <div className="card">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-medium text-slate-300">{t("det.riskScores")}</h2>
              <RiskPill score={s.final_score} />
            </div>
            <div className="space-y-3">
              <ScoreBar label={t("score.threat")} value={s.threat_score} />
              <ScoreBar label={t("score.user")} value={s.user_risk} />
              <ScoreBar label={t("score.asset")} value={s.asset_risk} />
              <ScoreBar label={t("score.business")} value={s.business_impact} />
              <div className="mt-2 border-t border-ink-700 pt-3">
                <ScoreBar label={t("score.final")} value={s.final_score} />
              </div>
            </div>
          </div>

          {(isAdmin || (inc.actions?.length > 0)) && (
            <div className="card">
              <h2 className="mb-3 text-sm font-medium text-slate-300">{t("det.response")}</h2>
              {isAdmin && (
                <div className="grid grid-cols-2 gap-2">
                  {actions.map((a) => (
                    <button
                      key={a.type}
                      className="btn"
                      onClick={() => setConfirm({ type: a.type, label: t(`action.${a.type}`), target: defaultTarget })}
                    >
                      {t(`action.${a.type}`)}
                    </button>
                  ))}
                </div>
              )}
              {inc.actions?.length > 0 && (
                <div className={`space-y-1.5 text-xs ${isAdmin ? "mt-4 border-t border-ink-700 pt-3" : ""}`}>
                  <div className="text-slate-500">{t("det.audit")}</div>
                  {inc.actions.map((a: any) => (
                    <div key={a.id} className="flex items-center justify-between">
                      <span className="text-slate-300">{t(`action.${a.action_type}`)} → {a.target}</span>
                      <StatusPill status={a.status} />
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          <div className="card">
            <h2 className="mb-3 text-sm font-medium text-slate-300">{t("det.triage")}</h2>
            {isAnalystUp && (
              <div className="flex flex-wrap gap-2">
                <button className="btn" onClick={() => setStatus("investigating")}>{t("triage.investigating")}</button>
                <button className="btn btn-accent" onClick={() => setStatus("resolved")}>{t("triage.resolve")}</button>
                <button className="btn" onClick={() => setStatus("dismissed")}>{t("triage.dismiss")}</button>
              </div>
            )}
            <div className="mt-3 flex items-center gap-2 text-xs text-slate-500">
              {t("det.currentStatus")} <StatusPill status={inc.status} />
            </div>
          </div>
        </div>
      </div>

      {confirm && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" onClick={() => setConfirm(null)}>
          <div className="card w-full max-w-md" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-lg font-semibold text-white">{t("det.confirm")} {confirm.label}</h3>
            <p className="mt-2 text-sm text-slate-400">{t("det.confirmBody")}</p>
            <label className="mt-4 block text-xs text-slate-400">{t("det.targetField")}</label>
            <input
              className="mt-1 w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent/60"
              value={confirm.target}
              onChange={(e) => setConfirm({ ...confirm, target: e.target.value })}
            />
            <div className="mt-5 flex justify-end gap-2">
              <button className="btn" onClick={() => setConfirm(null)}>{t("det.cancel")}</button>
              <button className="btn btn-danger" onClick={runAction} disabled={busy || !confirm.target}>
                {busy ? t("det.executing") : t("det.approveExecute")}
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
