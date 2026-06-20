"use client";

import { useEffect, useState } from "react";
import { ApprovalPill, PageHeader, SeverityPill, Spinner } from "@/components/ui";
import { api, threatLabel } from "@/lib/api";
import { useLang } from "@/lib/i18n";

export default function DetectionsPage() {
  const { t, lang } = useLang();
  const [items, setItems] = useState<any[] | null>(null);
  const [active, setActive] = useState<any>(null);

  useEffect(() => {
    api.detections().then((d) => {
      setItems(d);
      if (d.length) setActive(d[0]);
    });
  }, []);

  if (!items) return <Spinner />;

  const name = (d: any) => (lang === "fa" && d.name_fa ? d.name_fa : d.name_en);

  return (
    <>
      <PageHeader title={t("nav.detections")} subtitle={t("cat.subtitle")} />
      <div className="grid gap-5 lg:grid-cols-3">
        <div className="card lg:col-span-1">
          <div className="space-y-1.5">
            {items.map((d) => (
              <button
                key={d.det_id}
                onClick={() => setActive(d)}
                className={`w-full rounded-lg px-3 py-2.5 text-start hover:bg-ink-800 ${
                  active?.det_id === d.det_id ? "bg-ink-800" : ""
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-200">{name(d)}</span>
                  <SeverityPill severity={d.default_severity} />
                </div>
                <div className="text-xs text-slate-500">
                  <span className="font-mono text-accent-soft">{d.det_id}</span> · {d.category}
                </div>
              </button>
            ))}
          </div>
        </div>

        {active && (
          <div className="card lg:col-span-2">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-lg font-semibold text-white">{name(active)}</h2>
                <p className="text-sm text-slate-400" dir="rtl">{active.name_fa}</p>
              </div>
              <div className="flex items-center gap-2">
                <SeverityPill severity={active.default_severity} />
                <ApprovalPill level={active.human_approval_required} />
              </div>
            </div>
            <p className="mb-5 text-sm text-slate-300" dir="rtl">{active.description_fa}</p>

            <div className="grid gap-5 sm:grid-cols-2">
              <Block title={t("cat.scoringFactors")}>
                <ul className="space-y-1 text-sm">
                  {Object.entries(active.scoring_factors || {}).map(([k, v]: any) => (
                    <li key={k} className="flex items-center justify-between">
                      <span className="text-slate-300">{threatLabel(k)}</span>
                      <span className="font-mono text-accent-soft">+{v as number}</span>
                    </li>
                  ))}
                </ul>
              </Block>
              <Block title={t("cat.signals")}>
                <ul className="list-disc space-y-1 pe-4 text-sm text-slate-300" dir="rtl">
                  {(active.detection_signals || []).map((sig: string) => (
                    <li key={sig}>{sig}</li>
                  ))}
                </ul>
              </Block>
              <Block title={t("cat.dataSources")}>
                <div className="flex flex-wrap gap-1.5">
                  {(active.required_data_sources || []).map((src: string) => (
                    <span key={src} className="pill bg-ink-800 font-mono text-slate-400">{src}</span>
                  ))}
                </div>
              </Block>
              <Block title={t("cat.response")}>
                <ul className="list-disc space-y-1 pe-4 text-sm text-slate-300" dir="rtl">
                  {(active.recommended_response || []).map((r: string) => (
                    <li key={r}>{r}</li>
                  ))}
                </ul>
              </Block>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-ink-700/60 bg-ink-850/60 p-4">
      <div className="mb-2 text-[11px] uppercase tracking-wide text-slate-500">{title}</div>
      {children}
    </div>
  );
}
