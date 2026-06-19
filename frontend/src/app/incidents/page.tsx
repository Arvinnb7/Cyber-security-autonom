"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { PageHeader, RiskPill, SeverityPill, Spinner, StatusPill } from "@/components/ui";
import { api, threatLabel } from "@/lib/api";

const FILTERS = ["all", "open", "investigating", "resolved", "dismissed"];

export default function IncidentsPage() {
  const [items, setItems] = useState<any[] | null>(null);
  const [filter, setFilter] = useState("all");

  const load = useCallback(async () => {
    setItems(await api.incidents(filter === "all" ? undefined : filter));
  }, [filter]);

  useEffect(() => {
    load();
    const t = setInterval(load, 6000);
    return () => clearInterval(t);
  }, [load]);

  return (
    <>
      <PageHeader
        title="Incidents"
        subtitle="Correlated, scored and explained automatically — newest and riskiest first"
        right={
          <div className="flex flex-wrap gap-1.5">
            {FILTERS.map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`pill capitalize ${
                  filter === f ? "bg-accent/20 text-accent-soft" : "bg-ink-800 text-slate-400"
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        }
      />

      {!items ? (
        <Spinner />
      ) : items.length === 0 ? (
        <div className="card text-sm text-slate-400">No incidents for this filter.</div>
      ) : (
        <div className="space-y-2.5">
          {items.map((i) => (
            <Link key={i.id} href={`/incidents/${i.id}`} className="card block transition hover:border-accent/40">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-white">{i.title || threatLabel(i.threat_type)}</span>
                    <SeverityPill severity={i.severity} />
                    <StatusPill status={i.status} />
                  </div>
                  <div className="mt-1 text-xs text-slate-500">
                    <span className="font-mono text-accent-soft">{i.det_id}</span> · {Math.round(i.confidence * 100)}% confidence
                    {i.target_asset && <> · target {i.target_asset}</>}
                  </div>
                </div>
                <RiskPill score={i.final_score} />
              </div>
            </Link>
          ))}
        </div>
      )}
    </>
  );
}
