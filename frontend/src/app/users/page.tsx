"use client";

import { useEffect, useState } from "react";
import { PageHeader, RiskPill, Spinner } from "@/components/ui";
import { api } from "@/lib/api";

export default function UsersAssetsPage() {
  const [users, setUsers] = useState<any[] | null>(null);
  const [assets, setAssets] = useState<any[] | null>(null);

  useEffect(() => {
    api.users().then(setUsers);
    api.assets().then(setAssets);
  }, []);

  if (!users || !assets) return <Spinner />;

  return (
    <>
      <PageHeader title="Users & Assets" subtitle="Identity and asset risk, continuously recomputed from incidents" />
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="card">
          <h2 className="mb-3 text-sm font-medium text-slate-300">Users ({users.length})</h2>
          <div className="space-y-1.5">
            {users.map((u) => (
              <div key={u.username} className="flex items-center justify-between rounded-lg px-2 py-2 hover:bg-ink-800">
                <div>
                  <div className="text-sm text-slate-200">
                    {u.display_name}
                    {u.is_privileged && <span className="ml-2 pill bg-ink-700 text-slate-300">privileged</span>}
                    {u.is_blocked && <span className="ml-2 pill bg-risk-critical/20 text-risk-critical">blocked</span>}
                  </div>
                  <div className="text-xs text-slate-500">
                    @{u.username} · {u.department} · {u.title}
                  </div>
                </div>
                <RiskPill score={u.risk_score} />
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h2 className="mb-3 text-sm font-medium text-slate-300">Assets ({assets.length})</h2>
          <div className="space-y-1.5">
            {assets.map((a) => (
              <div key={a.name} className="flex items-center justify-between rounded-lg px-2 py-2 hover:bg-ink-800">
                <div>
                  <div className="font-mono text-sm text-slate-200">{a.name}</div>
                  <div className="text-xs text-slate-500">
                    {a.asset_type} · {a.owner_department} · sensitivity {a.sensitivity}/5
                  </div>
                </div>
                <RiskPill score={a.risk_score} />
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}
