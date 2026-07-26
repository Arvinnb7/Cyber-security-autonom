"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader, RiskPill, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { useMe } from "@/lib/me";

export default function UsersAssetsPage() {
  const { t } = useLang();
  const { isAdmin } = useMe();
  const [users, setUsers] = useState<any[] | null>(null);
  const [assets, setAssets] = useState<any[] | null>(null);

  const load = useCallback(async () => {
    setUsers(await api.users());
    setAssets(await api.assets());
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (!users || !assets) return <Spinner />;

  async function togglePrivileged(u: any) {
    await api.updateMonitoredUser(u.id, { is_privileged: !u.is_privileged });
    load();
  }
  async function setSensitivity(a: any, sensitivity: number) {
    await api.updateAsset(a.id, { sensitivity });
    load();
  }

  return (
    <>
      <PageHeader title={t("nav.users")} subtitle={t("users.subtitle")} />
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="card">
          <h2 className="mb-3 text-sm font-medium text-slate-300">{t("users.users")} ({users.length})</h2>
          <div className="space-y-1.5">
            {users.map((u) => (
              <div key={u.username} className="flex items-center justify-between rounded-lg px-2 py-2 hover:bg-ink-800">
                <div>
                  <div className="text-sm text-slate-200">
                    {u.display_name}
                    {u.is_privileged && <span className="ms-2 pill bg-ink-700 text-slate-300">{t("users.privileged")}</span>}
                    {u.is_blocked && <span className="ms-2 pill bg-risk-critical/20 text-risk-critical">{t("common.blocked")}</span>}
                  </div>
                  <div className="text-xs text-slate-500">@{u.username} · {u.department} · {u.title}</div>
                </div>
                <div className="flex items-center gap-2">
                  {isAdmin && (
                    <label className="flex items-center gap-1 text-[11px] text-slate-400" title={t("case.privileged")}>
                      <input
                        type="checkbox"
                        checked={!!u.is_privileged}
                        onChange={() => togglePrivileged(u)}
                      />
                      {t("case.privileged")}
                    </label>
                  )}
                  <RiskPill score={u.risk_score} />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h2 className="mb-3 text-sm font-medium text-slate-300">{t("users.assets")} ({assets.length})</h2>
          <div className="space-y-1.5">
            {assets.map((a) => (
              <div key={a.name} className="flex items-center justify-between rounded-lg px-2 py-2 hover:bg-ink-800">
                <div>
                  <div className="font-mono text-sm text-slate-200">{a.name}</div>
                  <div className="text-xs text-slate-500">
                    {a.asset_type} · {a.owner_department} · {t("common.sensitivity")} {a.sensitivity}/5
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {isAdmin && (
                    <select
                      className="rounded-lg border border-ink-600 bg-ink-950 px-1.5 py-1 text-[11px] outline-none focus:border-accent/60"
                      value={a.sensitivity}
                      onChange={(e) => setSensitivity(a, Number(e.target.value))}
                      title={t("case.sensitivity")}
                    >
                      {[1, 2, 3, 4, 5].map((n) => (
                        <option key={n} value={n}>{n}</option>
                      ))}
                    </select>
                  )}
                  <RiskPill score={a.risk_score} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}
