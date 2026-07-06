"use client";

import { useEffect, useState } from "react";
import { PageHeader, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { useMe } from "@/lib/me";

const ROLES = ["admin", "analyst", "viewer"];

export default function TeamPage() {
  const { t } = useLang();
  const { me, isAdmin, loading } = useMe();
  const [accounts, setAccounts] = useState<any[] | null>(null);
  const [adding, setAdding] = useState(false);

  async function reload() {
    setAccounts(await api.accounts().catch(() => []));
  }
  useEffect(() => {
    if (isAdmin) reload();
  }, [isAdmin]);

  if (loading) return <Spinner />;
  if (!isAdmin)
    return (
      <div className="card text-sm text-slate-400">403 — {t("role.admin")} only.</div>
    );
  if (!accounts) return <Spinner />;

  async function toggle(a: any) {
    await api.updateAccount(a.id, { is_active: !a.is_active });
    reload();
  }
  async function resetPw(a: any) {
    const pw = window.prompt(`${t("team.resetPw")} — ${a.username}`);
    if (pw) {
      await api.updateAccount(a.id, { password: pw });
      reload();
    }
  }
  async function remove(a: any) {
    await api.deleteAccount(a.id);
    reload();
  }

  return (
    <>
      <PageHeader
        title={t("nav.team")}
        subtitle={t("team.subtitle")}
        right={
          <button className="btn btn-accent" onClick={() => setAdding(true)}>
            {t("team.add")}
          </button>
        }
      />

      {adding && <AddForm onClose={() => setAdding(false)} onSaved={() => { setAdding(false); reload(); }} />}

      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-start text-xs uppercase tracking-wide text-slate-500">
              <th className="px-2 py-2 text-start">{t("team.username")}</th>
              <th className="px-2 py-2 text-start">{t("team.role")}</th>
              <th className="px-2 py-2 text-start">{t("team.status")}</th>
              <th className="px-2 py-2 text-start">{t("team.lastLogin")}</th>
              <th className="px-2 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {accounts.map((a) => (
              <tr key={a.id} className="border-t border-ink-800">
                <td className="px-2 py-2 text-slate-200">
                  {a.username}
                  {me?.username === a.username && <span className="ms-2 pill bg-ink-700 text-slate-400">{t("team.you")}</span>}
                  {a.email && <div className="text-xs text-slate-500">{a.email}</div>}
                </td>
                <td className="px-2 py-2">
                  <span className="pill bg-accent/15 text-accent-soft">{t(`role.${a.role}`)}</span>
                </td>
                <td className="px-2 py-2">
                  <span className={`pill ${a.is_active ? "bg-risk-low/15 text-risk-low" : "bg-ink-800 text-slate-500"}`}>
                    {a.is_active ? t("team.active") : t("team.inactive")}
                  </span>
                </td>
                <td className="px-2 py-2 text-xs text-slate-400">
                  {a.last_login ? new Date(a.last_login).toLocaleString() : t("team.never")}
                </td>
                <td className="px-2 py-2">
                  <div className="flex flex-wrap justify-end gap-1.5">
                    <button className="btn px-2 py-1 text-xs" onClick={() => resetPw(a)}>{t("team.resetPw")}</button>
                    {me?.username !== a.username && (
                      <>
                        <button className="btn px-2 py-1 text-xs" onClick={() => toggle(a)}>
                          {a.is_active ? t("team.disable") : t("team.enable")}
                        </button>
                        <button className="btn btn-danger px-2 py-1 text-xs" onClick={() => remove(a)}>
                          {t("team.delete")}
                        </button>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function AddForm({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const { t } = useLang();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("viewer");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function save() {
    setSaving(true);
    setError("");
    try {
      await api.createAccount(username, password, role, email);
      onSaved();
    } catch (e: any) {
      setError(String(e?.message || "error"));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="card mb-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("team.username")}>
          <input className="fld" value={username} onChange={(e) => setUsername(e.target.value)} />
        </Field>
        <Field label={t("team.email")}>
          <input className="fld" value={email} onChange={(e) => setEmail(e.target.value)} />
        </Field>
        <Field label={t("team.password")}>
          <input type="password" className="fld" value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <Field label={t("team.role")}>
          <select className="fld" value={role} onChange={(e) => setRole(e.target.value)}>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {t(`role.${r}`)} — {t(`team.role${r[0].toUpperCase() + r.slice(1)}Desc`)}
              </option>
            ))}
          </select>
        </Field>
      </div>
      {error && <p className="mt-2 text-sm text-risk-critical">{error}</p>}
      <div className="mt-4 flex justify-end gap-2">
        <button className="btn" onClick={onClose}>{t("team.cancel")}</button>
        <button className="btn btn-accent" onClick={save} disabled={saving || !username || !password}>
          {saving ? t("team.saving") : t("team.save")}
        </button>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1 block text-xs text-slate-400">{label}</label>
      {children}
    </div>
  );
}
