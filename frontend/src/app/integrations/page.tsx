"use client";

import { useEffect, useState } from "react";
import { PageHeader, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useLang } from "@/lib/i18n";

export default function IntegrationsPage() {
  const { t } = useLang();
  const [providers, setProviders] = useState<any[] | null>(null);
  const [connections, setConnections] = useState<any[] | null>(null);
  const [adding, setAdding] = useState(false);
  const [testResult, setTestResult] = useState<Record<number, any>>({});

  async function reload() {
    setConnections(await api.connections());
  }

  useEffect(() => {
    api.providers().then(setProviders);
    reload();
  }, []);

  if (!providers || !connections) return <Spinner />;
  const providerMap: Record<string, any> = Object.fromEntries(providers.map((p) => [p.provider, p]));

  async function toggle(c: any) {
    await api.updateConnection(c.id, { enabled: !c.enabled });
    reload();
  }
  async function runTest(c: any) {
    setTestResult((r) => ({ ...r, [c.id]: { loading: true } }));
    try {
      const res = await api.testConnection(c.id);
      setTestResult((r) => ({ ...r, [c.id]: res }));
    } finally {
      reload();
    }
  }
  async function remove(c: any) {
    await api.deleteConnection(c.id);
    reload();
  }
  async function toggleActions(c: any) {
    await api.updateConnection(c.id, { allow_actions: !c.allow_actions });
    reload();
  }

  return (
    <>
      <PageHeader
        title={t("nav.integrations")}
        subtitle={t("int.subtitle")}
        right={
          <button className="btn btn-accent" onClick={() => setAdding(true)}>
            {t("int.add")}
          </button>
        }
      />

      {adding && (
        <AddForm
          providers={providers}
          onClose={() => setAdding(false)}
          onSaved={() => {
            setAdding(false);
            reload();
          }}
        />
      )}

      {connections.length === 0 && !adding ? (
        <div className="card text-sm text-slate-400">{t("int.none")}</div>
      ) : (
        <div className="grid gap-3 md:grid-cols-2">
          {connections.map((c) => {
            const meta = providerMap[c.provider] || {};
            const tr = testResult[c.id];
            return (
              <div key={c.id} className="card">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-white">{c.display_name}</span>
                      <StatusBadge status={c.status} t={t} />
                    </div>
                    <div className="mt-0.5 text-xs text-slate-500">
                      {meta.label || c.provider}
                      <span className={`ms-2 ${meta.implemented ? "text-risk-low" : "text-slate-500"}`}>
                        · {meta.implemented ? t("int.live") : t("int.pending")}
                      </span>
                    </div>
                  </div>
                  <span className={`pill ${c.enabled ? "bg-risk-low/15 text-risk-low" : "bg-ink-800 text-slate-500"}`}>
                    {c.enabled ? t("int.enabled") : t("int.disabled")}
                  </span>
                </div>

                <div className="mt-3 space-y-1 text-xs text-slate-400">
                  {Object.entries(c.config || {}).map(([k, v]: any) => (
                    <div key={k} className="flex justify-between">
                      <span className="font-mono text-slate-500">{k}</span>
                      <span className="text-slate-300">{String(v)}</span>
                    </div>
                  ))}
                  {(c.secrets_set || []).map((k: string) => (
                    <div key={k} className="flex justify-between">
                      <span className="font-mono text-slate-500">{k}</span>
                      <span className="text-slate-500">•••••• {t("int.secretSet")}</span>
                    </div>
                  ))}
                  {c.last_sync && (
                    <div className="flex justify-between">
                      <span className="text-slate-500">{t("int.lastSync")}</span>
                      <span className="text-slate-300">{new Date(c.last_sync).toLocaleString()}</span>
                    </div>
                  )}
                </div>

                {tr && !tr.loading && (
                  <div className={`mt-3 rounded-lg p-2 text-xs ${tr.ok ? "bg-risk-low/10 text-risk-low" : "bg-risk-critical/10 text-risk-critical"}`}>
                    {tr.ok ? "✓ " : "✕ "} {tr.message}
                  </div>
                )}
                {c.last_error && !tr && (
                  <div className="mt-3 rounded-lg bg-risk-critical/10 p-2 text-xs text-risk-critical">{c.last_error}</div>
                )}

                {(c.supported_actions?.length > 0) && (
                  <div className="mt-3 rounded-lg border border-ink-700/60 bg-ink-850/60 p-2.5">
                    <div className="flex items-center justify-between">
                      <div className="text-xs">
                        <div className="text-slate-300">{t("int.response")}</div>
                        <div className={c.allow_actions ? "text-risk-low" : "text-slate-500"}>
                          {c.allow_actions ? `● ${t("int.responseOn")}` : `○ ${t("int.responseOff")}`}
                        </div>
                      </div>
                      <button className="btn px-2.5 py-1 text-xs" onClick={() => toggleActions(c)}>
                        {c.allow_actions ? t("int.disableActions") : t("int.enableActions")}
                      </button>
                    </div>
                    <div className="mt-1.5 text-[11px] text-slate-500">{t("int.responseHint")}</div>
                  </div>
                )}

                <div className="mt-3 flex flex-wrap gap-2">
                  <button className="btn" onClick={() => runTest(c)} disabled={tr?.loading}>
                    {tr?.loading ? t("int.testing") : t("int.test")}
                  </button>
                  <button className="btn" onClick={() => toggle(c)}>
                    {c.enabled ? t("int.disable") : t("int.enable")}
                  </button>
                  <button className="btn btn-danger" onClick={() => remove(c)}>
                    {t("int.delete")}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

function StatusBadge({ status, t }: { status: string; t: (k: string) => string }) {
  const map: Record<string, [string, string]> = {
    connected: ["#34d399", t("int.statusConnected")],
    error: ["#f43f5e", t("int.statusError")],
    unknown: ["#94a3b8", t("int.statusUnknown")],
  };
  const [color, label] = map[status] || map.unknown;
  return (
    <span className="pill" style={{ background: `${color}22`, color }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {label}
    </span>
  );
}

function AddForm({ providers, onClose, onSaved }: { providers: any[]; onClose: () => void; onSaved: () => void }) {
  const { t } = useLang();
  const [provider, setProvider] = useState(providers[0]?.provider || "");
  const [displayName, setDisplayName] = useState("");
  const [creds, setCreds] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const meta = providers.find((p) => p.provider === provider);

  async function save() {
    setSaving(true);
    try {
      await api.createConnection(provider, displayName || meta?.label || provider, creds);
      onSaved();
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="card mb-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("int.provider")}>
          <select
            className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent/60"
            value={provider}
            onChange={(e) => {
              setProvider(e.target.value);
              setCreds({});
            }}
          >
            {providers.map((p) => (
              <option key={p.provider} value={p.provider}>
                {p.label} {p.implemented ? "" : "(connector pending)"}
              </option>
            ))}
          </select>
        </Field>
        <Field label={t("int.displayName")}>
          <input
            className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent/60"
            value={displayName}
            placeholder={meta?.label || ""}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </Field>
      </div>

      {meta?.doc && <p className="mt-3 text-xs text-slate-500">{meta.doc}</p>}

      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        {(meta?.fields || []).map((f: any) => (
          <Field key={f.key} label={`${f.label}${f.secret ? " 🔒" : ""}`}>
            <input
              type={f.secret ? "password" : "text"}
              placeholder={f.placeholder || ""}
              className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent/60"
              value={creds[f.key] || ""}
              onChange={(e) => setCreds((c) => ({ ...c, [f.key]: e.target.value }))}
            />
          </Field>
        ))}
      </div>

      <div className="mt-4 flex justify-end gap-2">
        <button className="btn" onClick={onClose}>{t("int.cancel")}</button>
        <button className="btn btn-accent" onClick={save} disabled={saving}>
          {saving ? t("int.saving") : t("int.save")}
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
