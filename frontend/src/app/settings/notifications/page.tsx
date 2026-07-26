"use client";

import { useEffect, useState } from "react";
import { PageHeader, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { useMe } from "@/lib/me";

const SEVERITIES = ["low", "medium", "high", "critical"];

export default function AlertingPage() {
  const { t } = useLang();
  const { isAdmin, loading } = useMe();
  const [kinds, setKinds] = useState<any[] | null>(null);
  const [channels, setChannels] = useState<any[] | null>(null);
  const [feed, setFeed] = useState<any[]>([]);
  const [adding, setAdding] = useState(false);
  const [testResult, setTestResult] = useState<Record<number, any>>({});

  async function reload() {
    setChannels(await api.channels().catch(() => []));
    setFeed(await api.notifications(15).catch(() => []));
  }
  useEffect(() => {
    if (isAdmin) {
      api.notificationKinds().then(setKinds).catch(() => setKinds([]));
      reload();
    }
  }, [isAdmin]);

  if (loading) return <Spinner />;
  if (!isAdmin) return <div className="card text-sm text-slate-400">403 — {t("role.admin")} only.</div>;
  if (!kinds || !channels) return <Spinner />;

  const kindMap: Record<string, any> = Object.fromEntries(kinds.map((k) => [k.kind, k]));

  async function toggle(c: any) {
    await api.updateChannel(c.id, { enabled: !c.enabled });
    reload();
  }
  async function setSeverity(c: any, min_severity: string) {
    await api.updateChannel(c.id, { min_severity });
    reload();
  }
  async function setFlag(c: any, key: string, value: boolean) {
    await api.updateChannel(c.id, { [key]: value });
    reload();
  }
  async function runTest(c: any) {
    setTestResult((r) => ({ ...r, [c.id]: { loading: true } }));
    try {
      const res = await api.testChannel(c.id);
      setTestResult((r) => ({ ...r, [c.id]: res }));
    } finally {
      reload();
    }
  }
  async function remove(c: any) {
    await api.deleteChannel(c.id);
    reload();
  }

  return (
    <>
      <PageHeader
        title={t("nav.alerts")}
        subtitle={t("alerts.subtitle")}
        right={
          <button className="btn btn-accent" onClick={() => setAdding(true)}>
            {t("alerts.add")}
          </button>
        }
      />

      {adding && (
        <AddForm
          kinds={kinds}
          onClose={() => setAdding(false)}
          onSaved={() => {
            setAdding(false);
            reload();
          }}
        />
      )}

      {channels.length === 0 && !adding ? (
        <div className="card text-sm text-slate-400">{t("alerts.none")}</div>
      ) : (
        <div className="grid gap-3 md:grid-cols-2">
          {channels.map((c) => {
            const meta = kindMap[c.kind] || {};
            const tr = testResult[c.id];
            return (
              <div key={c.id} className="card">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-white">{c.display_name}</span>
                      <StatusBadge status={c.status} t={t} />
                    </div>
                    <div className="mt-0.5 text-xs text-slate-500">{meta.label || c.kind}</div>
                  </div>
                  <span className={`pill ${c.enabled ? "bg-risk-low/15 text-risk-low" : "bg-ink-800 text-slate-500"}`}>
                    {c.enabled ? t("alerts.enabled") : t("alerts.disabled")}
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
                      <span className="text-slate-500">•••••• {t("alerts.secretSet")}</span>
                    </div>
                  ))}
                  {c.last_sent && (
                    <div className="flex justify-between">
                      <span className="text-slate-500">{t("alerts.lastSent")}</span>
                      <span className="text-slate-300">{new Date(c.last_sent).toLocaleString()}</span>
                    </div>
                  )}
                </div>

                <div className="mt-3 rounded-lg border border-ink-700/60 bg-ink-850/60 p-2.5">
                  <label className="mb-1 block text-[11px] text-slate-400">{t("alerts.minSeverity")}</label>
                  <select
                    className="w-full rounded-lg border border-ink-600 bg-ink-950 px-2 py-1.5 text-xs outline-none focus:border-accent/60"
                    value={c.min_severity}
                    onChange={(e) => setSeverity(c, e.target.value)}
                  >
                    {SEVERITIES.map((s) => (
                      <option key={s} value={s}>
                        {t(`sev.${s}`)}
                      </option>
                    ))}
                  </select>
                  <div className="mt-2 flex flex-col gap-1.5">
                    <label className="flex items-center gap-2 text-xs text-slate-300">
                      <input
                        type="checkbox"
                        checked={c.notify_on_incident}
                        onChange={(e) => setFlag(c, "notify_on_incident", e.target.checked)}
                      />
                      {t("alerts.onIncident")}
                    </label>
                    <label className="flex items-center gap-2 text-xs text-slate-300">
                      <input
                        type="checkbox"
                        checked={c.notify_on_approval}
                        onChange={(e) => setFlag(c, "notify_on_approval", e.target.checked)}
                      />
                      {t("alerts.onApproval")}
                    </label>
                    <label className="flex items-center gap-2 text-xs text-slate-300">
                      <input
                        type="checkbox"
                        checked={c.notify_on_health}
                        onChange={(e) => setFlag(c, "notify_on_health", e.target.checked)}
                      />
                      {t("alerts.onHealth")}
                    </label>
                  </div>
                </div>

                {tr && !tr.loading && (
                  <div className={`mt-3 rounded-lg p-2 text-xs ${tr.ok ? "bg-risk-low/10 text-risk-low" : "bg-risk-critical/10 text-risk-critical"}`}>
                    {tr.ok ? "✓ " : "✕ "} {tr.message}
                  </div>
                )}
                {c.last_error && !tr && (
                  <div className="mt-3 rounded-lg bg-risk-critical/10 p-2 text-xs text-risk-critical">{c.last_error}</div>
                )}

                <div className="mt-3 flex flex-wrap gap-2">
                  <button className="btn" onClick={() => runTest(c)} disabled={tr?.loading}>
                    {tr?.loading ? t("alerts.testing") : t("alerts.test")}
                  </button>
                  <button className="btn" onClick={() => toggle(c)}>
                    {c.enabled ? t("alerts.disable") : t("alerts.enable")}
                  </button>
                  <button className="btn btn-danger" onClick={() => remove(c)}>
                    {t("alerts.delete")}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div className="mt-6">
        <h2 className="mb-2 text-sm font-medium text-slate-300">{t("alerts.recent")}</h2>
        {feed.length === 0 ? (
          <div className="card text-sm text-slate-500">{t("alerts.recentEmpty")}</div>
        ) : (
          <div className="card divide-y divide-ink-800">
            {feed.map((n) => (
              <div key={n.id} className="flex items-center justify-between gap-3 py-2 text-xs">
                <span className="truncate text-slate-300">{n.subject}</span>
                <span className="flex shrink-0 items-center gap-2">
                  <span className={`pill ${n.status === "sent" ? "bg-risk-low/15 text-risk-low" : "bg-risk-critical/15 text-risk-critical"}`}>
                    {t(`status.${n.status}`) !== `status.${n.status}` ? t(`status.${n.status}`) : n.status}
                  </span>
                  <span className="text-slate-500">{new Date(n.created_at).toLocaleString()}</span>
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}

function StatusBadge({ status, t }: { status: string; t: (k: string) => string }) {
  const map: Record<string, [string, string]> = {
    connected: ["#34d399", t("alerts.statusConnected")],
    error: ["#f43f5e", t("alerts.statusError")],
    unknown: ["#94a3b8", t("alerts.statusUnknown")],
  };
  const [color, label] = map[status] || map.unknown;
  return (
    <span className="pill" style={{ background: `${color}22`, color }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {label}
    </span>
  );
}

function AddForm({ kinds, onClose, onSaved }: { kinds: any[]; onClose: () => void; onSaved: () => void }) {
  const { t } = useLang();
  const [kind, setKind] = useState(kinds[0]?.kind || "");
  const [displayName, setDisplayName] = useState("");
  const [minSeverity, setMinSeverity] = useState("high");
  const [onIncident, setOnIncident] = useState(true);
  const [onApproval, setOnApproval] = useState(true);
  const [creds, setCreds] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const meta = kinds.find((k) => k.kind === kind);

  async function save() {
    setSaving(true);
    try {
      await api.createChannel({
        kind,
        display_name: displayName || meta?.label || kind,
        min_severity: minSeverity,
        notify_on_incident: onIncident,
        notify_on_approval: onApproval,
        credentials: creds,
      });
      onSaved();
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="card mb-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("alerts.kind")}>
          <select
            className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent/60"
            value={kind}
            onChange={(e) => {
              setKind(e.target.value);
              setCreds({});
            }}
          >
            {kinds.map((k) => (
              <option key={k.kind} value={k.kind}>
                {k.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label={t("alerts.displayName")}>
          <input
            className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent/60"
            value={displayName}
            placeholder={meta?.label || ""}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </Field>
      </div>

      {meta?.doc && <p className="mt-3 text-xs text-slate-500">{meta.doc}</p>}

      <div className="mt-3 grid gap-4 sm:grid-cols-2">
        <Field label={t("alerts.minSeverity")}>
          <select
            className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-sm outline-none focus:border-accent/60"
            value={minSeverity}
            onChange={(e) => setMinSeverity(e.target.value)}
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {t(`sev.${s}`)}
              </option>
            ))}
          </select>
          <p className="mt-1 text-[11px] text-slate-500">{t("alerts.minSeverityHint")}</p>
        </Field>
        <div className="flex flex-col justify-center gap-2">
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={onIncident} onChange={(e) => setOnIncident(e.target.checked)} />
            {t("alerts.onIncident")}
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={onApproval} onChange={(e) => setOnApproval(e.target.checked)} />
            {t("alerts.onApproval")}
          </label>
        </div>
      </div>

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
        <button className="btn" onClick={onClose}>
          {t("alerts.cancel")}
        </button>
        <button className="btn btn-accent" onClick={save} disabled={saving}>
          {saving ? t("alerts.saving") : t("alerts.save")}
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
