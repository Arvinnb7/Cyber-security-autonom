# 🛡️ Sentinel — Autonomous Network Security Monitoring

Sentinel is a high-end SOC platform that **monitors like a senior security analyst —
autonomously**. Instead of dumping `Alert #734982` on a human, it ingests events
from your security stack, detects multi-step attacks, scores their real business
risk, and explains them in plain language with a recommended action. It is built
to **replace tier‑1/2 monitoring headcount**, not just assist it.

> Example of what Sentinel writes on its own:
> *"User n.ahmadi logged in from Iran, then from Russia 10 minutes later, followed by
> a bulk download of 47 files. Likelihood of account takeover: **92%**. Recommended:
> reset password, revoke sessions, block the foreign IP."*

---

## The ten capabilities

| # | Capability | Where it lives |
|---|------------|----------------|
| 1 | **Connect to security sources** — M365, Google Workspace, Defender, CrowdStrike, SentinelOne, Cloudflare, AWS, Azure | `backend/app/connectors/` |
| 2 | **Collect & unify events** — log ingestion, normalization, de-duplication | `backend/app/ingestion/` |
| 3 | **Threat detection** — suspicious login, account takeover, anomalous activity, ransomware, data exfiltration | `backend/app/detection/` |
| 4 | **Threat scoring** *(the core)* — threat, user, asset, business-impact and final score | `backend/app/scoring/` |
| 5 | **Automated incident analysis** — narrative + likelihood %, not an alert ID | `backend/app/ai/analysis.py` |
| 6 | **Executive summary** — what happened / why it matters / damage / action | `backend/app/ai/analysis.py` |
| 7 | **Security chat assistant** — natural-language Q&A over live data | `backend/app/ai/chat.py` |
| 8 | **Semi-automatic response** — block user / reset password / kill session / block IP, **with manager approval** | `backend/app/response/` |
| 9 | **Org risk dashboard** — overall risk, risky users, risky systems, active threats | `frontend/src/app/page.tsx` |
| 10 | **Automatic weekly report** — what happened, what's resolved, what needs action | `backend/app/reporting/` |

---

## Architecture

```
Connectors (8 sources, simulated)
        │  raw events
        ▼
Ingestion  ── normalize ─▶ de-duplicate ─▶ canonical Event store
        │
        ▼
Detection engine ─▶ Signals ─▶ Correlation ─▶ Incident
                                    │
                                    ▼
                         Risk Scoring (5 scores)
                                    │
                                    ▼
                    AI: narrative · exec summary · chat   (Claude, with fallback)
                                    │
        ┌───────────────┬──────────┴───────────┬──────────────┐
        ▼               ▼                       ▼              ▼
   Dashboard       Incident view           Chat assistant   Weekly report
                        │
                        ▼
             Semi-auto response (manager-approved) ─▶ Audit trail
```

- **Backend:** Python 3.11 · FastAPI · SQLModel (SQLite, Postgres-ready) · APScheduler
- **Frontend:** Next.js 14 · TypeScript · Tailwind · Recharts (dark SOC theme)
- **AI:** Claude (`claude-opus-4-8` for deep analysis, `claude-sonnet-4-6` for chat).
  **Works with no API key** — it falls back to deterministic, rule-based summaries so
  the platform is always fully functional.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the detailed design.

---

## Quick start

### Option A — Docker (recommended)

```bash
# optional: export SENTINEL_ANTHROPIC_API_KEY=sk-ant-...   # enables real Claude output
docker compose up --build
```

Open **http://localhost:3000** and sign in with `admin` / `admin`.

### Option B — Local dev

**Backend**
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# optional: export SENTINEL_ANTHROPIC_API_KEY=sk-ant-...
uvicorn app.main:app --reload --port 8000
```

**Frontend** (separate terminal)
```bash
cd frontend
npm install
npm run dev          # proxies /api -> http://127.0.0.1:8000
```

Open **http://localhost:3000**.

On first boot the backend seeds a demo organization (8 users, 8 assets) and a set
of attack scenarios, then keeps ingesting simulated traffic every 20s. Use the
**"⚡ Simulate attack"** button on the dashboard to inject a fresh incident live.

---

## Enabling real Claude analysis

Set `SENTINEL_ANTHROPIC_API_KEY` (see `backend/.env.example`). With a key:
- incident narratives & executive summaries are written by Claude,
- the chat assistant uses Claude with **tool-calling** against the live database.

Without a key everything still works via rule-based fallbacks — look for the
`✦ Claude analysis` vs `rule-based` badge in the UI.

---

## Detection coverage on real data (honest status)

Detection is judged against a **per-organization behavioural baseline** learned
from each user's real history (home countries, devices, usual hours) — not
hardcoded assumptions — so it works for any org in any country. Which of the 10
catalog detections actually fire depends on which real telemetry a connector
provides:

| Detection | Works on real data today | Source needed |
|-----------|--------------------------|---------------|
| DET-001 Suspicious Login | ✅ (M365 sign-ins + baseline) | Microsoft 365 |
| DET-002 Account Compromise | ✅ (sign-ins + MFA/password audit + file activity) | Microsoft 365 |
| DET-007 Privilege Abuse | ⚠️ partial (directory audit) | Microsoft 365 |
| DET-003 Phishing | ⚠️ needs mail-security signal | Defender for O365 (Phase 4) |
| DET-006 Data Exfiltration | ⚠️ partial (file download; upload signal missing) | + network/DLP (Phase 4) |
| DET-004 Malware / DET-005 Ransomware | ❌ needs EDR telemetry | CrowdStrike/SentinelOne (Phase 4) |
| DET-008/009/010 | ⚠️ partial / source-dependent | varies |

Live-mode ingestion auto-provisions users & assets from real events so risk
scoring has real subjects. **Note:** the Office 365 file/email activity feed
(Management Activity API) is implemented but must be validated against a real
tenant during a pilot; EDR-driven detections require the Phase-4 connectors.

## Real response actions (not a demo)

When an incident fires, an admin can execute a **real** containment action against
the connected source — not a simulated one:

- **Microsoft 365 / Azure AD** actions run via Microsoft Graph: `Block user`
  (`accountEnabled=false`), `Kill session` (revoke sign-in sessions), `Reset
  password` (force change). They require the app registration to also have
  `User.ReadWrite.All`.
- **Safety guardrail:** real execution only happens when you turn on **Automated
  response** for that integration (Integrations page). Otherwise the action is
  recorded as `blocked by policy`. Manager approval + full audit still apply.
- In **demo mode** actions are always safely simulated.

## Production deployment

- **Database:** PostgreSQL in production (SQLite for dev). Schema is managed by
  **Alembic** migrations, applied automatically on startup.
- **Scale:** the API runs as multiple stateless Gunicorn/Uvicorn workers; a single
  dedicated **worker** container runs the scheduler (ingestion, weekly report,
  retention) so jobs aren't duplicated. `docker compose up` brings up Postgres +
  API + worker + frontend.
- **Observability:** structured JSON logs (`SENTINEL_JSON_LOGS=true`), Prometheus
  metrics at `/metrics`, liveness `/api/health` + readiness `/api/ready`, and
  optional Sentry error tracking (`SENTINEL_SENTRY_DSN`).
- **Data retention:** raw events/signals older than `SENTINEL_RETENTION_DAYS`
  (default 90) are purged automatically; incidents are kept.
- **CI:** GitHub Actions lints, tests and builds on every push/PR.

## Users, roles & security

Sentinel has real multi-user auth with **role-based access control**:

| Role | Can do |
|------|--------|
| `viewer` | Read everything (dashboards, incidents, catalog, reports) |
| `analyst` | + triage incidents, request response actions, run reports, chat |
| `admin` | + approve/execute actions, manage integrations, switch data mode, manage the detection catalog and **users** |

- Passwords are hashed (bcrypt); the bootstrap admin is seeded from
  `SENTINEL_ADMIN_*` on first boot only — after that, manage accounts from the
  **Team & Access** page (admin only).
- Every sensitive action (login, mode switch, connection changes, response
  actions, user changes) is written to an **audit log** (`GET /api/audit`, admin).
- Connector credentials are encrypted at rest with a **dedicated key**
  (`SENTINEL_ENCRYPTION_KEY`).

### Production checklist
Set these before exposing the app (in `production` the backend **refuses to boot**
if any are still at their default):
- `SENTINEL_ENVIRONMENT=production`
- `SENTINEL_JWT_SECRET` — long random value
- `SENTINEL_ADMIN_PASSWORD` — strong password (then rotate/replace the admin)
- `SENTINEL_ENCRYPTION_KEY` — strong random value
- `SENTINEL_CORS_ORIGINS` — your frontend origin(s), no wildcard
- Terminate TLS at a reverse proxy in front of the app (HSTS is sent in production)

## Connecting your real security sources (live integrations)

Open **Integrations** in the app to connect your organization's actual API:

1. Click **Add connection**, pick a provider (e.g. *Microsoft 365 / Azure AD*).
2. Enter the API credentials (for M365: Tenant ID, Client ID, Client Secret from
   an Azure AD app registration with `AuditLog.Read.All` application permission).
3. **Test** the connection — it authenticates against the real vendor API.
4. Once enabled, the pipeline pulls live events every cycle and the detection
   engine runs on your real data.

Credentials are encrypted at rest (Fernet) and never returned by the API — reads
only show which secret fields are set. **Microsoft 365 / Azure AD** ships a real,
live connector today (Microsoft Graph sign-in + directory audit logs); the other
providers are configurable and their connectors are drop-in (`backend/app/connectors/real/`).

To run purely on real data, disable simulation with `SENTINEL_SIM_ENABLED=false`.

## Plugging in your own attack models

Drop JSON attack-model definitions into [`data/attack_models/`](data/attack_models/README.md).
They are loaded at runtime and are designed to extend the built-in scenarios and
detection rules with patterns specific to your environment.

---

## Tests

```bash
cd backend && source .venv/bin/activate && pytest
```

Covers de-duplication, each detector, score bounds, idempotent detection cycles,
and full seed-to-incident flow.
