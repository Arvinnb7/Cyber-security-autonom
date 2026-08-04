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
| 1 | **Connect to security sources** — live today: Microsoft 365 / Entra ID and Defender XDR; configurable (connector pending): Google Workspace, CrowdStrike, SentinelOne, Cloudflare, AWS | `backend/app/connectors/` |
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
| DET-001 Suspicious Login | ✅ sign-ins + learned baseline, worldwide impossible-travel, real admin privilege | Microsoft 365 |
| DET-002 Account Compromise | ✅ sign-ins + MFA/password audit + file activity | Microsoft 365 |
| DET-003 Phishing | ✅ `EmailEvents` — spoofed sender, malicious URL, attachment, auth failure, campaign size | Defender XDR |
| DET-004 Malware Execution | ✅ Defender verdicts + `DeviceProcessEvents` (obfuscated PowerShell, elevated, unknown hash) | Defender XDR |
| DET-005 Ransomware | ✅ rename bursts + shadow-copy deletion + ransomware verdict | Defender XDR |
| DET-006 Data Exfiltration | ✅ bulk download + bulk/external upload | Microsoft 365 |
| DET-007 Privilege Abuse | ✅ directory audit + security-control tampering | M365 + Defender |
| DET-008 Security Config Change | ⚠️ partial — covers MFA/logging policy changes; firewall & cloud exposure need network/cloud sources | Microsoft 365 |
| DET-009 Lateral Movement | ✅ remote logons + remote-execution tooling | Defender XDR |
| DET-010 Privilege Escalation | ✅ role additions / role changes | Microsoft 365 |

**9 of 10 fire on real telemetry**; DET-008 is partial because firewall and cloud
exposure changes come from sources not yet connected (AWS/Cloudflare).

Live-mode ingestion auto-provisions users & assets from real events so risk
scoring has real subjects.

> **Validation status — read this before quoting the table.** Every mapping is
> unit-tested against recorded payload shapes, and the detections above are
> proven end-to-end in `backend/tests/test_defender.py` (Defender-shaped events
> in → DET-003/004/005/009 out, with no simulator flags anywhere). What that does
> **not** prove is that a given tenant's real payloads match those shapes: the
> Office 365 Management Activity feed and the Defender Advanced Hunting queries
> both need confirming against a live tenant during a pilot. Treat this as
> "implemented and tested", not "certified in production".

### Connecting Defender
Reuse the **same Azure AD app registration** as Microsoft 365 and add the
application permissions `SecurityAlert.Read.All` and `ThreatHunting.Read.All`
(plus `Machine.Isolate` if you want host isolation), then add a *Microsoft
Defender XDR* connection on the Integrations page. Each source degrades
independently — a tenant licensed for Defender for Endpoint but not for Office
365 still gets endpoint detections.

## Real response actions (not a demo)

When an incident fires, an admin can execute a **real** containment action against
the connected source — not a simulated one:

- **Microsoft 365 / Azure AD** actions run via Microsoft Graph: `Block user`
  (`accountEnabled=false`), `Kill session` (revoke sign-in sessions), `Reset
  password` (force change). They require the app registration to also have
  `User.ReadWrite.All`.
- **Microsoft Defender** adds `Isolate host` — cutting a compromised machine off
  the network, which is the containment step that actually stops ransomware
  spreading. Requires `Machine.Isolate`.
- **Safety guardrail:** real execution only happens when you turn on **Automated
  response** for that integration (Integrations page). Otherwise the action is
  recorded as `blocked by policy`. Manager approval + full audit still apply.
- In **demo mode** actions are always safely simulated.

## Alerting & escalation (operational)

Detection only matters if a human hears about it. When a high-severity incident
fires — or a response action is waiting on manager approval — Sentinel pushes an
alert to your team's channels:

- **Channels:** Email (SMTP), Microsoft Teams and Slack (incoming webhooks). Add
  them on the **Alerting** page (admin only). A generic webhook / PagerDuty
  connector is a drop-in for later.
- **Severity-gated:** each channel has a minimum severity, so low-severity noise
  doesn't page the on-call.
- **Deduped, with escalation:** an incident re-touched every ingest cycle is
  alerted once; a *severity increase* re-alerts (escalation). A scheduler job
  re-alerts still-pending manager approvals (default: every 10 min, after a
  30-min grace) until they're actioned.
- **Auditable:** every delivery (sent / failed / skipped) is recorded and shown
  in the Alerting feed. Channel secrets (SMTP password, webhook URLs) are
  encrypted at rest (Fernet) and never returned by the API.
- **Opt-in & safe in demo:** no channels exist until an admin adds one, so demo
  mode never alerts anyone by accident.

## Self-monitoring — why you can leave it unattended

The dangerous failure mode for an autonomous SOC is **silent blindness**: an
expired API secret stops ingestion, the dashboard shows *"0 active threats"*
(which reads like good news), and if you have removed the humans, nobody notices.
Sentinel watches itself:

- **Three checks, every 5 minutes:** an enabled integration that is failing to
  poll, no events ingested inside the staleness window (live mode), and a
  scheduler that has stopped running cycles (it heartbeats each ingest).
- **Alerts bypass severity tuning.** Health alerts go to every channel with
  *"On platform health issues"* enabled regardless of its `min_severity` — a
  blind SOC is always critical. You get one alert per state change (not a stream)
  and an explicit **RECOVERED** notice when it clears.
- **Visible in the product:** a red banner on the dashboard and
  `GET /api/system/health`, both stating plainly that an empty incident list does
  not mean you are safe.

## Response performance & what it replaces

Sentinel records the case work, so the value is measured rather than asserted:

- **Casework:** incidents can be acknowledged, assigned, annotated with notes,
  and closed with a reason (`true_positive` / `false_positive` / `benign`) — a
  full audit record of who did what and when.
- **Metrics** (`GET /api/metrics/sla`, dashboard tiles, weekly report):
  **MTTA**, **MTTR**, **false-positive rate**, and **% handled autonomously**
  (closed without a human ever acknowledging them).
- The weekly report converts that into an effort estimate ("~N hours of analyst
  time avoided") using a stated 20-min-per-alert triage assumption — an
  **estimate**, labelled as one, not a guarantee.
- False positives are tracked per detection, so you can see which rule is noisy
  and calibrate its threshold (`SENTINEL_MASS_DOWNLOAD_COUNT`,
  `SENTINEL_IMPOSSIBLE_TRAVEL_KMH`, etc. — see `backend/.env.example`).

**Honest scope:** this makes the tier-1 *watch → triage → enrich → first
response* loop autonomous for an M365/Azure estate. It does **not** cover
malware/ransomware detection, which needs EDR telemetry (a later phase), and
incident *ownership* still belongs to a human — the platform escalates to them.

## Scale — measured, not claimed

The number that decides whether an autonomous SOC keeps up is **how long one
ingest+detect cycle takes versus the polling interval** (default 20s). If a cycle
runs long, detection latency grows without bound. Run it yourself:

```bash
cd backend && python -m benchmarks.bench --users 5000 --days 30
```

Measured on a 4-vCPU Intel Xeon @ 2.10GHz / 15 GB RAM, Python 3.11, SQLite,
5,000 users with 30 days (600k events) of history and 2,000 events per cycle:

| Stage | Before | After |
|---|---|---|
| Behavioural baseline, per cycle | 28.33 s | **0.10 s** |
| Ingest 2,000 events | 1.37 s / 4,009 queries | **0.49 s / 11 queries** |
| Detection pass | 22.10 s | **0.32 s** |
| **Full cycle (vs 20 s budget)** | **25.07 s — falls behind** | **0.99 s — keeps up** |
| Queries per cycle | 3,526 | **15** |

At double the target (10,000 users, 1.2M events of history, 5,000 events/cycle) a
full cycle takes **2.48 s** — still ~8x inside the budget.

What changed:
- **Baselines are stored, not recomputed.** Learned behaviour lives in
  `userbaselinestate` and is updated incrementally as events arrive; a nightly
  job does the authoritative recompute (26 s at 5k users) so counters can't drift
  as events age out of the window. A cycle reads one small row per user instead
  of the entire 30-day history.
- **Batched ingestion.** De-duplication and identity provisioning use chunked
  `IN` lookups and multi-row writes, so cost tracks the number of batches rather
  than the number of events.
- **Activity-scoped detection.** The correlation window is read only for the
  users and assets touched by the current cycle — cost follows what the
  organization *did*, not how many people it employs.
- **Composite indexes** matching the real access patterns, and **SQL aggregation**
  for the dashboard/SLA figures instead of loading incidents into memory.

`backend/tests/test_scale.py` pins these as invariants (bounded query counts,
flat baseline cost as history grows, scoped and unscoped detection agreeing), so
a future change that reintroduces a per-row query fails the build.

## Resilience under load — what happens when it's hammered

Scaling throughput and surviving abuse are different problems. Every user-supplied
bound is capped, every in-process structure has a ceiling, and every container
restarts itself. Run it yourself against a live instance:

```bash
cd backend && python -m benchmarks.loadtest --url http://127.0.0.1:8000 --users 50 --seconds 30
```

Measured on the same 4-vCPU / 15 GB machine, **one** Uvicorn worker on SQLite —
a deliberately pessimistic floor, since production runs four workers on PostgreSQL:

| Check | Result |
|---|---|
| 50 concurrent users, 25 s | 1,881 requests, **all 200**, **zero 5xx** |
| Latency p50 / p95 / p99 | 548 ms / 1,306 ms / 1,723 ms |
| `?limit=999999999` (3 endpoints) | **422** — refused, not served |
| `?days=999999999` | **422** — previously an unhandled `OverflowError` → 500 |
| Oversized chat/note payload | **422** |
| 300 logins with rotating usernames | throttled after 8 failures, **contained** |
| 400 varied cache keys | **contained** |
| Memory across 5,000 abusive requests | **122,824 kB → 122,828 kB** (flat) |
| Server after all of the above | **healthy** |

What was fixed:
- **Bounded inputs.** Every `limit` and window is validated by FastAPI
  (`ge`/`le`), so a hostile request is rejected before it can materialize a table
  into memory. Chat questions, conversation history and notes are length-capped —
  that payload is forwarded to Claude, so it is a cost vector as well as a memory one.
- **Bounded memory.** `app/core/limits.py` provides an LRU+TTL cache and a
  sliding-window limiter with a **capped key table**. The login throttle and the
  SLA cache were both unbounded dictionaries keyed by attacker-controlled values;
  they now evict instead of growing.
- **Quotas.** A general per-client quota plus a much stricter tier for the
  endpoints that call Claude. `/api/health` and `/api/ready` are exempt so an
  orchestrator never kills a healthy container during a spike.
- **Login throttling counts failures, not successes** — keyed by IP *and*
  username, so rotating usernames from one source is still caught while a busy
  office behind one NAT is never locked out by its own valid logins.
- **Self-recovery.** All services declare `restart: unless-stopped` with memory
  limits; Gunicorn recycles workers (`--max-requests` with jitter); the worker
  container's healthcheck asserts the **scheduler heartbeat is fresh**, not merely
  that the process exists.

**Honest limits.** The rate limiter is in-process: with four API workers the
effective quota is roughly four times the configured value, and it resets on
deploy. It exists to stop the platform harming *itself* — a runaway client, a
buggy script, an accidental loop. Real abuse or DDoS protection belongs at the
edge (nginx, Cloudflare). The capacity figures above are a single-worker SQLite
floor, not a tuned production ceiling.

### Operating at sustained volume
- **Retention.** At ~1M events/day the 90-day default means ~90M rows. Lower
  `SENTINEL_RETENTION_DAYS` or partition the `event` table monthly.
- **Connection pool.** Keep
  `api_workers x (SENTINEL_DB_POOL_SIZE + SENTINEL_DB_MAX_OVERFLOW)` plus the
  worker container below PostgreSQL's `max_connections`. Defaults (5 + 10 across
  4 workers = 60) fit a stock Postgres; raise `max_connections` before raising
  these.
- **One scheduler.** Only the worker container may run it
  (`SENTINEL_RUN_SCHEDULER=true`); API workers must keep it off or cycles double up.

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
