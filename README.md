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
