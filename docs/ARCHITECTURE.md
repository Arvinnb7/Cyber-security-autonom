# Sentinel — Architecture

This document explains how the platform is put together and where to extend it.

## Layers

### 1. Connectors (`backend/app/connectors/`)
`BaseConnector` is the interface every source implements (`fetch_events()` +
`execute_action()`). The MVP ships `SimulatedConnector` instances for the eight
requested sources (Microsoft 365, Google Workspace, Microsoft Defender,
CrowdStrike, SentinelOne, Cloudflare, AWS, Azure). Each emits realistic *benign*
background traffic; attack chains are injected by the pipeline.

**To add a real source:** subclass `BaseConnector`, implement `fetch_events()`
against the vendor API, and register it in `simulators.py::ALL_CONNECTORS` (or a
new module). Nothing downstream changes.

### 2. Ingestion (`backend/app/ingestion/`)
- `normalizer.py` maps a source-native `RawEvent` to the **canonical `Event`**
  (OCSF/ECS-inspired: actor, src_ip, geo, action, target asset, severity, raw).
- `dedup.py` computes a fingerprint (identity fields + payload digest + 30s time
  bucket) so the same event seen twice collapses while distinct rapid events are
  preserved.
- `pipeline.py` orchestrates `connectors → normalize → dedup → persist`, injects
  attack scenarios, then runs detection.

### 3. Detection (`backend/app/detection/`)
`detectors.py` holds transparent rule/heuristic detectors over a recent event
window:
- `impossible_travel` — geo/velocity between logins (haversine).
- `account_takeover` — MFA failures + foreign login + mass download.
- `ransomware` — mass file-rename rate and/or EDR malware verdict.
- `data_exfiltration` — bulk download followed by a large external upload.
- `anomalous_activity` — privilege escalation / config tampering.

Each detector yields candidate `Signal`s. `run_detectors()` de-duplicates against
already-stored signals so cycles are idempotent. `correlation.py` groups signals
by `(threat_type, user)` into an `Incident`, builds the timeline, scores it, and
triggers AI enrichment.

### 4. Scoring (`backend/app/scoring/engine.py`) — the core
For each incident it computes five 0–100 scores:
`threat_score`, `user_risk`, `asset_risk`, `business_impact`, and a configurable
weighted `final_score`. User and asset rolling risk are recomputed from their open
incidents. Weights live in `settings` (`weight_threat`, …) so the model is tunable
without code changes — this is where the user's guide file maps in.

### 5/6. AI analysis & summary (`backend/app/ai/`)
`analysis.py::enrich_incident` sends the incident + timeline + scores to Claude and
parses a JSON response into a narrative (F5) and a structured executive summary
(F6: what happened / why it matters / potential damage / recommended action /
likelihood). `summary.py` provides deterministic templates used when no API key is
present, so output is never empty.

### 7. Chat (`backend/app/ai/chat.py`)
Claude with **tool-calling**. Tools (`get_top_incidents`, `get_riskiest_users`,
`get_riskiest_assets`, `get_active_threats`, `get_org_risk`) read live data via
`services/analytics.py`. A keyword-based fallback answers when AI is offline.

### 8. Response (`backend/app/response/actions.py`)
Actions are created `pending` and only execute after manager approval, routing to
the relevant connector and writing an `AuditAction` trail. `block_user` flips the
user's `is_blocked` flag; others are simulated with hooks for real connectors.

### 9. Dashboard & 10. Reports
`services/analytics.py` powers the dashboard API and `reporting/weekly.py` builds
the weekly executive report (Claude narrative + template fallback), scheduled via
APScheduler and also exposed as a manual trigger.

## Data model (`backend/app/models/tables.py`)
`User`, `Asset`, `Event` (canonical), `Signal`, `Incident` (carries the five
scores + AI outputs + timeline), `AuditAction`, `WeeklyReport`.

## Scheduler (`backend/app/core/scheduler.py`)
`BackgroundScheduler` runs the ingest+analyze cycle every
`SENTINEL_INGEST_INTERVAL_SECONDS` and the weekly report job. The frontend stays
live by polling the dashboard/incident APIs every few seconds.

## Time convention
SQLite stores naive datetimes; the whole app uses **naive UTC** via
`core/time.py::utcnow()` to avoid aware/naive comparison bugs in queries.

## Extension points
- **Real connectors** → `connectors/`.
- **Your attack models** → `data/attack_models/` (loaded by
  `scenarios.py::load_external_scenarios()`).
- **Scoring weights** → `core/config.py`.
- **New detectors** → add a function to `detection/detectors.py::DETECTORS`.
