"""End-to-end tests for the detection/scoring/dedup pipeline (AI in fallback mode)."""
from __future__ import annotations

from app.detection.correlation import correlate_and_score
from app.detection.detectors import run_detectors
from app.ingestion.dedup import event_fingerprint
from app.ingestion.pipeline import analyze, ingest_raw_events
from app.models.tables import Event, Incident
from app.scoring.engine import score_incident
from app.simulation.scenarios import generate_scenario
from app.simulation.seed import seed_org
from sqlmodel import select


def test_dedup_drops_repeats(session):
    raw = generate_scenario("account_takeover")
    first = ingest_raw_events(session, raw)
    second = ingest_raw_events(session, raw)  # identical batch
    assert first > 0
    # The second pass should be (almost) fully deduplicated.
    assert second < first


def test_fingerprint_stable(session):
    raw = generate_scenario("ransomware")[0]
    assert event_fingerprint(raw) == event_fingerprint(raw)


def test_account_takeover_detected(session):
    seed_org(session)
    ingest_raw_events(session, generate_scenario("account_takeover", user="s.karimi"))
    signals = run_detectors(session)
    types = {s.threat_type for s in signals}
    assert "account_takeover" in types


def test_ransomware_detected_and_scored_high(session):
    seed_org(session)
    ingest_raw_events(session, generate_scenario("ransomware"))
    signals = run_detectors(session)
    incidents = correlate_and_score(session, signals)
    ransomware = [i for i in incidents if i.threat_type == "ransomware"]
    assert ransomware
    assert ransomware[0].final_score >= 60  # ransomware must be high risk
    assert ransomware[0].ai_summary.get("recommended_action")  # F6 populated (template fallback)


def test_scores_are_bounded(session):
    seed_org(session)
    ingest_raw_events(session, generate_scenario("data_exfiltration"))
    signals = run_detectors(session)
    b = score_incident(session, signals, "data_exfiltration",
                       signals[0].actor_username, signals[0].target_asset)
    for v in (b.threat_score, b.user_risk, b.asset_risk, b.business_impact, b.final_score):
        assert 0 <= v <= 100


def test_full_seed_creates_incidents(session):
    seed_org(session)
    for name in ("account_takeover", "ransomware", "data_exfiltration", "anomalous_privileged"):
        ingest_raw_events(session, generate_scenario(name))
    analyze(session)
    incidents = list(session.exec(select(Incident)))
    assert len(incidents) >= 3
    # Every incident carries the five scores and a narrative.
    for inc in incidents:
        assert inc.final_score > 0
        assert inc.ai_analysis


def test_idempotent_detection(session):
    seed_org(session)
    ingest_raw_events(session, generate_scenario("ransomware"))
    run_detectors(session)
    second = run_detectors(session)  # same events, no new signals expected
    assert second == []
