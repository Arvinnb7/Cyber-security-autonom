"""End-to-end tests for the catalog-aligned detection/scoring/dedup pipeline."""
from __future__ import annotations

from sqlmodel import select

from app.detection.catalog import seed_catalog, severity_for_score
from app.detection.correlation import correlate_and_score
from app.detection.detectors import run_detectors
from app.ingestion.dedup import event_fingerprint
from app.ingestion.pipeline import analyze, ingest_raw_events
from app.models.tables import DetectionDefinition, Incident
from app.scoring.engine import score_incident
from app.simulation.scenarios import SCENARIOS, generate_scenario
from app.simulation.seed import seed_org


def test_catalog_seeds_ten_detections(session):
    added = seed_catalog(session)
    assert added == 10
    rows = list(session.exec(select(DetectionDefinition)))
    assert {r.det_id for r in rows} >= {f"DET-{i:03d}" for i in range(1, 11)}


def test_severity_bands():
    assert severity_for_score(90) == "critical"
    assert severity_for_score(70) == "high"
    assert severity_for_score(40) == "medium"
    assert severity_for_score(10) == "low"


def test_dedup_drops_repeats(session):
    raw = generate_scenario("account_compromise")
    first = ingest_raw_events(session, raw)
    second = ingest_raw_events(session, raw)
    assert first > 0
    assert second < first


def test_fingerprint_stable(session):
    raw = generate_scenario("ransomware")[0]
    assert event_fingerprint(raw) == event_fingerprint(raw)


def test_account_compromise_detected(session):
    seed_org(session)
    ingest_raw_events(session, generate_scenario("account_compromise", user="s.karimi"))
    signals = run_detectors(session)
    assert any(s.det_id == "DET-002" for s in signals)


def test_ransomware_scored_critical_with_summary(session):
    seed_catalog(session)
    seed_org(session)
    ingest_raw_events(session, generate_scenario("ransomware"))
    signals = run_detectors(session)
    incidents = correlate_and_score(session, signals)
    ransomware = [i for i in incidents if i.det_id == "DET-005"]
    assert ransomware
    inc = ransomware[0]
    assert inc.final_score >= 60
    assert inc.severity in ("high", "critical")
    assert inc.human_approval_required == "critical"
    assert inc.ai_summary.get("recommended_action")
    assert inc.ai_summary.get("human_approval_required")
    assert inc.matched_factors  # scoring factors recorded


def test_scores_are_bounded(session):
    seed_catalog(session)
    seed_org(session)
    ingest_raw_events(session, generate_scenario("data_exfiltration"))
    signals = run_detectors(session)
    assert signals
    b = score_incident(session, signals, signals[0].det_id,
                       signals[0].actor_username, signals[0].target_asset)
    for v in (b.threat_score, b.user_risk, b.asset_risk, b.business_impact, b.final_score):
        assert 0 <= v <= 100


def test_all_catalog_detections_fire(session):
    """Each of the 10 scenarios must produce its corresponding catalog detection."""
    seed_catalog(session)
    seed_org(session)
    fired: set[str] = set()
    for name in SCENARIOS:
        s = session  # fresh ingest per scenario into the same DB
        ingest_raw_events(s, generate_scenario(name))
        for sig in run_detectors(s):
            fired.add(sig.det_id)
    # All ten detections should have fired at least once.
    assert fired >= {f"DET-{i:03d}" for i in range(1, 11)}, fired


def test_idempotent_detection(session):
    seed_org(session)
    ingest_raw_events(session, generate_scenario("ransomware"))
    run_detectors(session)
    assert run_detectors(session) == []
