"""Detection Catalog — the MVP source of truth (DET-001..DET-010).

Loads ``detection_catalog.json`` and exposes it both as in-memory definitions
(for the detectors/scoring) and as a CRUD-backed DB table (for the API).
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from app.core.config import settings
from app.models.tables import DetectionDefinition

DEFAULT_CATALOG_PATH = Path(__file__).resolve().parents[2] / "data" / "detection_catalog.json"

# Severity bands from the catalog scoring_model (0..100).
SEVERITY_BANDS = [("critical", 86), ("high", 61), ("medium", 31), ("low", 0)]

# Per-severity floor applied to threat_score so e.g. a "critical" detection never
# scores trivially even when few scoring_factors matched.
SEVERITY_FLOOR = {"low": 15, "medium": 45, "high": 70, "critical": 90}

# Human-approval policy (from the catalog).
APPROVAL_POLICY = {
    "low": "Can be automated if configured by the customer.",
    "medium": "Recommend action; analyst review required by default.",
    "high": "Human approval required before disruptive response.",
    "critical": "Immediate escalation + human approval (containment-only allowed if pre-approved).",
}


def severity_for_score(score: float) -> str:
    for label, floor in SEVERITY_BANDS:
        if score >= floor:
            return label
    return "low"


@lru_cache
def load_catalog() -> dict[str, Any]:
    path = Path(settings.detection_catalog_path) if settings.detection_catalog_path else DEFAULT_CATALOG_PATH
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache
def catalog_by_id() -> dict[str, dict[str, Any]]:
    return {d["id"]: d for d in load_catalog()["detections"]}


def get_definition(det_id: str) -> dict[str, Any] | None:
    return catalog_by_id().get(det_id)


def seed_catalog(session: Session) -> int:
    """Insert catalog detections into the DB if not already present."""
    existing = {d.det_id for d in session.exec(select(DetectionDefinition))}
    added = 0
    for d in load_catalog()["detections"]:
        if d["id"] in existing:
            continue
        session.add(DetectionDefinition(
            det_id=d["id"],
            name_en=d.get("name_en", ""),
            name_fa=d.get("name_fa", ""),
            category=d.get("category", ""),
            description_fa=d.get("description_fa", ""),
            default_severity=d.get("default_severity", "medium"),
            required_data_sources=d.get("required_data_sources", []),
            detection_signals=d.get("detection_signals", []),
            scoring_factors=d.get("scoring_factors", {}),
            required_evidence=d.get("required_evidence", []),
            recommended_response=d.get("recommended_response", []),
            human_approval_required=d.get("human_approval_required", "high"),
        ))
        added += 1
    session.commit()
    return added
