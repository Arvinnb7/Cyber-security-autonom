"""Risk scoring engine (F4) — the most important part of the product.

Produces five 0..100 scores for every incident and rolls user/asset risk up
from them:

    threat_score     how dangerous the technique is
    user_risk        how risky/important the involved identity is
    asset_risk       how critical the targeted asset is
    business_impact  potential damage to the business
    final_score      configurable weighted blend of the above

Weights live in ``settings`` so the model is tunable (the user's guide file can
adjust them without code changes).
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlmodel import Session, select

from app.core import runtime
from app.core.config import settings
from app.detection.catalog import SEVERITY_FLOOR, get_definition
from app.models.tables import Asset, Signal, User


@dataclass
class ScoreBreakdown:
    threat_score: float
    user_risk: float
    asset_risk: float
    business_impact: float
    final_score: float
    confidence: float
    matched_factors: dict[str, int]


def _clamp(v: float) -> float:
    return max(0.0, min(100.0, v))


def _user(session: Session, username: str | None) -> User | None:
    if not username:
        return None
    return session.exec(
        select(User).where(User.username == username, User.origin == runtime.current_mode())
    ).first()


def _asset(session: Session, name: str | None) -> Asset | None:
    if not name:
        return None
    return session.exec(
        select(Asset).where(Asset.name == name, Asset.origin == runtime.current_mode())
    ).first()


def score_incident(session: Session, signals: list[Signal], det_id: str,
                   username: str | None, asset_name: str | None) -> ScoreBreakdown:
    confidence = max((s.confidence for s in signals), default=0.5)

    # threat_score (F4): sum of matched catalog scoring_factors across the
    # incident's signals, with a floor from the detection's default_severity so
    # critical techniques never score trivially.
    matched: dict[str, int] = {}
    for s in signals:
        for k, v in (s.matched_factors or {}).items():
            matched[k] = max(matched.get(k, 0), v)
    points = min(sum(matched.values()), 100)
    definition = get_definition(det_id)
    floor = SEVERITY_FLOOR.get(definition["default_severity"], 30) if definition else 30
    threat_score = _clamp(max(points, floor))

    # user_risk: privilege + existing rolling risk + this event's pressure.
    user = _user(session, username)
    user_risk = 30.0
    if user:
        user_risk = user.risk_score
        user_risk += 25 if user.is_privileged else 10
        user_risk += 0.4 * threat_score
    user_risk = _clamp(user_risk)

    # asset_risk: sensitivity 1..5 -> 0..100.
    asset = _asset(session, asset_name)
    asset_risk = _clamp((asset.sensitivity / 5 * 100) if asset else 50.0)

    # business_impact: blend of asset criticality, threat severity, user importance.
    priv_factor = 1.15 if (user and user.is_privileged) else 1.0
    business_impact = _clamp((0.6 * asset_risk + 0.4 * threat_score) * priv_factor * (0.8 + 0.2 * confidence))

    final_score = _clamp(
        settings.weight_threat * threat_score
        + settings.weight_user * user_risk
        + settings.weight_asset * asset_risk
        + settings.weight_business * business_impact
    )
    return ScoreBreakdown(
        threat_score=round(threat_score, 1),
        user_risk=round(user_risk, 1),
        asset_risk=round(asset_risk, 1),
        business_impact=round(business_impact, 1),
        final_score=round(final_score, 1),
        confidence=round(confidence, 2),
        matched_factors=matched,
    )


def recompute_user_risk(session: Session, username: str | None) -> None:
    """Roll a user's risk score from their open incidents (decayed average)."""
    from app.models.tables import Incident  # local import to avoid cycle

    if not username:
        return
    user = _user(session, username)
    if not user:
        return
    incidents = list(session.exec(
        select(Incident).where(Incident.actor_username == username, Incident.status != "dismissed",
                               Incident.origin == runtime.current_mode())
    ))
    if not incidents:
        user.risk_score = max(0.0, user.risk_score * 0.5)
    else:
        top = max(i.final_score for i in incidents)
        avg = sum(i.final_score for i in incidents) / len(incidents)
        user.risk_score = round(_clamp(0.7 * top + 0.3 * avg), 1)
    session.add(user)
    session.commit()


def recompute_asset_risk(session: Session, asset_name: str | None) -> None:
    from app.models.tables import Incident

    if not asset_name:
        return
    asset = _asset(session, asset_name)
    if not asset:
        return
    incidents = list(session.exec(
        select(Incident).where(Incident.target_asset == asset_name, Incident.status != "dismissed",
                               Incident.origin == runtime.current_mode())
    ))
    base = asset.sensitivity / 5 * 100
    if incidents:
        top = max(i.final_score for i in incidents)
        asset.risk_score = round(_clamp(0.5 * base + 0.5 * top), 1)
    else:
        asset.risk_score = round(base, 1)
    session.add(asset)
    session.commit()
