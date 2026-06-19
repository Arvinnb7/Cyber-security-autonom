"""Automated incident analysis + executive summary (F5/F6).

AI investigation module (per the MVP spec): explains what happened, why it
matters, what evidence supports the detection, the recommended action, and
whether human approval is required. Uses Claude when available, templates otherwise.
"""
from __future__ import annotations

import json
import logging

from sqlmodel import Session

from app.ai import summary as templates
from app.ai.client import complete
from app.detection.catalog import APPROVAL_POLICY, get_definition
from app.models.tables import Incident, Signal

logger = logging.getLogger("sentinel.ai")

_SYSTEM = (
    "You are a senior SOC (Security Operations Center) analyst. You receive a correlated "
    "security incident with its event timeline, matched detection factors, evidence and risk "
    "scores. Explain it the way an expert briefs a manager: concrete, calm, decisive. Never "
    "invent facts beyond the data. Respond in the same language as the incident data (English)."
)

_INSTRUCTION = """Analyze this incident and respond with ONLY a JSON object (no markdown) with keys:
- "narrative": 2-4 sentence expert analysis describing the actor's steps and an explicit likelihood %.
- "what_happened": one plain sentence a non-technical manager understands.
- "why_it_matters": one sentence on the significance.
- "evidence": one sentence summarizing the concrete evidence that supports this detection.
- "potential_damage": one sentence on worst-case business impact.
- "recommended_action": one concrete next step.
- "human_approval_required": one sentence stating whether human approval is required and why.
- "likelihood_pct": integer 0-100.

Incident data:
"""


def _context(incident: Incident, signals: list[Signal]) -> str:
    definition = get_definition(incident.det_id)
    payload = {
        "detection": {
            "id": incident.det_id,
            "name": definition["name_en"] if definition else incident.threat_type,
            "category": definition.get("category") if definition else None,
            "recommended_response": definition.get("recommended_response") if definition else [],
            "approval_policy": APPROVAL_POLICY.get(incident.human_approval_required, ""),
        },
        "actor": incident.actor_username,
        "asset": incident.target_asset,
        "scores": {
            "threat": incident.threat_score, "user_risk": incident.user_risk,
            "asset_risk": incident.asset_risk, "business_impact": incident.business_impact,
            "final": incident.final_score, "severity": incident.severity,
            "confidence": incident.confidence,
        },
        "matched_factors": incident.matched_factors,
        "evidence": incident.evidence,
        "human_approval_required": incident.human_approval_required,
        "signals": [s.description for s in signals],
        "timeline": incident.timeline,
    }
    return json.dumps(payload, ensure_ascii=False, default=str, indent=2)


def _parse_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None


def enrich_incident(session: Session, incident: Incident, signals: list[Signal]) -> Incident:
    """Populate ``ai_analysis`` (F5) and ``ai_summary`` (F6) on the incident."""
    raw = complete(_SYSTEM, _INSTRUCTION + _context(incident, signals))
    data = _parse_json(raw) if raw else None
    fallback = templates.template_summary(incident, signals)

    if data:
        incident.ai_analysis = data.get("narrative") or templates.template_narrative(incident, signals)
        incident.ai_summary = {
            "what_happened": data.get("what_happened", fallback["what_happened"]),
            "why_it_matters": data.get("why_it_matters", fallback["why_it_matters"]),
            "evidence": data.get("evidence", fallback["evidence"]),
            "potential_damage": data.get("potential_damage", fallback["potential_damage"]),
            "recommended_action": data.get("recommended_action", fallback["recommended_action"]),
            "recommended_actions": fallback["recommended_actions"],
            "human_approval_required": data.get("human_approval_required", fallback["human_approval_required"]),
            "likelihood_pct": data.get("likelihood_pct", fallback["likelihood_pct"]),
        }
        incident.ai_generated = True
    else:
        incident.ai_analysis = templates.template_narrative(incident, signals)
        incident.ai_summary = fallback
        incident.ai_generated = False

    session.add(incident)
    session.commit()
    session.refresh(incident)
    return incident
