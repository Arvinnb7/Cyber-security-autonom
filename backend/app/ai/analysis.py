"""Automated incident analysis + executive summary (F5/F6).

Turns a correlated incident into a senior-analyst narrative and a plain-language
executive summary. Uses Claude when available, deterministic templates otherwise.
"""
from __future__ import annotations

import json
import logging

from sqlmodel import Session

from app.ai import summary as templates
from app.ai.client import complete
from app.models.tables import Incident, Signal

logger = logging.getLogger("sentinel.ai")

_SYSTEM = (
    "You are a senior SOC (Security Operations Center) analyst. You receive a correlated "
    "security incident with its event timeline and risk scores. Explain it the way an expert "
    "would brief a manager: concrete, calm, and decisive. Never invent facts beyond the data. "
    "Always respond in the SAME language the incident data is written in (English here)."
)

_INSTRUCTION = """Analyze this incident and respond with ONLY a JSON object, no markdown, with keys:
- "narrative": 2-4 sentence expert analysis describing what the actor did step by step and the
  likelihood it is a real attack (include an explicit percentage).
- "what_happened": one plain sentence a non-technical manager understands.
- "why_it_matters": one sentence on the significance.
- "potential_damage": one sentence on worst-case business impact.
- "recommended_action": one concrete next step.
- "likelihood_pct": integer 0-100.

Incident data:
"""


def _context(incident: Incident, signals: list[Signal]) -> str:
    payload = {
        "threat_type": incident.threat_type,
        "actor": incident.actor_username,
        "asset": incident.target_asset,
        "scores": {
            "threat": incident.threat_score, "user_risk": incident.user_risk,
            "asset_risk": incident.asset_risk, "business_impact": incident.business_impact,
            "final": incident.final_score, "confidence": incident.confidence,
        },
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

    if data:
        incident.ai_analysis = data.get("narrative") or templates.template_narrative(incident, signals)
        incident.ai_summary = {
            "what_happened": data.get("what_happened", ""),
            "why_it_matters": data.get("why_it_matters", ""),
            "potential_damage": data.get("potential_damage", ""),
            "recommended_action": data.get("recommended_action", ""),
            "likelihood_pct": data.get("likelihood_pct", int(incident.confidence * 100)),
        }
        incident.ai_generated = True
    else:
        incident.ai_analysis = templates.template_narrative(incident, signals)
        incident.ai_summary = templates.template_summary(incident, signals)
        incident.ai_generated = False

    session.add(incident)
    session.commit()
    session.refresh(incident)
    return incident
