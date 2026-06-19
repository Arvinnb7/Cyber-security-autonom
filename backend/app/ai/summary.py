"""Template fallbacks for incident narrative + executive summary (F5/F6).

Catalog-aware: pulls recommended_response and the human-approval policy from the
detection definition so the offline output mirrors the AI output.
"""
from __future__ import annotations

from app.detection.catalog import APPROVAL_POLICY, get_definition
from app.models.tables import Incident, Signal


def _damage(definition: dict | None) -> str:
    if definition:
        return definition.get("description_fa", "Potential security and business impact.")
    return "Potential security and business impact."


def template_narrative(incident: Incident, signals: list[Signal]) -> str:
    steps = " ".join(s.description for s in signals)
    pct = int(incident.confidence * 100)
    who = incident.actor_username or "an account"
    return (
        f"{who} is involved in a likely {incident.threat_type.replace('_', ' ')} affecting "
        f"{incident.target_asset or 'organization resources'}. {steps} "
        f"Estimated likelihood: {pct}%."
    )


def template_summary(incident: Incident, signals: list[Signal]) -> dict:
    pct = int(incident.confidence * 100)
    definition = get_definition(incident.det_id)
    response = definition.get("recommended_response", []) if definition else []
    observed = [e["field"] for e in (incident.evidence or []) if e.get("observed")]
    approval = incident.human_approval_required
    return {
        "what_happened": template_narrative(incident, signals),
        "why_it_matters": (
            f"Severity {incident.severity} · risk {incident.final_score}/100 with {pct}% confidence "
            f"on a {'high-value' if incident.asset_risk >= 70 else 'standard'} asset."
        ),
        "evidence": "Supporting evidence: " + (", ".join(observed) if observed else "see timeline")
        + f". Triggered factors: {', '.join(incident.matched_factors or {})}.",
        "potential_damage": _damage(definition),
        "recommended_action": (response[0] if response else "Investigate and contain the affected account/asset."),
        "recommended_actions": response,
        "human_approval_required": f"{approval} — {APPROVAL_POLICY.get(approval, '')}",
        "likelihood_pct": pct,
    }
