"""Template fallbacks for incident narrative + executive summary (F5/F6).

Used when Claude is unavailable so the product is fully functional offline.
"""
from __future__ import annotations

from app.models.tables import Incident, Signal

_DAMAGE = {
    "ransomware": "Encryption of business-critical files and operational downtime; possible ransom demand.",
    "account_takeover": "Unauthorized access to corporate data, lateral movement, and possible fraud.",
    "data_exfiltration": "Loss of confidential/customer data, regulatory exposure, and reputational damage.",
    "anomalous_activity": "Privileged misuse that could disable controls or stage a larger attack.",
}

_ACTION = {
    "ransomware": "Isolate the affected host now, kill the malicious process, and restore from clean backups.",
    "account_takeover": "Reset the user's password, revoke active sessions, and block the foreign IP.",
    "data_exfiltration": "Suspend the account, block the upload destination, and review what left the network.",
    "anomalous_activity": "Re-verify the privileged action with the owner and audit recent changes.",
}


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
    return {
        "what_happened": template_narrative(incident, signals),
        "why_it_matters": (
            f"Risk score {incident.final_score}/100 with {pct}% confidence on a "
            f"{'high-value' if incident.asset_risk >= 70 else 'standard'} asset."
        ),
        "potential_damage": _DAMAGE.get(incident.threat_type, "Potential security and business impact."),
        "recommended_action": _ACTION.get(incident.threat_type, "Investigate and contain the affected account/asset."),
        "likelihood_pct": pct,
    }
