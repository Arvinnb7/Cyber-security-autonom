"""Security chat assistant (F7).

A manager asks natural-language questions ("show today's most dangerous
incidents", "which users are riskiest?") and Claude answers using tool-calls
against the live database. Falls back to an intent matcher when AI is offline.
"""
from __future__ import annotations

import json

from sqlmodel import Session

from app.ai.client import complete_with_tools, get_client
from app.services import analytics

TOOLS = [
    {
        "name": "get_top_incidents",
        "description": "Return the highest-risk incidents, optionally limited to the last N hours or a status.",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 5},
                "since_hours": {"type": "integer", "description": "e.g. 24 for today"},
                "status": {"type": "string", "enum": ["open", "investigating", "resolved", "dismissed"]},
            },
        },
    },
    {
        "name": "get_riskiest_users",
        "description": "Return the users with the highest current risk score.",
        "input_schema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 5}}},
    },
    {
        "name": "get_riskiest_assets",
        "description": "Return the assets/systems with the highest current risk score.",
        "input_schema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 5}}},
    },
    {
        "name": "get_active_threats",
        "description": "Return active threats grouped by type with counts.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_org_risk",
        "description": "Return the overall organization risk score and active incident count.",
        "input_schema": {"type": "object", "properties": {}},
    },
]

_SYSTEM = (
    "You are Sentinel, an autonomous SOC assistant embedded in a security platform. "
    "Answer the manager's questions using the provided tools to read live data. Be concise, "
    "lead with the answer, cite incident risk scores and user/asset names. If the user writes in "
    "Persian, answer in Persian; otherwise mirror their language. Never fabricate data not returned by tools."
)


def _dispatch(session: Session, name: str, args: dict) -> dict:
    if name == "get_top_incidents":
        items = analytics.top_incidents(session, limit=args.get("limit", 5),
                                        since_hours=args.get("since_hours"), status=args.get("status"))
        return {"incidents": [
            {"id": i.id, "title": i.title, "threat_type": i.threat_type, "final_score": i.final_score,
             "confidence": i.confidence, "user": i.actor_username, "asset": i.target_asset,
             "status": i.status} for i in items
        ]}
    if name == "get_riskiest_users":
        users = analytics.riskiest_users(session, limit=args.get("limit", 5))
        return {"users": [
            {"username": u.username, "name": u.display_name, "department": u.department,
             "risk_score": u.risk_score, "privileged": u.is_privileged, "blocked": u.is_blocked}
            for u in users
        ]}
    if name == "get_riskiest_assets":
        assets = analytics.riskiest_assets(session, limit=args.get("limit", 5))
        return {"assets": [
            {"name": a.name, "type": a.asset_type, "sensitivity": a.sensitivity, "risk_score": a.risk_score}
            for a in assets
        ]}
    if name == "get_active_threats":
        return {"threats": analytics.active_threats(session)}
    if name == "get_org_risk":
        return analytics.org_risk(session)
    return {"error": f"unknown tool {name}"}


def _fallback(session: Session, question: str) -> str:
    """Keyword router used when Claude is unavailable."""
    q = question.lower()
    if any(k in q for k in ("user", "کاربر", "افراد", "people")):
        users = analytics.riskiest_users(session, 5)
        lines = [f"- {u.display_name} ({u.username}, {u.department}): risk {u.risk_score}/100"
                 + (" [BLOCKED]" if u.is_blocked else "") for u in users]
        return "Riskiest users / پرریسک‌ترین کاربران:\n" + "\n".join(lines)
    if any(k in q for k in ("asset", "system", "سیستم", "دارایی", "سرور")):
        assets = analytics.riskiest_assets(session, 5)
        lines = [f"- {a.name} ({a.asset_type}, sensitivity {a.sensitivity}): risk {a.risk_score}/100"
                 for a in assets]
        return "Riskiest systems / سیستم‌های پرخطر:\n" + "\n".join(lines)
    if any(k in q for k in ("threat", "active", "تهدید", "فعال")):
        threats = analytics.active_threats(session)
        lines = [f"- {t['threat_type']}: {t['count']} active (max score {t['max_score']})" for t in threats]
        return "Active threats / تهدیدهای فعال:\n" + ("\n".join(lines) or "None")
    # default: top incidents
    items = analytics.top_incidents(session, 5)
    lines = [f"- #{i.id} {i.title}: {i.final_score}/100 ({int(i.confidence*100)}% confidence, {i.status})"
             for i in items]
    risk = analytics.org_risk(session)
    return (f"Org risk: {risk['score']}/100 ({risk['band']}).\n"
            f"Top incidents / خطرناک‌ترین رخدادها:\n" + ("\n".join(lines) or "None"))


def answer_question(session: Session, question: str, history: list[dict] | None = None) -> dict:
    """Return {"answer": str, "ai_generated": bool}."""
    if get_client() is None:
        return {"answer": _fallback(session, question), "ai_generated": False}

    messages: list[dict] = list(history or [])
    messages.append({"role": "user", "content": question})

    for _ in range(5):  # bounded tool loop
        resp = complete_with_tools(_SYSTEM, messages, TOOLS)
        if resp is None:
            return {"answer": _fallback(session, question), "ai_generated": False}

        if resp.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": resp.content})
            tool_results = []
            for block in resp.content:
                if getattr(block, "type", None) == "tool_use":
                    result = _dispatch(session, block.name, block.input or {})
                    tool_results.append({
                        "type": "tool_result", "tool_use_id": block.id,
                        "content": json.dumps(result, ensure_ascii=False, default=str),
                    })
            messages.append({"role": "user", "content": tool_results})
            continue

        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        return {"answer": text or _fallback(session, question), "ai_generated": True}

    return {"answer": _fallback(session, question), "ai_generated": False}
