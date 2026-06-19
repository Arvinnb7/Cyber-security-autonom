"""Automated weekly executive report (F10)."""
from __future__ import annotations

from collections import Counter
from datetime import timedelta

from sqlmodel import Session, select

from app.ai.client import complete
from app.core.time import utcnow
from app.models.tables import AuditAction, Incident, WeeklyReport

_SYSTEM = (
    "You are a senior SOC manager writing a weekly security report for executives. "
    "Be concise, business-focused and plain-spoken. Use the provided statistics only."
)


def _collect_stats(session: Session, start: datetime, end: datetime) -> dict:
    incidents = list(session.exec(
        select(Incident).where(Incident.created_at >= start, Incident.created_at <= end)
    ))
    resolved = [i for i in incidents if i.status in ("resolved", "dismissed")]
    needs_action = sorted(
        [i for i in incidents if i.status in ("open", "investigating")],
        key=lambda i: i.final_score, reverse=True,
    )
    actions = list(session.exec(
        select(AuditAction).where(AuditAction.requested_at >= start, AuditAction.requested_at <= end)
    ))
    by_type = Counter(i.threat_type for i in incidents)
    return {
        "total_incidents": len(incidents),
        "resolved": len(resolved),
        "open": len(needs_action),
        "by_type": dict(by_type),
        "actions_taken": len([a for a in actions if a.status == "executed"]),
        "top_open": [
            {"id": i.id, "title": i.title, "score": i.final_score, "type": i.threat_type}
            for i in needs_action[:5]
        ],
    }


def _template_report(start: datetime, end: datetime, stats: dict) -> str:
    by_type = "\n".join(f"- {k}: {v}" for k, v in stats["by_type"].items()) or "- none"
    top = "\n".join(f"- #{t['id']} {t['title']} — risk {t['score']}/100" for t in stats["top_open"]) or "- none"
    return f"""# Weekly Security Report
**Period:** {start.date()} → {end.date()}

## What happened
{stats['total_incidents']} incidents were detected this week across the monitored estate.

### Threats by type
{by_type}

## What was resolved
{stats['resolved']} incidents resolved/dismissed; {stats['actions_taken']} response actions executed.

## What needs action
{stats['open']} incidents are still open. Highest priority:
{top}
"""


def generate_weekly_report(session: Session, days: int = 7) -> WeeklyReport:
    end = utcnow()
    start = end - timedelta(days=days)
    stats = _collect_stats(session, start, end)

    prompt = (
        "Write a weekly security report in markdown with sections: 'What happened', "
        "'What was resolved', 'What needs action'. Statistics (JSON):\n"
        f"{stats}"
    )
    ai_text = complete(_SYSTEM, prompt, fast=True)
    content = ai_text or _template_report(start, end, stats)

    report = WeeklyReport(
        period_start=start, period_end=end, content_md=content,
        stats=stats, ai_generated=bool(ai_text),
    )
    session.add(report)
    session.commit()
    session.refresh(report)
    return report
