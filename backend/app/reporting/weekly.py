"""Automated weekly executive report (F10)."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from sqlmodel import Session, select

from app.ai.client import complete
from app.core import runtime
from app.core.time import utcnow
from app.models.tables import AuditAction, Incident, WeeklyReport
from app.services import analytics

_SYSTEM = (
    "You are a senior SOC manager writing a weekly security report for executives. "
    "Be concise, business-focused and plain-spoken. Use the provided statistics only."
)

# Industry rule-of-thumb for manual tier-1 triage of a single alert. Used only to
# express saved effort in hours; it is an ESTIMATE and labelled as such.
ANALYST_MINUTES_PER_INCIDENT = 20


def _collect_stats(session: Session, start: datetime, end: datetime) -> dict:
    mode = runtime.current_mode()
    incidents = list(session.exec(
        select(Incident).where(Incident.created_at >= start, Incident.created_at <= end,
                               Incident.origin == mode)
    ))
    resolved = [i for i in incidents if i.status in ("resolved", "dismissed")]
    needs_action = sorted(
        [i for i in incidents if i.status in ("open", "investigating")],
        key=lambda i: i.final_score, reverse=True,
    )
    actions = list(session.exec(
        select(AuditAction).where(AuditAction.requested_at >= start, AuditAction.requested_at <= end,
                                  AuditAction.origin == mode)
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
        # Operational performance — the ROI evidence for the business.
        "sla": analytics.sla_metrics(session, days=(end - start).days or 7),
    }


def _fmt_minutes(value: float | None) -> str:
    if value is None:
        return "n/a"
    if value < 60:
        return f"{value:.0f} min"
    return f"{value / 60:.1f} h"


def _sla_section(sla: dict) -> str:
    """Plain-language operations section — how much work was absorbed, honestly."""
    saved_hours = round(sla.get("autonomously_handled", 0) * ANALYST_MINUTES_PER_INCIDENT / 60.0, 1)
    fp = sla.get("false_positive_rate")
    lines = [
        f"- Mean time to acknowledge (MTTA): **{_fmt_minutes(sla.get('mtta_minutes'))}**",
        f"- Mean time to resolve (MTTR): **{_fmt_minutes(sla.get('mttr_minutes'))}**",
        f"- Closed without needing an analyst: **{sla.get('autonomously_handled', 0)}**"
        + (f" ({sla['autonomous_pct']}% of closed cases)" if sla.get("autonomous_pct") is not None else ""),
        f"- Estimated analyst time avoided: **~{saved_hours} h**"
        f" (at {ANALYST_MINUTES_PER_INCIDENT} min of manual triage per case)",
        f"- False-positive rate: **{fp}%**" if fp is not None
        else "- False-positive rate: not enough triaged cases yet",
    ]
    return "\n".join(lines)


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

## Operations & effort saved
{_sla_section(stats.get('sla', {}))}
"""


def generate_weekly_report(session: Session, days: int = 7) -> WeeklyReport:
    end = utcnow()
    start = end - timedelta(days=days)
    stats = _collect_stats(session, start, end)

    prompt = (
        "Write a weekly security report in markdown with sections: 'What happened', "
        "'What was resolved', 'What needs action'. Do NOT invent an operations "
        "section — measured SLA figures are appended separately. Statistics (JSON):\n"
        f"{stats}"
    )
    ai_text = complete(_SYSTEM, prompt, fast=True)
    content = ai_text or _template_report(start, end, stats)
    if ai_text:
        # Always append the measured operations numbers verbatim — these are
        # facts for the business, not something to leave to prose generation.
        content += f"\n\n## Operations & effort saved\n{_sla_section(stats.get('sla', {}))}\n"

    report = WeeklyReport(
        period_start=start, period_end=end, content_md=content,
        stats=stats, ai_generated=bool(ai_text), origin=runtime.current_mode(),
    )
    session.add(report)
    session.commit()
    session.refresh(report)
    return report
