import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import select, update, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Alert, Rule


# ────────────────────────────────────────────────────────────────────────────
#  Alerts
# ────────────────────────────────────────────────────────────────────────────

async def insert_alert(db: AsyncSession, data: dict) -> Alert:

    alert = Alert(
        received_at     = datetime.utcnow(),
        source          = data.get("source",          "ml_engine"),
        verdict         = data.get("verdict",          "BENIGN"),
        action          = data.get("action",           "log_only"),
        label           = data.get("label"),
        confidence      = data.get("confidence"),
        ml_source       = data.get("ml_source"),
        src_ip          = data["src_ip"],
        dst_ip          = data.get("dst_ip"),
        src_port        = data.get("src_port"),
        dst_port        = data.get("dst_port"),
        protocol        = data.get("protocol"),
        start_time_ms   = data.get("start_time_ms"),
        end_time_ms     = data.get("end_time_ms"),
        anomaly_score   = data.get("anomaly_score"),
        anomaly_flagged = data.get("anomaly_flagged", False),
        rule_id         = None,   # filled after rule is created
    )
    db.add(alert)
    await db.flush()   # flush assigns alert.id without full commit
    return alert


async def link_alert_to_rule(
    db: AsyncSession, alert_id: int, rule_id: uuid.UUID
) -> None:
    """Update alert.rule_id after the rule has been created."""
    await db.execute(
        update(Alert)
        .where(Alert.id == alert_id)
        .values(rule_id=rule_id)
    )


async def get_alerts(
    db: AsyncSession,
    limit: int = 100,
    offset: int = 0,
    verdict: Optional[str] = None,
    src_ip: Optional[str] = None,
) -> list[Alert]:

    query = select(Alert).order_by(desc(Alert.received_at))

    if verdict:
        query = query.where(Alert.verdict == verdict.upper())
    if src_ip:
        query = query.where(Alert.src_ip == src_ip)

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())


async def get_alert_by_id(db: AsyncSession, alert_id: int) -> Optional[Alert]:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    return result.scalar_one_or_none()


async def count_alerts(db: AsyncSession) -> int:
    from sqlalchemy import func
    result = await db.execute(select(func.count()).select_from(Alert))
    return result.scalar_one()


# ────────────────────────────────────────────────────────────────────────────
#  Rules
# ────────────────────────────────────────────────────────────────────────────

async def insert_rule(db: AsyncSession, data: dict) -> Rule:
    rule = Rule(
        rule_id      = data.get("rule_id") or uuid.uuid4(),
        src_ip       = data["src_ip"],
        action       = data["action"],
        dpid         = data.get("dpid"),
        source       = data["source"],
        rate_kbps    = data.get("rate_kbps"),
        created_at   = datetime.utcnow(),
        deleted_at   = None,
        idle_timeout = data.get("idle_timeout", 300),
        hard_timeout = data.get("hard_timeout", 3600),
        active       = True,
        alert_id     = data.get("alert_id"),
    )
    db.add(rule)
    await db.flush()
    return rule


async def get_rules(
    db: AsyncSession,
    active_only: bool = False,
    source: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> list[Rule]:

    query = select(Rule).order_by(desc(Rule.created_at))

    if active_only:
        query = query.where(Rule.active == True)
    if source:
        query = query.where(Rule.source == source)
    if action:
        query = query.where(Rule.action == action)

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())


async def get_rule_by_id(
    db: AsyncSession, rule_id: uuid.UUID
) -> Optional[Rule]:
    result = await db.execute(
        select(Rule).where(Rule.rule_id == rule_id)
    )
    return result.scalar_one_or_none()


async def get_active_rule_for_ip(
    db: AsyncSession, src_ip: str
) -> Optional[Rule]:

    result = await db.execute(
        select(Rule).where(
            and_(Rule.src_ip == src_ip, Rule.active == True)
        )
    )
    return result.scalar_one_or_none()


async def deactivate_rule(
    db: AsyncSession, rule_id: uuid.UUID
) -> Optional[Rule]:

    rule = await get_rule_by_id(db, rule_id)
    if not rule:
        return None

    rule.active     = False
    rule.deleted_at = datetime.utcnow()
    await db.flush()
    return rule


async def count_active_rules(db: AsyncSession) -> int:
    from sqlalchemy import func
    result = await db.execute(
        select(func.count())
        .select_from(Rule)
        .where(Rule.active == True)
    )
    return result.scalar_one()