
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import get_settings
from src.db.database import get_db
from src.db import crud
from src import normalizer, decision, dedup
from src.actions import actions
from src.actions.ryu_client import RyuClientError

log = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter()


@router.post("/alert", status_code=200)
async def receive_alert(
    request: Request,
    db: AsyncSession = Depends(get_db),
):

    # ── 1. Parse body ─────────────────────────────────────────────────
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # ── 2. Normalize ──────────────────────────────────────────────────
    try:
        alert_data = normalizer.normalize(payload)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    log.info(
        "Alert received | source=%s | verdict=%s | label=%s | "
        "confidence=%.2f | src_ip=%s",
        alert_data.source, alert_data.verdict,
        alert_data.label, alert_data.confidence, alert_data.src_ip,
    )

    # ── 3. Decide action ──────────────────────────────────────────────
    action = decision.decide(alert_data)
    reason = decision.describe_decision(alert_data, action)
    log.info("Decision | action=%s | reason: %s", action, reason)

    # ── 4. Store alert in DB (always, even if log_only or duplicate) ──
    alert_record = await crud.insert_alert(db, {
        "source":          alert_data.source,
        "verdict":         alert_data.verdict,
        "action":          action,
        "label":           alert_data.label,
        "confidence":      alert_data.confidence,
        "ml_source":       alert_data.ml_source,
        "src_ip":          alert_data.src_ip,
        "dst_ip":          alert_data.dst_ip,
        "src_port":        alert_data.src_port,
        "dst_port":        alert_data.dst_port,
        "protocol":        alert_data.protocol,
        "start_time_ms":   alert_data.start_time_ms,
        "end_time_ms":     alert_data.end_time_ms,
        "anomaly_score":   alert_data.anomaly_score,
        "anomaly_flagged": alert_data.anomaly_flagged,
    })

    # ── 5. Skip OVS action if log_only ────────────────────────────────
    if action == "log_only":
        log.info("log_only | alert_id=%d stored, no OVS action", alert_record.id)
        return {
            "alert_id":  alert_record.id,
            "rule_id":   None,
            "action":    "log_only",
            "duplicate": False,
        }

    # ── 6. Deduplication check ────────────────────────────────────────
    if dedup.is_duplicate(alert_data.src_ip):
        log.info(
            "Duplicate suppressed | src_ip=%s | alert_id=%d stored",
            alert_data.src_ip, alert_record.id,
        )
        return {
            "alert_id":  alert_record.id,
            "rule_id":   None,
            "action":    action,
            "duplicate": True,
        }

    # ── 7. Call Ryu to install the OVS rule ───────────────────────────
    ryu_rule = None
    try:
        if action == "block":
            ryu_rule = await actions.execute_block(
                src_ip=alert_data.src_ip,
                idle_timeout=settings.DEFAULT_IDLE_TIMEOUT,
                hard_timeout=settings.DEFAULT_HARD_TIMEOUT,
            )
        elif action == "ratelimit":
            ryu_rule = await actions.execute_ratelimit(
                src_ip=alert_data.src_ip,
                idle_timeout=settings.DEFAULT_IDLE_TIMEOUT,
                hard_timeout=settings.DEFAULT_HARD_TIMEOUT,
            )
        elif action == "isolate":
            ryu_rule = await actions.execute_isolate(
                src_ip=alert_data.src_ip,
                idle_timeout=settings.DEFAULT_IDLE_TIMEOUT,
                hard_timeout=settings.DEFAULT_HARD_TIMEOUT,
            )
        else:
            log.warning("Unhandled action type: %s | alert_id=%d", action, alert_record.id)
    except RyuClientError as e:
        # Ryu is unreachable or returned an error.
        # The alert is already stored. Log and return partial success.
        log.error(
            "Ryu call failed | alert_id=%d | action=%s | error: %s",
            alert_record.id, action, e,
        )
        return {
            "alert_id":  alert_record.id,
            "rule_id":   None,
            "action":    action,
            "duplicate": False,
            "warning":   f"OVS rule not installed: {e}",
        }

    rule_id = None
    dpid = None
    if ryu_rule:
        raw_rule_id = ryu_rule.get("rule_id")
        if not raw_rule_id:
            log.error("Ryu response missing rule_id | alert_id=%d", alert_record.id)
        else:
            rule_id = uuid.UUID(raw_rule_id)
        dpid = ryu_rule.get("dpid")   
        dpid    = ryu_rule.get("dpid") if ryu_rule else None

    if rule_id:
        await crud.insert_rule(db, {
            "rule_id":      rule_id,
            "src_ip":       alert_data.src_ip,
            "action":       action,
            "dpid":         dpid,
            "source":       "mitigation_engine",
            "rate_kbps":    ryu_rule.get("rate_kbps"),
            "idle_timeout": settings.DEFAULT_IDLE_TIMEOUT,
            "hard_timeout": settings.DEFAULT_HARD_TIMEOUT,
            "alert_id":     alert_record.id,
        })

        # Link alert → rule
        await crud.link_alert_to_rule(db, alert_record.id, rule_id)

        # Record in dedup cache — prevents duplicate rules for this IP
        dedup.record_action(alert_data.src_ip)

    log.info(
        "Alert processed | alert_id=%d | action=%s | rule_id=%s | src_ip=%s",
        alert_record.id, action, rule_id, alert_data.src_ip,
    )

    return {
        "alert_id":  alert_record.id,
        "rule_id":   str(rule_id) if rule_id else None,
        "action":    action,
        "duplicate": False,
    }