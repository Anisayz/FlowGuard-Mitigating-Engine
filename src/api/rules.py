import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import get_settings
from src.db.database import get_db
from src.db import crud
from src import dedup
from src.actions import actions
from src.actions.ryu_client import RyuClientError, delete_rule as ryu_delete

log = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter()


# ────────────────────────────────────────────────────────────────────────────
#  Request / Response schemas
# ────────────────────────────────────────────────────────────────────────────

class ManualRuleRequest(BaseModel):
   
    src_ip:       str  = Field(..., description="IP to apply rule to")
    action:       str  = Field(..., description="block | ratelimit | isolate")
    rate_kbps:    Optional[int] = Field(None, description="Required for ratelimit")
    idle_timeout: Optional[int] = Field(None)
    hard_timeout: Optional[int] = Field(None)
    dpid:         Optional[int] = Field(None, description="Target switch (auto if omitted)")


def _rule_to_dict(rule) -> dict:
    return {
        "rule_id":      str(rule.rule_id),
        "src_ip":       rule.src_ip,
        "action":       rule.action,
        "dpid":         rule.dpid,
        "source":       rule.source,
        "rate_kbps":    rule.rate_kbps,
        "created_at":   rule.created_at.isoformat() if rule.created_at else None,
        "deleted_at":   rule.deleted_at.isoformat() if rule.deleted_at else None,
        "idle_timeout": rule.idle_timeout,
        "hard_timeout": rule.hard_timeout,
        "active":       rule.active,
        "alert_id":     rule.alert_id,
    }


# ────────────────────────────────────────────────────────────────────────────
#  GET /rules
# ────────────────────────────────────────────────────────────────────────────

@router.get("/rules")
async def list_rules(
    active:  Optional[bool] = Query(None,  description="Filter active/inactive"),
    source:  Optional[str]  = Query(None,  description="manual | mitigation_engine"),
    action:  Optional[str]  = Query(None,  description="block | ratelimit | isolate"),
    limit:   int            = Query(200,   ge=1, le=1000),
    offset:  int            = Query(0,     ge=0),
    db: AsyncSession = Depends(get_db),
):
    """
    List firewall rules. Used by the dashboard rules table.

    Examples:
        GET /rules                      → all rules
        GET /rules?active=true          → only active rules
        GET /rules?action=block         → only block rules
        GET /rules?source=manual        → manually created rules
    """
    rules = await crud.get_rules(
        db,
        active=active,
        source=source,
        action=action,
        limit=limit,
        offset=offset,
    )
    log.info(len(rules))
    return {
        "count": len(rules),
        "rules": [_rule_to_dict(r) for r in rules],
    }


# ────────────────────────────────────────────────────────────────────────────
#  GET /rules/{rule_id}
# ────────────────────────────────────────────────────────────────────────────

@router.get("/rules/{rule_id}")
async def get_rule(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Return a single rule by ID. Used by dashboard rule detail popup."""
    rule = await crud.get_rule_by_id(db, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return _rule_to_dict(rule)


# ────────────────────────────────────────────────────────────────────────────
#  POST /rules/manual
# ────────────────────────────────────────────────────────────────────────────

@router.post("/rules/manual", status_code=201)
async def create_manual_rule(
    body: ManualRuleRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a firewall rule manually from the dashboard.

    Calls Ryu to install the OVS rule, then stores the record in DB.
    Returns the created rule dict.
    """
    if body.action not in ("block", "ratelimit", "isolate"):
        raise HTTPException(
            status_code=422,
            detail="action must be block | ratelimit | isolate",
        )
    if body.action == "ratelimit" and not body.rate_kbps:
        raise HTTPException(
            status_code=422,
            detail="rate_kbps is required for ratelimit action",
        )

    idle = body.idle_timeout if body.idle_timeout is not None else settings.DEFAULT_IDLE_TIMEOUT
    hard = body.hard_timeout if body.hard_timeout is not None else settings.DEFAULT_HARD_TIMEOUT
    # ── Call Ryu ──────────────────────────────────────────────────────
    try:
        if body.action == "block":
            ryu_rule = await actions.execute_block(
                src_ip=body.src_ip,
                idle_timeout=idle,
                hard_timeout=hard,
                dpid=body.dpid,
            )
        elif body.action == "ratelimit":
            ryu_rule = await actions.execute_ratelimit(
                src_ip=body.src_ip,
                rate_kbps=body.rate_kbps,
                idle_timeout=idle,
                hard_timeout=hard,
                dpid=body.dpid,
            )
        elif body.action == "isolate":
            ryu_rule = await actions.execute_isolate(
                src_ip=body.src_ip,
                idle_timeout=idle,
                hard_timeout=hard,
                dpid=body.dpid,
            )
    except RyuClientError as e:
        raise HTTPException(
            status_code=503,
            detail=f"Failed to install rule on OVS: {e}",
        )

    # ── Store in DB ───────────────────────────────────────────────────
    # ── Store in DB ───────────────────────────────────────────────────
    try:
        rule_id = uuid.UUID(ryu_rule["rule_id"])
    except (KeyError, ValueError, TypeError) as e:
        log.error("Ryu returned malformed response: %s", ryu_rule)
        raise HTTPException(
            status_code=502,
            detail=f"Ryu returned invalid rule response: {e}",
        )
    rule = await crud.insert_rule(db, {
        "rule_id":      rule_id,
        "src_ip":       body.src_ip,
        "action":       body.action,
        "dpid":         ryu_rule.get("dpid"),
        "source":       "manual",
        "rate_kbps":    body.rate_kbps,
        "idle_timeout": idle,
        "hard_timeout": hard,
        "alert_id":     None,   # no triggering alert for manual rules
    })   
    dedup.record_action(body.src_ip)

    log.info(
        "Manual rule created | rule_id=%s | action=%s | src_ip=%s",
        rule_id, body.action, body.src_ip,
    )
    return _rule_to_dict(rule)


# ────────────────────────────────────────────────────────────────────────────
#  DELETE /rules/{rule_id}
# ────────────────────────────────────────────────────────────────────────────

@router.delete("/rules/{rule_id}")
async def delete_rule(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Delete a firewall rule.

    Steps:
      1. Look up rule in DB.
      2. Call Ryu DELETE /firewall/rules/{rule_id} to remove from OVS.
      3. Soft-delete in DB (active=False, deleted_at=now).
      4. Clear dedup cache so new alerts can install new rules.

    Returns { "deleted": true, "rule_id": "..." }
    """
    rule = await crud.get_rule_by_id(db, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    if not rule.active:
        raise HTTPException(
            status_code=409,
            detail=f"Rule {rule_id} is already inactive",
        )

    # ── Remove from OVS via Ryu ───────────────────────────────────────
    try:
        await ryu_delete(str(rule_id))
    except RyuClientError as e:
        # Ryu unreachable — still soft-delete from DB so dashboard stays consistent
        log.warning(
            "Ryu delete failed for rule %s: %s — deactivating in DB anyway",
            rule_id, e,
        )

    # ── Soft-delete in DB ─────────────────────────────────────────────
    await crud.deactivate_rule(db, rule_id)

    # ── Clear dedup so same IP can be acted on again ──────────────────
    dedup.clear(rule.src_ip)

    log.info("Rule deleted | rule_id=%s | src_ip=%s", rule_id, rule.src_ip)
    return {"deleted": True, "rule_id": str(rule_id)}