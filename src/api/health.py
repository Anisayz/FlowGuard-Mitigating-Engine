import logging
import time
from fastapi import APIRouter, Depends,  Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from typing import Optional
 

from src.db.database import get_db
from src.db import crud
from src.dedup import get_cache_snapshot

log = logging.getLogger(__name__)
health_router = APIRouter()
alerts_router = APIRouter()


@health_router.get("/health")
async def health(db: AsyncSession = Depends(get_db)):
 
    db_ok = False
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception as e:
        log.error("DB health check failed: %s", e)

    active_rules  = await crud.count_active_rules(db) if db_ok else -1
    total_alerts  = await crud.count_alerts(db)        if db_ok else -1
    dedup_entries = len(get_cache_snapshot())

    return {
        "status":        "ok" if db_ok else "degraded",
        "db":            "connected" if db_ok else "unreachable",
        "active_rules":  active_rules,
        "total_alerts":  total_alerts,
        "dedup_cache":   dedup_entries,
        "time":          time.time(),
    }


def _alert_to_dict(alert) -> dict:
    return {
        "id":             alert.id,
        "received_at":    alert.received_at.isoformat() if alert.received_at else None,
        "source":         alert.source,
        "verdict":        alert.verdict,
        "action":         alert.action,
        "label":          alert.label,
        "confidence":     alert.confidence,
        "ml_source":      alert.ml_source,
        "src_ip":         alert.src_ip,
        "dst_ip":         alert.dst_ip,
        "src_port":       alert.src_port,
        "dst_port":       alert.dst_port,
        "protocol":       alert.protocol,
        "anomaly_score":  alert.anomaly_score,
        "anomaly_flagged":alert.anomaly_flagged,
        "rule_id":        str(alert.rule_id) if alert.rule_id else None,
        "start_time_ms":  alert.start_time_ms,
        "end_time_ms":    alert.end_time_ms,
    }


@alerts_router.get("/alerts")
async def list_alerts(
    verdict: Optional[str] = Query(None, description="ATTACK | SUSPECT | ANOMALY"),
    src_ip:  Optional[str] = Query(None, description="Filter by source IP"),
    limit:   int           = Query(100,  ge=1, le=1000),
    offset:  int           = Query(0,    ge=0),
    db: AsyncSession = Depends(get_db),
):
 
    total = await crud.count_alerts(db, verdict=verdict, src_ip=src_ip) 
    alerts = await crud.get_alerts(
        db,
        limit=limit,
        offset=offset,
        verdict=verdict,
        src_ip=src_ip,
    )
    return {
        "total":  total,
        "count":  len(alerts),
        "alerts": [_alert_to_dict(a) for a in alerts],
    }


@alerts_router.get("/alerts/{alert_id}")
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
):
     
    alert = await crud.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return _alert_to_dict(alert)