

import logging
from src.actions.ryu_client import install_rule
from src.config import get_settings

log = logging.getLogger(__name__)
settings = get_settings()
DEFAULT_RATE_KBPS = 512


async def execute_block(
    src_ip: str,
    idle_timeout: int | None = None,
    hard_timeout: int | None = None,
    dpid: int | None = None,
) -> dict:

    payload = {
        "action":       "block",
        "src_ip":       src_ip,
        "idle_timeout": idle_timeout if idle_timeout is not None else settings.DEFAULT_IDLE_TIMEOUT,
        "hard_timeout": hard_timeout if hard_timeout is not None else settings.DEFAULT_HARD_TIMEOUT,
        "source":       "mitigation_engine",
    }
    if dpid is not None:
        payload["dpid"] = dpid
    log.warning("ACTION block | src_ip=%s", src_ip)
    return await install_rule(payload)


async def execute_ratelimit(
        src_ip: str,
        rate_kbps: int = DEFAULT_RATE_KBPS,
        idle_timeout: int | None = None,
        hard_timeout: int | None = None,
        dpid: int | None = None,
) -> dict:
    """
    Rate-limit traffic from src_ip to rate_kbps kilobits/second.
    Returns the rule dict from Ryu (includes rule_id, dpid, meter_id).
    """
 
    if rate_kbps <= 0:
        raise ValueError("rate_kbps must be positive")
    payload = {
        "action": "ratelimit",
        "src_ip": src_ip,
        "rate_kbps": rate_kbps,
        "idle_timeout": idle_timeout if idle_timeout is not None else settings.DEFAULT_IDLE_TIMEOUT,
        "hard_timeout": hard_timeout if hard_timeout is not None else settings.DEFAULT_HARD_TIMEOUT,
        "source": "mitigation_engine",
    }
    if dpid is not None:
        payload["dpid"] = dpid    
        log.warning(
        "ACTION ratelimit | src_ip=%s | rate=%d kbps", src_ip, rate_kbps
    )
    return await install_rule(payload)


async def execute_isolate(
        src_ip: str,
        idle_timeout: int | None = None,
        hard_timeout: int | None = None,
        dpid: int | None = None,
) -> dict:

    payload = {
        "action": "isolate",
        "src_ip": src_ip,
        "idle_timeout": idle_timeout or settings.DEFAULT_IDLE_TIMEOUT,
        "hard_timeout": hard_timeout or settings.DEFAULT_HARD_TIMEOUT,
        "source": "mitigation_engine",
    }
    if dpid:
        payload["dpid"] = dpid

    log.warning("ACTION isolate | src_ip=%s (full isolation)", src_ip)
    return await install_rule(payload)