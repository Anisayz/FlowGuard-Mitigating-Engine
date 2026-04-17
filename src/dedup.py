 
import time
import logging
from src.config import get_settings

log = logging.getLogger(__name__)
settings = get_settings()
 
_cache: dict[str, float] = {}


def is_duplicate(src_ip: str) -> bool:
 
    
    last = _cache.get(src_ip)
    if last is None:
        return False

    elapsed = time.time() - last
    if elapsed < settings.DEDUP_COOLDOWN_S:
        log.debug(
            "DEDUP hit | src_ip=%s | last_action=%.1fs ago | cooldown=%ds",
            src_ip, elapsed, settings.DEDUP_COOLDOWN_S,
        )
        return True

    # Cooldown expired — remove stale entry
    _cache.pop(src_ip, None)
    return False

def record_action(src_ip: str) -> None:
    """
    Record that we just acted on src_ip.
    Call this immediately after a successful Ryu call.
    """
    _cache[src_ip] = time.time()
    log.debug("DEDUP recorded | src_ip=%s", src_ip)


def clear(src_ip: str) -> None:
    """
    Manually clear the cooldown for src_ip.
    Called when a rule is deleted so a new alert can trigger a new rule.
    """
    if src_ip in _cache:
        del _cache[src_ip]
        log.debug("DEDUP cleared | src_ip=%s", src_ip)


def get_cache_snapshot() -> dict[str, float]:
   
    return dict(_cache)