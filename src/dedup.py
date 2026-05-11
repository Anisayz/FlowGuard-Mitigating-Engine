import asyncio
import logging
import time

from src.config import get_settings

log      = logging.getLogger(__name__)
settings = get_settings()

_FlowKey = tuple[str, str, str]   # (src_ip, dst_ip, verdict)

_cache: dict[_FlowKey, float] = {}

_lock = asyncio.Lock()


def _make_key(src_ip: str, dst_ip: str, verdict: str) -> _FlowKey:
    return (src_ip, dst_ip or "", verdict.upper())


async def check_and_record(
    src_ip:  str,
    dst_ip:  str = "",
    verdict: str = "",
) -> bool:
    key = _make_key(src_ip, dst_ip, verdict)
    async with _lock:
        last = _cache.get(key)
        if last is not None:
            elapsed = time.time() - last
            if elapsed < settings.DEDUP_COOLDOWN_S:
                log.debug(
                    "DEDUP hit | src_ip=%s dst_ip=%s verdict=%s "
                    "| last_action=%.1fs ago | cooldown=%ds",
                    src_ip, dst_ip, verdict,
                    elapsed, settings.DEDUP_COOLDOWN_S,
                )
                return True
            del _cache[key]
        _cache[key] = time.time()
        log.debug(
            "DEDUP reserved | src_ip=%s dst_ip=%s verdict=%s",
            src_ip, dst_ip, verdict,
        )
        return False


def clear(
    src_ip:  str,
    dst_ip:  str = "",
    verdict: str = "",
) -> None:
    key = _make_key(src_ip, dst_ip, verdict)
    if key in _cache:
        del _cache[key]
        log.debug(
            "DEDUP cleared | src_ip=%s dst_ip=%s verdict=%s",
            src_ip, dst_ip, verdict,
        )


def get_cache_snapshot() -> dict[str, float]:
    return {str(k): v for k, v in _cache.items()}