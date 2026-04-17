import logging
from typing import Any

import httpx

from src.config import get_settings

log = logging.getLogger(__name__)
settings = get_settings()
 
_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            base_url=settings.RYU_BASE_URL,
            timeout=settings.RYU_TIMEOUT,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": settings.RYU_API_KEY,
            },
        )
    return _client


async def close_client() -> None:
   
    global _client
    if _client and not _client.is_closed:
        await _client.aclose()


async def install_rule(payload: dict[str, Any]) -> dict[str, Any]:
    """
    POST /firewall/rules — install a new rule on OVS via Ryu.

    payload fields:
        action        str  required — block | ratelimit | isolate
        src_ip        str  required
        idle_timeout  int  optional
        hard_timeout  int  optional
        rate_kbps     int  optional (ratelimit only)
        dpid          int  optional (auto-resolved by Ryu if omitted)
        source        str  optional — "mitigation_engine"

    Returns the rule dict from Ryu (includes rule_id and dpid).
    Raises RyuClientError on failure.
    """
    client = _get_client()
    log.info(
        "Ryu install_rule | action=%s | src_ip=%s",
        payload.get("action"), payload.get("src_ip"),
    )
    try:
        response = await client.post("/firewall/rules", json=payload)
        response.raise_for_status()
        data = response.json()
        log.info(
            "Ryu rule installed | rule_id=%s | dpid=%s",
            data.get("rule_id"), data.get("dpid"),
        )
        return data

    except httpx.HTTPStatusError as e:
        raise RyuClientError(
            f"Ryu returned {e.response.status_code}: {e.response.text[:200]}"
        ) from e
    except httpx.TimeoutException:
        raise RyuClientError(
            f"Ryu timed out after {settings.RYU_TIMEOUT}s — "
            "is the controller running?"
        )
    except httpx.ConnectError:
        raise RyuClientError(
            f"Cannot reach Ryu at {settings.RYU_BASE_URL} — "
            "check RYU_BASE_URL in .env"
        )


async def delete_rule(rule_id: str) -> bool:

    client = _get_client()
    log.info("Ryu delete_rule | rule_id=%s", rule_id)
    try:
        response = await client.delete(f"/firewall/rules/{rule_id}")
        if response.status_code == 404:
            log.warning("Ryu rule not found | rule_id=%s", rule_id)
            return False
        response.raise_for_status()
        log.info("Ryu rule deleted | rule_id=%s", rule_id)
        return True

    except httpx.HTTPStatusError as e:
        raise RyuClientError(
            f"Ryu returned {e.response.status_code}: {e.response.text[:200]}"
        ) from e
    except httpx.TimeoutException:
        raise RyuClientError(f"Ryu timed out deleting rule {rule_id}")
    except httpx.ConnectError:
        raise RyuClientError(
            f"Cannot reach Ryu at {settings.RYU_BASE_URL}"
        )


class RyuClientError(Exception):
    """Raised when the Ryu REST API call fails."""
    pass