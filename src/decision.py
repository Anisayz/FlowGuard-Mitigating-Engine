"""
decision.py — maps alert label + verdict + confidence → mitigation action.

Design rules:
  1. Label is the primary signal — a DDoS is always blocked regardless
     of confidence because the label itself carries the severity.
  2. Confidence is a secondary signal — used only for ambiguous labels
     (brute force) where a low-confidence prediction should be downgraded.
  3. Verdict from the ML engine (ATTACK / SUSPECT / ANOMALY) is used
     only when the label is unknown or generic.
  4. IDS alerts always come with confidence=1.0 (signatures are binary).

Action meanings:
  block     → DROP all traffic from src_ip (priority 200 in OVS Table 0)
  ratelimit → Meter rule to cap src_ip bandwidth (priority 150)
  isolate   → DROP both directions: src_ip and dst_ip (full isolation)
  log_only  → Store in DB, do NOT call Ryu (SUSPECT / low-confidence)
"""

from src.normalizer import AlertData
from src.config import get_settings

settings = get_settings()


# ────────────────────────────────────────────────────────────────────────────
#  Label → (action, min_confidence)
#
#  min_confidence = 0.0 means the action is applied regardless of confidence.
#  min_confidence > 0.0 means: if confidence < threshold → downgrade to ratelimit.
# ────────────────────────────────────────────────────────────────────────────

LABEL_ACTION_MAP: dict[str, tuple[str, float]] = {
    # ── High-volume DDoS → always block ──────────────────────────────
    "DDoS attacks-LOIC-HTTP":   ("block",     0.0),
    "DDoS attacks-LOIC-UDP":    ("block",     0.0),
    "DDoS attacks-HOIC":        ("block",     0.0),

    # ── DoS volume attacks → block ────────────────────────────────────
    "DoS attacks-Hulk":         ("block",     0.0),

    # ── Slow DoS → ratelimit (cutting them off loses TCP state) ───────
    "DoS attacks-SlowHTTPTest": ("ratelimit", 0.0),
    "DoS attacks-Slowloris":    ("ratelimit", 0.0),
    "DoS attacks-GoldenEye":    ("ratelimit", 0.0),

    # ── Web layer attacks → ratelimit ─────────────────────────────────
    "Brute Force -Web":         ("ratelimit", 0.0),
    "Brute Force -XSS":         ("ratelimit", 0.0),

    # ── Database exploit → block immediately ──────────────────────────
    "SQL Injection":            ("block",     0.0),

    # ── Protocol exploit → block ──────────────────────────────────────
    "Heartbleed":               ("block",     0.0),

    # ── Compromised host → full isolation ─────────────────────────────
    "Bot":                      ("isolate",   0.0),
    "Infiltration":             ("isolate",   0.0),
    # ── Brute force — confidence-gated ────────────────────────────────
    # High confidence → block outright.
    # Low confidence → ratelimit (buy time without false-positive risk).
    "FTP-BruteForce":           ("block",     0.70),
    "SSH-Bruteforce":           ("block",     0.70),

    # ── Port scan → ratelimit (scanning itself is not destructive) ────
    "PortScan":                 ("ratelimit", 0.0),
}


def decide(alert: AlertData) -> str:

    label      = alert.label or ""
    verdict    = (alert.verdict or "").upper()
    confidence = alert.confidence
    # ── BENIGN — should never arrive but guard anyway ─────────────────
    if verdict == "BENIGN" :
        return "log_only"

    # ── SUSPECT — ML says possible attack but confidence too low ──────

    if verdict == "SUSPECT" and label == "BENIGN" :
        return "log_only"

    # ── ANOMALY — AE flagged but RF didn't classify it ────────────────
    # Unknown threat → cautious ratelimit (never block an unknown)
    if verdict == "ANOMALY":
        return "ratelimit"

    # ── ATTACK — look up the label in the map ─────────────────────────
    if label in LABEL_ACTION_MAP:
        action, min_conf = LABEL_ACTION_MAP[label]

        # Confidence gate: if threshold is set and not met → downgrade
        threshold = min_conf or settings.BRUTE_FORCE_CONF_THRESHOLD \
            if min_conf > 0.0 else 0.0

        if threshold > 0.0 and confidence < threshold:
            # Not confident enough for the primary action — be conservative
            return "ratelimit"

        return action

    # ── ATTACK with unknown label ─────────────────────────────────────
    # RF says it's an attack but we don't recognise the class.
    # Ratelimit is the safe default — never block without knowing why.
    if verdict == "ATTACK":
        return "ratelimit"

    # ── Fallback ──────────────────────────────────────────────────────
    return "log_only"


def describe_decision(alert: AlertData, action: str) -> str:

    if action == "log_only":
        return (
            f"No OVS action: verdict={alert.verdict} confidence={alert.confidence:.2f} "
            f"label='{alert.label}'"
        )
    if alert.label in LABEL_ACTION_MAP:
        base_action, threshold = LABEL_ACTION_MAP[alert.label]
        if threshold > 0.0 and alert.confidence < threshold:
            return (
                f"Downgraded {base_action}→ratelimit: confidence {alert.confidence:.2f} "
                f"< threshold {threshold} for label '{alert.label}'"
            )
        return (
            f"Label match: '{alert.label}' → {action} "
            f"(confidence={alert.confidence:.2f})"
        )
    return (
        f"Fallback: verdict={alert.verdict} label='{alert.label}' → {action}"
    )