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

RF labels (from CIC-IDS2018 training data):
    Benign, Bot, Brute Force -Web, Brute Force -XSS,
    DDOS attack-HOIC, DDOS attack-LOIC-UDP, DDoS attacks-LOIC-HTTP,
    DoS attacks-GoldenEye, DoS attacks-Hulk, DoS attacks-SlowHTTPTest,
    DoS attacks-Slowloris, FTP-BruteForce, Infilteration,
    SQL Injection, SSH-Bruteforce

Heuristic / AE-inferred labels (from alert.py _resolve_attack_type):
    SYN Flood, Port Scan, HTTP Scan, HTTPS Scan, SSH Scan,
    FTP Scan, RDP Scan, SSH Brute Force, FTP Brute Force,
    HTTP DoS, HTTPS DoS, Anomalous Flow
"""

from src.normalizer import AlertData
from src.config import get_settings

settings = get_settings()

 
LABEL_ACTION_MAP: dict[str, tuple[str, float]] = {

   
    "DDoS attacks-LOIC-HTTP"   : ("block",     0.0),
    "DDoS attacks-LOIC-UDP"    : ("block",     0.0),
    "DDOS attack-LOIC-UDP"     : ("block",     0.0),   # alternate capitalisation
    "DDOS attack-HOIC"         : ("block",     0.0),
    "DDoS attacks-HOIC"        : ("block",     0.0),   # alternate capitalisation
    "DoS attacks-Hulk"         : ("block",     0.0),
    "HTTP DoS"                 : ("block",     0.0),   # heuristic label
    "HTTPS DoS"                : ("block",     0.0),   # heuristic label

   
    "SYN Flood"                : ("block",     0.0),

   
    "DoS attacks-SlowHTTPTest" : ("ratelimit", 0.0),
    "DoS attacks-Slowloris"    : ("ratelimit", 0.0),
    "DoS attacks-GoldenEye"    : ("ratelimit", 0.0),

    
    "Port Scan"                : ("isolate",   0.0),
    "HTTP Scan"                : ("isolate",   0.0),
    "HTTPS Scan"               : ("isolate",   0.0),
    "SSH Scan"                 : ("isolate",   0.0),
    "FTP Scan"                 : ("isolate",   0.0),
    "RDP Scan"                 : ("isolate",   0.0),

   
    "Brute Force -Web"         : ("ratelimit", 0.0),
    "Brute Force -XSS"         : ("ratelimit", 0.0),

   
    "SQL Injection"            : ("block",     0.0),

     
    "Heartbleed"               : ("block",     0.0),

    # ── Compromised host → full isolation ─────────────────────────────
    "Bot"                      : ("isolate",   0.0),
    "Infilteration"            : ("isolate",   0.0),

    # ── Brute force — confidence-gated ────────────────────────────────
    # High confidence → block outright.
    # Low confidence  → ratelimit (buy time without false-positive risk).
    "FTP-BruteForce"           : ("block",     0.70),
    "SSH-Bruteforce"           : ("block",     0.70),
    "SSH Brute Force"          : ("block",     0.70),   # heuristic label
    "FTP Brute Force"          : ("block",     0.70),   # heuristic label

    # ── Anomalous Flow — AE flagged, RF uncertain ─────────────────────
    # Unknown threat profile → cautious ratelimit, never block blindly.
    "Anomalous Flow"           : ("ratelimit", 0.0),
}


def decide(alert: AlertData) -> str:
    """
    Map an alert to a mitigation action.

    Returns one of: "block", "ratelimit", "isolate", "log_only"
    """
    label      = (alert.label or "").strip()
    verdict    = (alert.verdict or "").upper()
    confidence = alert.confidence

    # ── BENIGN — should never arrive but guard anyway ─────────────────
    if verdict == "BENIGN":
        return "log_only"

    # ── SUSPECT — low-confidence attack signal ────────────────────────
    if verdict == "SUSPECT":
        # If RF actually named an attack class, still look it up
        if label and label != "Benign" and label in LABEL_ACTION_MAP:
            pass   # fall through to label lookup below
        else:
            return "log_only"

    # ── ANOMALY — AE flagged, RF said Benign ─────────────────────────
    # Use label if it was resolved to something meaningful by _resolve_attack_type,
    # otherwise default to ratelimit (never block an unknown threat).
    if verdict == "ANOMALY":
        if label in LABEL_ACTION_MAP:
            pass   # fall through to label lookup below
        else:
            return "ratelimit"

    # ── Label lookup ──────────────────────────────────────────────────
    if label in LABEL_ACTION_MAP:
        action, min_conf = LABEL_ACTION_MAP[label]

        # Confidence gate
        threshold = (
            min_conf or settings.BRUTE_FORCE_CONF_THRESHOLD
            if min_conf > 0.0 else 0.0
        )
        if threshold > 0.0 and confidence < threshold:
            return "ratelimit"

        return action

    # ── ATTACK with unknown label ─────────────────────────────────────
    if verdict == "ATTACK":
        return "ratelimit"

    # ── Fallback ──────────────────────────────────────────────────────
    return "log_only"


def describe_decision(alert: AlertData, action: str) -> str:
    """Return a human-readable explanation of why an action was chosen."""

    if action == "log_only":
        return (
            f"No OVS action: verdict={alert.verdict} "
            f"confidence={alert.confidence:.2f} label='{alert.label}'"
        )

    label = (alert.label or "").strip()

    if label in LABEL_ACTION_MAP:
        base_action, threshold = LABEL_ACTION_MAP[label]
        if threshold > 0.0 and alert.confidence < threshold:
            return (
                f"Downgraded {base_action}→ratelimit: "
                f"confidence {alert.confidence:.2f} < threshold {threshold} "
                f"for label '{label}'"
            )
        return (
            f"Label match: '{label}' → {action} "
            f"(confidence={alert.confidence:.2f})"
        )

    return (
        f"Fallback: verdict={alert.verdict} label='{label}' → {action}"
    )