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
  5. Heuristic flags are resolved separately and merged with the label
     result — the more severe of the two wins.

Action meanings:
  block     → DROP all traffic from src_ip (priority 200 in OVS Table 0)
  ratelimit → Meter rule to cap src_ip bandwidth (priority 150)
  isolate   → DROP both directions: src_ip and dst_ip (full isolation)
  log_only  → Store in DB, do NOT call Ryu (SUSPECT / low-confidence)

IMPORTANT — keep these three files in sync when adding a new heuristic rule:
  1. heuristics.py  — add the rule function
  2. alert.py       — add rule_name → label in _HEUR_LABEL_MAP
  3. decision.py    — add that label → action in LABEL_ACTION_MAP
Failure to update step 3 causes heuristic-only alerts to fall through to log_only.
"""

from src.normalizer import AlertData
from src.config import get_settings

settings = get_settings()



LABEL_ACTION_MAP: dict[str, tuple[str, float]] = {

   
    "DDoS attacks-LOIC-HTTP"   : ("block",     0.0),
    "DDoS attacks-LOIC-UDP"    : ("block",     0.0),
    "DDOS attack-LOIC-UDP"     : ("block",     0.0),
    "DDOS attack-HOIC"         : ("block",     0.0),
    "DDoS attacks-HOIC"        : ("block",     0.0),
    "DoS attacks-Hulk"         : ("block",     0.0),
    "HTTP DoS"                 : ("block",     0.0),
    "HTTPS DoS"                : ("block",     0.0),

    
    "SYN Flood"                : ("block",     0.0),

    
    "DoS attacks-SlowHTTPTest" : ("ratelimit", 0.0),
    "DoS attacks-Slowloris"    : ("ratelimit", 0.0),
    "DoS attacks-GoldenEye"    : ("ratelimit", 0.0),

    # Scanning
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

    
    "Bot"                      : ("isolate",   0.0),
    "Infilteration"            : ("isolate",   0.0),

    
    "FTP-BruteForce"           : ("block",     0.70),
    "SSH-Bruteforce"           : ("block",     0.70),
    "SSH Brute Force"          : ("block",     0.70),
    "FTP Brute Force"          : ("block",     0.70),
 
    "Anomalous Flow"           : ("ratelimit", 0.0),

   
    "SYN Flood"                : ("block",     0.0),   
    "DoS attacks-Slowloris"    : ("ratelimit", 0.0),  
    "Port Scan"                : ("isolate",   0.0),   
    "Brute Force"              : ("ratelimit", 0.70),   
    "ICMP Flood"               : ("ratelimit", 0.0),    
    "UDP Probe"                : ("log_only",  0.0),   
    "Web Scanner"              : ("isolate",   0.0),   
    "Injection Attack"         : ("block",     0.0),    
    "HTTP Probe"               : ("log_only",  0.0),    
}


 
HEUR_ACTION_MAP: dict[str, tuple[str, float]] = {
    "_rule_syn_flood"      : ("block",    0.0),
    "_rule_slowloris"      : ("ratelimit", 0.0),
    "_rule_brute_force"    : ("ratelimit", 0.0),
    "_rule_portscan"       : ("isolate",  0.0),
    "_rule_icmp_flood"     : ("ratelimit", 0.0),
    "_rule_empty_udp_probe": ("log_only", 0.0),
    "_rule_web_scanner"    : ("isolate",  0.0),
    "_rule_injection_tool" : ("block",    0.0),
    "_rule_http_probe"     : ("log_only", 0.0),
}


def _action_severity(action: str) -> int:
    """Higher = more severe. Used to pick the worst action across heuristics."""
    return {"block": 3, "isolate": 2, "ratelimit": 1, "log_only": 0}.get(action, 0)


def _resolve_heuristic_action(heuristic_flags: list[str]) -> str | None:
    """
    Walk all fired heuristic flags and return the most severe action among them.
    Rule name is the prefix before the first '(' or ':'.
    Returns None if no flags are present or none match HEUR_ACTION_MAP.
    """
    best: str | None = None
    for flag in heuristic_flags:
        rule_name = flag.split("(")[0].split(":")[0].strip()
        entry = HEUR_ACTION_MAP.get(rule_name)
        if entry is None:
            continue
        action, _ = entry
        if best is None or _action_severity(action) > _action_severity(best):
            best = action
    return best


def decide(alert: AlertData) -> str:
    """
    Map an alert to a mitigation action.

    Priority order:
      1. BENIGN verdict  → always log_only.
      2. Heuristic flags → resolved against HEUR_ACTION_MAP (raw rule names).
      3. Label lookup    → resolved against LABEL_ACTION_MAP (includes both
                           RF labels and heuristic translated labels).
      4. Merge           → more severe of heuristic vs label wins.
      5. Verdict-only    → fallback when neither label nor flags matched.

    Returns one of: "block", "ratelimit", "isolate", "log_only"
    """
    label           = (alert.label or "").strip()
    verdict         = (alert.verdict or "").upper()
    confidence      = alert.confidence
    heuristic_flags = getattr(alert, "heuristic_flags", []) or []

    # ── 1. BENIGN ─────────────────────────────────────────────────────
    if verdict == "BENIGN":
        return "log_only"

    # ── 2. Heuristic resolution (raw rule names from flags) ───────────
    heur_action = _resolve_heuristic_action(heuristic_flags)

    # ── 3. SUSPECT ────────────────────────────────────────────────────
    if verdict == "SUSPECT":
        if label and label != "Benign" and label in LABEL_ACTION_MAP:
            pass  # fall through to label lookup
        else:
            return heur_action if heur_action else "log_only"

    # ── 4. ANOMALY ────────────────────────────────────────────────────
    if verdict == "ANOMALY":
        if label in LABEL_ACTION_MAP:
            pass  # fall through to label lookup
        else:
            return heur_action if heur_action else "ratelimit"

    # ── 5. Label lookup (RF labels + heuristic translated labels) ─────
    label_action: str | None = None
    if label in LABEL_ACTION_MAP:
        action, min_conf = LABEL_ACTION_MAP[label]
        threshold = min_conf or settings.BRUTE_FORCE_CONF_THRESHOLD if min_conf > 0.0 else 0.0
        label_action = "ratelimit" if threshold > 0.0 and confidence < threshold else action

    # ── 6. Merge: more severe of heuristic vs label wins ─────────────
    if label_action is not None:
        if heur_action is not None:
            return (
                label_action
                if _action_severity(label_action) >= _action_severity(heur_action)
                else heur_action
            )
        return label_action

    # ── 7. ATTACK with unknown label ──────────────────────────────────
    if verdict == "ATTACK":
        return heur_action if heur_action else "ratelimit"

    # ── 8. Fallback ───────────────────────────────────────────────────
    return heur_action if heur_action else "log_only"


def describe_decision(alert: AlertData, action: str) -> str:
    """Return a human-readable explanation of why an action was chosen."""
    label           = (alert.label or "").strip()
    heuristic_flags = getattr(alert, "heuristic_flags", []) or []
    heur_action     = _resolve_heuristic_action(heuristic_flags)

    if action == "log_only":
        return (
            f"No OVS action: verdict={alert.verdict} "
            f"confidence={alert.confidence:.2f} label='{label}'"
        )

    if label in LABEL_ACTION_MAP:
        base_action, threshold = LABEL_ACTION_MAP[label]
        if threshold > 0.0 and alert.confidence < threshold:
            label_part = (
                f"Downgraded {base_action}→ratelimit: "
                f"confidence {alert.confidence:.2f} < threshold {threshold} "
                f"for label '{label}'"
            )
        else:
            label_part = (
                f"Label match: '{label}' → {base_action} "
                f"(confidence={alert.confidence:.2f})"
            )

        if heur_action and _action_severity(heur_action) > _action_severity(base_action):
            rule_names = [f.split("(")[0].split(":")[0] for f in heuristic_flags]
            return (
                f"Heuristic escalation [{','.join(rule_names)}]: "
                f"{base_action}→{heur_action}  ({label_part})"
            )
        return label_part

    if heur_action:
        rule_names = [f.split("(")[0].split(":")[0] for f in heuristic_flags]
        return (
            f"Heuristic match [{','.join(rule_names)}] → {action} "
            f"(no label match, verdict={alert.verdict})"
        )

    return f"Fallback: verdict={alert.verdict} label='{label}' → {action}"