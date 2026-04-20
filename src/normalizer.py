"""
normalizer.py — convert incoming alert payloads to a unified internal schema.

Two sources send alerts to POST /alert:
  1. ML engine (alert.py)  — rich payload with verdict, confidence, label
  2. IDS (Suricata processor) — simpler payload with signature info

Both are normalized into the same AlertData dataclass before reaching
the decision engine. This means decision.py never needs to know
which source sent the alert.

IDS alert payload example:
{
    "source":    "ids",
    "src_ip":    "10.0.0.5",
    "dst_ip":    "10.0.0.1",
    "src_port":  54321,
    "dst_port":  80,
    "protocol":  6,
    "signature": "SYN flood detected",
    "severity":  1,              ← 1=high, 2=medium, 3=low
    "category":  "DoS",
    "sid":       9000001
}

ML engine alert payload example (from alert.py):
{
    "source":          "ae",           ← "ae" | "rf" | "rf+ae"
    "action":          "block",
    "verdict":         "ATTACK",
    "label":           "DDoS attacks-LOIC-HTTP",
    "confidence":      0.999,
    "src_ip":          "10.0.0.5",
    "dst_ip":          "10.0.0.1",
    "src_port":        54321,
    "dst_port":        80,
    "protocol":        6,
    "start_time_ms":   1700000000000,
    "end_time_ms":     1700000001500,
    "anomaly_score":   -0.045,
    "anomaly_flagged": true
}
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AlertData:

    source:          str            # "ml_engine" | "ids" |
    verdict:         str            # ATTACK | SUSPECT | ANOMALY | BENIGN
    label:           str            # attack class label or IDS category
    confidence:      float          # 0.0–1.0 (1.0 for IDS — signatures are certain)
    src_ip:          str
    dst_ip:          Optional[str]  = None
    src_port:        Optional[int]  = None
    dst_port:        Optional[int]  = None
    protocol:        Optional[int]  = None
    start_time_ms:   Optional[int]  = None
    end_time_ms:     Optional[int]  = None
    anomaly_score:   Optional[float]= None
    anomaly_flagged: bool           = False
    ml_source:       Optional[str]  = None   # RF | RF+AE | AE


# Map IDS category/signature strings to CIC-IDS2018-style labels
# so decision.py uses one unified label space.
_IDS_CATEGORY_MAP = {
    "dos":           "DoS attacks-Hulk",
    "ddos":          "DDoS attacks-LOIC-HTTP",
    "syn flood":     "DoS attacks-Hulk",
    "portscan":      "PortScan",
    "brute force":   "FTP-BruteForce",
    "ssh brute":     "SSH-Bruteforce",
    "ftp brute":     "FTP-BruteForce",
    "sql injection": "SQL Injection",
    "xss":           "Brute Force -XSS",
    "web attack":    "Brute Force -Web",
    "heartbleed":    "Heartbleed",
    "botnet":        "Bot",
    "infiltration":  "Infilteration",
}


def normalize(payload: dict) -> AlertData:

    source = payload.get("source", "ml_engine").lower()

    if source == "ae" or source == "rf" or source == "rf+ae": 
        return _normalize_ml(payload)  
    elif source == "ids":
        return _normalize_ids(payload)
 
    else:
        raise ValueError(f"Unknown alert source: '{source}'")


def _normalize_ml(p: dict) -> AlertData:
    src_ip = p.get("src_ip", "").strip()
    if not src_ip:
        raise ValueError("src_ip is required in ML engine alert")

    verdict = p.get("verdict", "BENIGN").upper()
    label   = p.get("label", "Unknown")

    return AlertData(
        source          = "ml_engine ",
        verdict         = verdict,
        label           = label,
        confidence      = float(p.get("confidence") or 0.0), 
        src_ip          = src_ip,
        dst_ip          = p.get("dst_ip"),
        src_port        = p.get("src_port"),
        dst_port        = p.get("dst_port"),
        protocol        = p.get("protocol"),
        start_time_ms   = p.get("start_time_ms"),
        end_time_ms     = p.get("end_time_ms"),
        anomaly_score   = p.get("anomaly_score"),
        anomaly_flagged = bool(p.get("anomaly_flagged", False)),
        ml_source       = p.get("source", p.get("ml_source")),
    )


def _normalize_ids(p: dict) -> AlertData:
    src_ip = p.get("src_ip", "").strip()
    if not src_ip:
        raise ValueError("src_ip is required in IDS alert")

    # Map IDS category to a unified label
    category  = p.get("category", "").lower()
    signature = p.get("signature", "").lower()
    label     = _IDS_CATEGORY_MAP.get(category) or _IDS_CATEGORY_MAP.get(
        next((k for k in _IDS_CATEGORY_MAP if k in signature), ""), "Unknown"
    )

    # IDS severity: 1=high→ATTACK, 2=medium→SUSPECT, 3=low→SUSPECT
    severity = int(p.get("severity", 2))
    verdict  = "ATTACK" if severity == 1 else "SUSPECT"

    return AlertData(
        source          = "ids",
        verdict         = verdict,
        label           = label,
        confidence      = 1.0,   # IDS signatures are binary — treat as 100%
        src_ip          = src_ip,
        dst_ip          = p.get("dst_ip"),
        src_port        = p.get("src_port"),
        dst_port        = p.get("dst_port"),
        protocol        = p.get("protocol"),
        start_time_ms   = None,
        end_time_ms     = None,
        anomaly_score   = None,
        anomaly_flagged = False,
        ml_source       = None,
    )