# FlowGuard-Mitigating-Engine

> **FlowGuard** — FastAPI-based mitigation engine: the security decision center that translates ML verdicts into OpenFlow firewall rules.

Part of the [FlowGuard](https://github.com/FlowGuard-platform) intelligent network security platform. This module sits between the ML detection module and the SDN controller. It receives attack verdicts, normalizes and deduplicates them, decides the appropriate mitigation action, persists everything to PostgreSQL, and instructs the Ryu controller to install the corresponding OpenFlow rules — all in well under a second.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Database Setup](#database-setup)
- [Running the Service](#running-the-service)
- [REST API Reference](#rest-api-reference)
- [Decision Logic](#decision-logic)
- [Fault Tolerance](#fault-tolerance)
- [Testing](#testing)
 

---

## Overview

The mitigation engine is a **FastAPI** service (Python 3.11) exposed on port **9000**. When it receives an alert from the ML module it executes a deterministic five-step pipeline:

1. **Normalize** — validate and unify the incoming payload (Pydantic, HTTP 422 on bad input)
2. **Decide** — map the attack label + confidence to an action (`block`, `ratelimit`, `isolate`, or `log_only`)
3. **Persist** — write the alert to PostgreSQL *before* contacting the controller (no lost alerts even if Ryu is down)
4. **Deduplicate** — skip rule installation if the same source IP was already handled within the cache window
5. **Act** — call `POST /firewall/rules` on the Ryu controller and store the returned `rule_id` linked to the alert

---

## Architecture

```
  ML Module (:8000)
       │
       │  POST /alert  (JSON verdict)
       ▼
┌──────────────────────────────────────┐
│      Mitigating Engine (:9000)       │
│                                      │
│  normalizer → decision → dedup       │
│      │                               │
│      └──► PostgreSQL (:5432)         │
│                                      │
│  actions ──► SDN Controller (:8080)  │
└──────────────────────────────────────┘
       ▲
       │  CRUD (alerts, rules)
  Dashboard Backend (:3000)
```

---

## Project Structure

```
FlowGuard-Mitigating-Engine/
├── src/
│   ├── api/
│   │   └── alert.py          # POST /alert + CRUD routes
│   ├── normalizer.py         # Pydantic validation & field unification
│   ├── decision.py           # Label → action mapping table
│   ├── dedup.py              # In-memory deduplication cache
│   ├── actions.py            # HTTP calls to Ryu (block/ratelimit/isolate)
│   ├── db.py                 # SQLAlchemy async models (alert, rule)
│   ├── crud.py               # DB operations (insert_alert, get_alerts, …)
│   ├── capture.py            # Entry-point: starts the FastAPI server + capture listener
│   └── main.py               # FastAPI app factory
├── tests/
│   └── db_test.py            # Integration test: insert + retrieve alert via PostgreSQL
├── requirements.txt
└── .env.example
```

---

## Prerequisites

- Python **3.11**
- **PostgreSQL** (tested with 14+)
- Running **SDN controller** (Ryu) reachable at the configured URL
- Linux host (same VM as OVS recommended for low-latency rule installation)

---

## Installation

```bash
git clone https://github.com/Anisayz/FlowGuard-Mitigating-Engine.git
cd FlowGuard-Mitigating-Engine

python3.11 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

---

## Configuration

Copy `.env.example` to `.env` and adjust values:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://flowguard:flowguard@localhost:5432/flowguard` | Async PostgreSQL connection string |
| `RYU_BASE_URL` | `http://127.0.0.1:8080` | SDN controller REST endpoint |
| `RYU_API_KEY` | *(none)* | Forwarded as `X-API-Key` to Ryu |
| `CAPTURE_INTERFACE` | `mirror0` | Network interface for passive traffic capture |
| `DEDUP_WINDOW_SECONDS` | `30` | Time window for source-IP deduplication |
| `LOG_LEVEL` | `INFO` | Python logging level |

---

## Database Setup

```bash
# Create the database and user (run as postgres superuser)
createuser flowguard --pwprompt
createdb flowguard --owner=flowguard

# Tables are created automatically on first startup via SQLAlchemy
```

### Data model

**`alert`** — every verdict received from the ML module:

| Column | Type | Description |
|---|---|---|
| `id` | int PK | Auto-increment |
| `verdict` | enum | `ATTACK` / `SUSPECT` / `ANOMALY` |
| `label` | varchar | Attack class from Random Forest |
| `confidence` | float | RF prediction probability |
| `src_ip`, `dst_ip` | varchar | Flow endpoints |
| `src_port`, `dst_port` | int | L4 ports |
| `protocol` | int | 6=TCP, 17=UDP |
| `anomaly_score` | float | Autoencoder reconstruction error |
| `action` | enum | Action chosen by the engine |
| `received_at` | timestamp | Reception time |

**`rule`** — every OpenFlow rule installed (or attempted):

| Column | Type | Description |
|---|---|---|
| `rule_id` | uuid PK | Provided by Ryu |
| `src_ip` | varchar | Targeted source address |
| `action` | enum | `block` / `ratelimit` / `isolate` |
| `rate_kbps` | int | Allowed bandwidth (ratelimit only) |
| `dpid` | bigint | Target switch datapath ID |
| `source` | enum | `manual` or `mitigation_engine` |
| `alert_id` | int FK | Alert that triggered this rule (nullable for manual rules) |
| `idle_timeout`, `hard_timeout` | int | OpenFlow rule lifetimes |
| `active` | bool | Logical delete flag |
| `created_at`, `deleted_at` | timestamp | Lifecycle timestamps |

> **Soft deletes** — rules are never physically removed. `active=false` + `deleted_at=now()` preserves a complete audit trail.

---

## Running the Service

```bash
# Ensure PostgreSQL and the SDN controller are already up
python3 -m src.capture --interface mirror0
```

The service starts on port **9000** and begins listening for capture events on the specified interface simultaneously.

---

## REST API Reference

All routes return JSON. Mutable routes require `Authorization: Bearer <JWT>` when called from the dashboard backend, or `X-API-Key` for internal service-to-service calls.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/alert` | Receive an ML verdict and run the full pipeline |
| `GET` | `/alerts` | Paginated, filterable list of alerts |
| `GET` | `/alerts/{id}` | Single alert detail |
| `GET` | `/rules` | Paginated list of rules |
| `GET` | `/rules/{id}` | Single rule detail |
| `POST` | `/rules/manual` | Create a manual rule from the dashboard |
| `DELETE` | `/rules/{id}` | Deactivate a rule (removes it from the switch + soft-deletes in DB) |
| `GET` | `/health` | Service health summary |

### POST `/alert` — payload

```json
{
  "verdict": "ATTACK",
  "label": "DDoS attack-HOIC",
  "confidence": 0.97,
  "src_ip": "10.0.0.1",
  "dst_ip": "10.0.0.2",
  "src_port": 54321,
  "dst_port": 80,
  "protocol": 6,
  "anomaly_score": 0.45
}
```

**Response (rule installed):**
```json
{
  "alert_id": 42,
  "action": "block",
  "rule_id": "a3f1c2d4-...",
  "deduplicated": false
}
```

---

## Decision Logic

The engine maps each attack label to an action using a priority table. The confidence score modulates edge cases:

| Attack category | Action | Rationale |
|---|---|---|
| DDoS volumetric (HOIC, LOIC) | `block` | Cut immediately |
| DoS Hulk | `block` | Cut immediately |
| Slow DoS (Slowloris, GoldenEye) | `ratelimit` | Preserve existing TCP connections |
| Web brute force (XSS, login) | `ratelimit` | Limit without blocking |
| SQL Injection | `block` | Data exfiltration risk |
| Bot, Infiltration | `isolate` | Host presumed compromised |
| SSH / FTP brute force (high confidence) | `block` | Clear behavior |
| SSH / FTP brute force (low confidence) | `ratelimit` | Reduce false-positive risk |

Labels with no match default to `log_only` — the alert is stored but no OpenFlow rule is installed.

---

## Fault Tolerance

| Failure | Behavior |
|---|---|
| Ryu unreachable | Alert persisted to DB; rule creation skipped; warning logged; no crash |
| PostgreSQL unreachable | Alert processing fails with HTTP 503; ML module retry mechanism kicks in |
| Dashboard unreachable | No effect on internal pipeline; only visual monitoring is affected |
| Duplicate alert (same src_ip within window) | Alert stored; rule installation skipped; `deduplicated: true` in response |

---

## Testing

```bash
# Integration test — requires a running PostgreSQL instance
pytest tests/db_test.py -v
```

The test inserts a representative alert and verifies it can be retrieved via `get_alerts`, validating the `insert_alert`/`get_alerts` pair and enum serialization.

---

 
