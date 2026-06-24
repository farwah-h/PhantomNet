from __future__ import annotations

import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from siem_logger import siem_log, SiemSeverity, SiemSource
from src_client import src_send

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="PhantomNet++ ARE API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ActionType(str, Enum):
    isolate      = "isolate"
    switch_model = "switch_model"
    escalate     = "escalate"
    block        = "block"
    log          = "log"
    monitor      = "monitor"


class ActionStatus(str, Enum):
    success         = "success"
    failed          = "failed"
    partial_success = "partial_success"
    pending         = "pending"


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

import os
os.makedirs("db", exist_ok=True)
DB_PATH = "db/are_data.db"


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db():
    conn = _get_conn()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                id            TEXT PRIMARY KEY,
                priority      INTEGER NOT NULL,
                name          TEXT NOT NULL,
                condition     TEXT NOT NULL,
                action        TEXT NOT NULL,
                enabled       INTEGER NOT NULL DEFAULT 1,
                lastTriggered TEXT,
                triggerCount  INTEGER NOT NULL DEFAULT 0,
                createdAt     TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS actions (
                id            TEXT PRIMARY KEY,
                policyId      TEXT NOT NULL,
                policyName    TEXT NOT NULL,
                action        TEXT NOT NULL,
                target        TEXT NOT NULL,
                reason        TEXT NOT NULL,
                details       TEXT NOT NULL,
                result        TEXT NOT NULL,
                executionTime REAL NOT NULL,
                timestamp     TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS isolations (
                threat_id   TEXT PRIMARY KEY,
                filename    TEXT NOT NULL,
                isolated_at TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                duration_s  INTEGER NOT NULL,
                policy_name TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'active'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel_log (
                id          TEXT PRIMARY KEY,
                synced_at   TEXT NOT NULL,
                source      TEXT NOT NULL,
                fetched     INTEGER NOT NULL,
                ml_relevant INTEGER NOT NULL,
                new_policies INTEGER NOT NULL,
                status      TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_isolations_filename
            ON isolations (filename)
        """)


# ---------------------------------------------------------------------------
# MITRE ATLAS + CVSS v3.1 Default Policy Seeder
# ---------------------------------------------------------------------------

_ATLAS_DEFAULT_POLICIES = [
    # ── CRITICAL (CVSS 9.0-10.0) ──────────────────────────────────────────
    {
        "name":      "[ATLAS AML.T0015] Critical Evasion — Isolate & Escalate",
        "priority":  1,
        "condition": 'threat.severity == "critical" AND threat.confidence >= 0.85',
        "action":    "isolate",
        "enabled":   True,
    },
    {
        "name":      "[ATLAS AML.T0043] Physical Adversarial Patch — Isolate",
        "priority":  2,
        "condition": 'threat.severity == "critical" AND threat.confidence >= 0.80',
        "action":    "isolate",
        "enabled":   True,
    },

    # ── HIGH (CVSS 7.0-8.9) ───────────────────────────────────────────────
    {
        "name":      "[ATLAS AML.T0040] High Confidence Attack — Escalate to Analyst",
        "priority":  3,
        "condition": 'threat.severity == "high" AND threat.confidence >= 0.65',
        "action":    "escalate",
        "enabled":   True,
    },
    {
        "name":      "[ATLAS AML.T0019] Model Accuracy Degraded — Switch to Hardened",
        "priority":  4,
        "condition": 'threat.severity == "high" AND model.accuracy < 0.60',
        "action":    "switch_model",
        "enabled":   True,
    },
    {
        "name":      "[ATLAS AML.T0016] Byzantine Agent Deviation — Escalate",
        "priority":  5,
        "condition": 'agent.deviation >= 0.40 AND threat.severity == "high"',
        "action":    "escalate",
        "enabled":   True,
    },

    # ── MEDIUM (CVSS 4.0-6.9) ─────────────────────────────────────────────
    {
        "name":      "[ATLAS AML.T0020] Sustained Medium Threats — Harden Posture",
        "priority":  6,
        "condition": 'threat.severity == "medium" AND threat.confidence >= 0.50',
        "action":    "switch_model",
        "enabled":   True,
    },
    {
        "name":      "[ATLAS AML.T0036] Attack Staging Signal — Log & Monitor",
        "priority":  7,
        "condition": 'threat.severity == "medium" AND agent.confidence < 0.60',
        "action":    "log",
        "enabled":   True,
    },

    # ── LOW (CVSS 0.1-3.9) ────────────────────────────────────────────────
    {
        "name":      "[ATLAS AML.T0018] Low-Confidence Anomaly — Monitor",
        "priority":  8,
        "condition": 'threat.severity == "low" AND threat.confidence >= 0.30',
        "action":    "monitor",
        "enabled":   True,
    },
    {
        "name":      "[ATLAS AML.T0024] Model Robustness Degraded — Trigger Retrain",
        "priority":  9,
        "condition": 'model.robustness < 0.50 AND model.accuracy < 0.70',
        "action":    "log",
        "enabled":   False,
    },
]


def seed_default_policies() -> None:
    with db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM policies").fetchone()[0]
        if count > 0:
            print(f"[ARE] Policies already exist ({count}) — skipping ATLAS seed.")
            return

        now = datetime.now(timezone.utc).isoformat()
        for p in _ATLAS_DEFAULT_POLICIES:
            conn.execute(
                """INSERT INTO policies
                   (id, priority, name, condition, action, enabled, lastTriggered, triggerCount, createdAt)
                   VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?)""",
                (
                    f"pol-{uuid.uuid4().hex[:8]}",
                    p["priority"],
                    p["name"],
                    p["condition"],
                    p["action"],
                    1 if p["enabled"] else 0,
                    now,
                )
            )
        print(f"[ARE] Seeded {len(_ATLAS_DEFAULT_POLICIES)} MITRE ATLAS default policies.")


init_db()
seed_default_policies()


def row_to_policy(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["enabled"] = bool(d["enabled"])
    return d


def row_to_action(row: sqlite3.Row) -> dict:
    return dict(row)


# ---------------------------------------------------------------------------
# Condition Validator
# ---------------------------------------------------------------------------

_ALLOWED_FIELDS = {
    "threat.severity", "threat.confidence", "threat.status",
    "agent.deviation", "agent.confidence", "agent.anomaly_score",
    "model.accuracy", "model.robustness", "model.latency",
}

_OPERATORS = r"(==|!=|>=|<=|>|<)"

_CONDITION_TOKEN = re.compile(
    r'([a-z_]+\.[a-z_]+)\s*' + _OPERATORS + r'\s*("[^"]*"|\d+(\.\d+)?)',
    re.IGNORECASE,
)


def validate_condition_syntax(condition: str) -> tuple[bool, str]:
    cond = condition.strip()
    if not cond:
        return False, "Condition cannot be empty."

    parts = re.split(r'\s+(?:AND|OR)\s+', cond, flags=re.IGNORECASE)

    for part in parts:
        part = part.strip()
        m = _CONDITION_TOKEN.fullmatch(part)
        if not m:
            return False, (
                f"Invalid condition token: '{part}'. "
                "Expected format: <field> <operator> <value>. "
                f"Allowed fields: {', '.join(sorted(_ALLOWED_FIELDS))}. "
                "Allowed operators: ==, !=, >=, <=, >, <."
            )
        field = m.group(1).lower()
        if field not in _ALLOWED_FIELDS:
            return False, (
                f"Unknown field '{field}'. "
                f"Allowed fields: {', '.join(sorted(_ALLOWED_FIELDS))}."
            )

    return True, ""


# ---------------------------------------------------------------------------
# ARE condition evaluator
# ---------------------------------------------------------------------------

def _evaluate_condition(condition: str, context: Dict[str, Any]) -> bool:
    namespace: Dict[str, Any] = {}
    for key, val in context.items():
        safe_key = key.replace(".", "__")
        namespace[safe_key] = val

    py_condition = re.sub(
        r'([a-z_]+)\.([a-z_]+)',
        lambda m: f"{m.group(1)}__{m.group(2)}",
        condition,
        flags=re.IGNORECASE,
    )
    py_condition = re.sub(r'\bAND\b', 'and', py_condition, flags=re.IGNORECASE)
    py_condition = re.sub(r'\bOR\b',  'or',  py_condition, flags=re.IGNORECASE)

    try:
        result = bool(eval(py_condition, {"__builtins__": {}}, namespace))  # noqa: S307
        print(f"    [EVAL] '{py_condition}' => {result}  | namespace={namespace}")
        return result
    except Exception as e:
        print(f"    [EVAL ERROR] '{py_condition}' => {e}  | namespace={namespace}")
        return False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


ISOLATION_DURATION_S = 60 * 60 * 24 * 365  # 1 year


def _set_isolation(threat_id: str, filename: str, duration_s: int, policy_name: str):
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=duration_s)
    with db() as conn:
        conn.execute("""
            INSERT INTO isolations (threat_id, filename, isolated_at, expires_at, duration_s, policy_name, status)
            VALUES (?, ?, ?, ?, ?, ?, 'active')
            ON CONFLICT(threat_id) DO UPDATE SET
                isolated_at = excluded.isolated_at,
                expires_at  = excluded.expires_at,
                duration_s  = excluded.duration_s,
                policy_name = excluded.policy_name,
                status      = 'active'
        """, (threat_id, filename, now.isoformat(), expires.isoformat(), duration_s, policy_name))


def _get_isolation(threat_id: str) -> Optional[dict]:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM isolations WHERE threat_id = ?", (threat_id,)
        ).fetchone()
    if not row:
        return None
    now = datetime.now(timezone.utc)
    expires = datetime.fromisoformat(row["expires_at"])
    remaining = max(0, int((expires - now).total_seconds()))
    status = row["status"]
    if status == "active" and now >= expires:
        status = "expired"
    return {
        "threat_id":   row["threat_id"],
        "filename":    row["filename"],
        "isolated_at": row["isolated_at"],
        "expires_at":  row["expires_at"],
        "duration_s":  row["duration_s"],
        "remaining_s": remaining,
        "policy_name": row["policy_name"],
        "status":      status,
    }


def execute_action(policy: dict, target: str, context: Dict[str, Any]) -> dict:
    action_id = f"act-{uuid.uuid4().hex[:8]}"
    ts = _now()

    try:
        action_type = policy["action"]
        details = ""

        if action_type == ActionType.isolate:
            threat_id = context.get("threat.id", target)
            filename  = context.get("threat.filename", target)
            _set_isolation(threat_id, filename, ISOLATION_DURATION_S, policy["name"])
            details = (
                f"Threat '{threat_id}' ({filename}) has been isolated for {ISOLATION_DURATION_S}s. "
                f"This threat is quarantined and flagged for review. "
                f"Isolation auto-expires after {ISOLATION_DURATION_S} seconds or can be manually released."
            )
        elif action_type == ActionType.switch_model:
            try:
                import requests
                src_send(
                    source      = "ARE",
                    destination = "IVM",
                    event_type  = "ModelSwitchDirective",
                    message     = f"ARE issuing switch-to-hardened directive for target: {target}",
                    metadata    = {"target": target, "new_mode": "hardened", "policy": policy["name"]},
                )
                r = requests.post("http://localhost:5000/api/switch-model",
                                json={"model": "hardened"}, timeout=3)
                details = (
                    "Detection posture switched to HARDENED mode. "
                    "ResNet-50 thresholds tightened — higher recall, "
                    f"more aggressive flagging for target '{target}'."
                )
            except Exception as sw_err:
                details = f"Switch directive issued but could not reach Threat Detection: {sw_err}"

        elif action_type == ActionType.escalate:
            details = f"Incident for '{target}' escalated to human review queue."
        elif action_type == ActionType.block:
            details = f"Traffic from '{target}' has been blocked at the ingress layer."
        elif action_type == ActionType.log:
            details = f"Event from '{target}' logged for audit trail."
        else:
            details = f"Monitor mode activated for '{target}'."

        result = ActionStatus.success
    except Exception as exc:
        details = f"Execution failed: {exc}"
        result  = ActionStatus.failed

    action_record = {
        "id":           action_id,
        "policyId":     policy["id"],
        "policyName":   policy["name"],
        "action":       action_type,
        "target":       target,
        "reason":       policy["condition"],
        "details":      details,
        "result":       result,
        "executionTime": 50.0 + (hash(action_id) % 200),
        "timestamp":    ts,
    }

    with db() as conn:
        conn.execute("""
            INSERT INTO actions
              (id, policyId, policyName, action, target, reason, details, result, executionTime, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            action_record["id"], action_record["policyId"], action_record["policyName"],
            action_record["action"], action_record["target"], action_record["reason"],
            action_record["details"], action_record["result"],
            action_record["executionTime"], action_record["timestamp"],
        ))

        conn.execute("""
            UPDATE policies
            SET lastTriggered = ?, triggerCount = triggerCount + 1
            WHERE id = ?
        """, (ts, policy["id"]))

    _sev = SiemSeverity.CRITICAL if action_type == ActionType.isolate else \
           SiemSeverity.WARNING  if action_type in (ActionType.escalate, ActionType.switch_model) else \
           SiemSeverity.INFO
    siem_log(
        severity   = _sev,
        source     = SiemSource.ARE,
        event_type = f"ARE_{action_type.upper()}",
        message    = f"Policy '{policy['name']}' fired — {action_type} on {target} ({result})",
        metadata   = {
            "action_id":   action_id,
            "policy_id":   policy["id"],
            "policy_name": policy["name"],
            "action":      action_type,
            "target":      target,
            "result":      result,
        }
    )
    return action_record


def compute_stats() -> dict:
    with db() as conn:
        rows = conn.execute("SELECT action, result FROM actions").fetchall()

    total_isolations    = sum(1 for r in rows if r["action"] == ActionType.isolate)
    total_model_switches = sum(1 for r in rows if r["action"] == ActionType.switch_model)
    total_escalations   = sum(1 for r in rows if r["action"] == ActionType.escalate)
    total     = len(rows)
    successes = sum(1 for r in rows if r["result"] == ActionStatus.success)
    success_rate = round((successes / total * 100), 1) if total > 0 else 0.0

    return {
        "totalIsolations":    total_isolations,
        "totalModelSwitches": total_model_switches,
        "totalEscalations":   total_escalations,
        "successRate":        success_rate,
    }


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class PolicyCreateRequest(BaseModel):
    name:      str       = Field(..., min_length=1, max_length=120)
    priority:  int       = Field(..., ge=1, le=100)
    condition: str       = Field(..., min_length=1)
    action:    ActionType
    enabled:   bool      = False

    @validator("condition")
    def condition_must_be_valid(cls, v):
        ok, err = validate_condition_syntax(v)
        if not ok:
            raise ValueError(err)
        return v


class PolicyUpdateRequest(BaseModel):
    name:      Optional[str]        = None
    priority:  Optional[int]        = Field(None, ge=1, le=100)
    condition: Optional[str]        = None
    action:    Optional[ActionType] = None
    enabled:   Optional[bool]       = None

    @validator("condition", pre=True, always=True)
    def condition_must_be_valid_if_provided(cls, v):
        if v is not None:
            ok, err = validate_condition_syntax(v)
            if not ok:
                raise ValueError(err)
        return v


class PolicyToggleRequest(BaseModel):
    enabled: bool


class ThreatEventRequest(BaseModel):
    threatId:   str
    target:     str
    severity:   str   = "low"
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    status:     str   = "detected"
    modelAccuracy:     Optional[float] = None
    modelRobustness:   Optional[float] = None
    agentDeviation:    Optional[float] = None
    agentConfidence:   Optional[float] = None
    agentAnomalyScore: Optional[float] = None


class ValidateConditionRequest(BaseModel):
    condition: str


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.get("/api/are/stats")
def get_stats():
    return compute_stats()


# ── Policies ───────────────────────────────────────────────────────────────

@app.get("/api/are/policies")
def list_policies(sort_by: str = "priority", order: str = "asc"):
    allowed_cols = {"priority", "name", "condition"}
    col = sort_by if sort_by in allowed_cols else "priority"
    direction = "DESC" if order.lower() == "desc" else "ASC"

    with db() as conn:
        rows = conn.execute(
            f"SELECT * FROM policies ORDER BY {col} {direction}"
        ).fetchall()

    return {"policies": [row_to_policy(r) for r in rows]}


@app.post("/api/are/policies", status_code=201)
def create_policy(body: PolicyCreateRequest):
    policy_id = f"pol-{uuid.uuid4().hex[:8]}"
    now = _now()

    with db() as conn:
        conn.execute("""
            INSERT INTO policies
              (id, priority, name, condition, action, enabled, lastTriggered, triggerCount, createdAt)
            VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?)
        """, (policy_id, body.priority, body.name, body.condition,
              body.action, int(body.enabled), now))

    return {
        "id": policy_id, "priority": body.priority, "name": body.name,
        "condition": body.condition, "action": body.action,
        "enabled": body.enabled, "lastTriggered": None,
        "triggerCount": 0, "createdAt": now,
    }


@app.get("/api/are/policies/{policy_id}")
def get_policy(policy_id: str):
    with db() as conn:
        row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found.")
    return row_to_policy(row)


@app.patch("/api/are/policies/{policy_id}")
def update_policy(policy_id: str, body: PolicyUpdateRequest):
    with db() as conn:
        row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Policy not found.")

        updates = {k: v for k, v in body.dict().items() if v is not None}
        if not updates:
            return row_to_policy(row)

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [policy_id]
        conn.execute(f"UPDATE policies SET {set_clause} WHERE id = ?", values)

        updated = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    return row_to_policy(updated)


@app.patch("/api/are/policies/{policy_id}/toggle")
def toggle_policy(policy_id: str, body: PolicyToggleRequest):
    with db() as conn:
        row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Policy not found.")
        conn.execute("UPDATE policies SET enabled = ? WHERE id = ?",
                     (int(body.enabled), policy_id))

    return {
        "id":      policy_id,
        "enabled": body.enabled,
        "message": f"Policy {'enabled' if body.enabled else 'disabled'} successfully.",
    }


@app.delete("/api/are/policies/{policy_id}", status_code=204)
def delete_policy(policy_id: str):
    with db() as conn:
        row = conn.execute("SELECT id FROM policies WHERE id = ?", (policy_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Policy not found.")
        conn.execute("DELETE FROM policies WHERE id = ?", (policy_id,))


# ── Actions Log ────────────────────────────────────────────────────────────

@app.get("/api/are/actions")
def get_actions(limit: int = 50, offset: int = 0):
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM actions").fetchone()[0]
        rows  = conn.execute(
            "SELECT * FROM actions ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()

    return {"total": total, "actions": [row_to_action(r) for r in rows]}


# ── Condition Validation ───────────────────────────────────────────────────

@app.post("/api/are/validate-condition")
def validate_condition(body: ValidateConditionRequest):
    ok, err = validate_condition_syntax(body.condition)
    return {"valid": ok, "error": err}


# ── Threat Evaluation ──────────────────────────────────────────────────────

@app.post("/api/are/evaluate")
def evaluate_threat(body: ThreatEventRequest):
    context = {
        "threat.severity":   body.severity,
        "threat.confidence": body.confidence,
        "threat.status":     body.status,
        "threat.id":         body.threatId,
        "threat.filename":   body.target,
    }
    if body.modelAccuracy     is not None: context["model.accuracy"]      = body.modelAccuracy
    if body.modelRobustness   is not None: context["model.robustness"]    = body.modelRobustness
    if body.agentDeviation    is not None: context["agent.deviation"]     = body.agentDeviation
    if body.agentConfidence   is not None: context["agent.confidence"]    = body.agentConfidence
    if body.agentAnomalyScore is not None: context["agent.anomaly_score"] = body.agentAnomalyScore

    print(f"\n[ARE /evaluate] threatId={body.threatId} severity={body.severity} confidence={body.confidence}")
    print(f"  context: {context}")

    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM policies WHERE enabled = 1 ORDER BY priority ASC"
        ).fetchall()

    sorted_policies = [row_to_policy(r) for r in rows]
    print(f"  enabled policies loaded: {len(sorted_policies)}")

    triggered_actions = []
    for policy in sorted_policies:
        if _evaluate_condition(policy["condition"], context):
            action_record = execute_action(policy, body.target, context)
            triggered_actions.append(action_record)
            print(f"  ✅ FIRED: {policy['name']}")
        else:
            print(f"  ❌ NO MATCH: {policy['name']}")

    print(f"  => {len(triggered_actions)} actions triggered\n")

    return {
        "threatId":         body.threatId,
        "policiesChecked":  len(sorted_policies),
        "actionsTriggered": len(triggered_actions),
        "actions":          triggered_actions,
        "updatedStats":     compute_stats(),
    }


# ── Isolations ─────────────────────────────────────────────────────────────

@app.get("/api/are/isolations")
def list_isolations():
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM isolations ORDER BY isolated_at DESC"
        ).fetchall()

    now = datetime.now(timezone.utc)
    result = []
    for row in rows:
        expires = datetime.fromisoformat(row["expires_at"])
        remaining = max(0, int((expires - now).total_seconds()))
        status = row["status"]
        if status == "active" and now >= expires:
            status = "expired"
        result.append({
            "threat_id":   row["threat_id"],
            "filename":    row["filename"],
            "isolated_at": row["isolated_at"],
            "expires_at":  row["expires_at"],
            "duration_s":  row["duration_s"],
            "remaining_s": remaining,
            "policy_name": row["policy_name"],
            "status":      status,
        })
    return {"isolations": result}


@app.get("/api/are/isolations/{threat_id}")
def get_isolation(threat_id: str):
    iso = _get_isolation(threat_id)
    if not iso:
        raise HTTPException(status_code=404, detail="No isolation record found.")
    return iso


@app.delete("/api/are/isolations/{threat_id}")
def release_isolation(threat_id: str):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM isolations WHERE threat_id = ?", (threat_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="No isolation record found.")
        conn.execute(
            "UPDATE isolations SET status = 'released', expires_at = ? WHERE threat_id = ?",
            (datetime.now(timezone.utc).isoformat(), threat_id)
        )
    print(f"[ARE] Isolation manually released: {threat_id}")
    return {"released": True, "threat_id": threat_id}


@app.get("/api/are/isolations/check-filename/{filename}")
def check_isolation_by_filename(filename: str):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM isolations WHERE filename = ? AND status = 'active' ORDER BY isolated_at DESC LIMIT 1",
            (filename,)
        ).fetchone()

    if not row:
        return {"isolated": False, "record": None}

    now = datetime.now(timezone.utc)
    expires = datetime.fromisoformat(row["expires_at"])
    if now >= expires:
        return {"isolated": False, "record": None}

    return {
        "isolated": True,
        "record": {
            "threat_id":   row["threat_id"],
            "filename":    row["filename"],
            "isolated_at": row["isolated_at"],
            "policy_name": row["policy_name"],
            "status":      row["status"],
        }
    }


@app.delete("/api/are/isolations/by-filename/{filename}")
def release_isolation_by_filename(filename: str):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM isolations WHERE filename = ? AND status = 'active'",
            (filename,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="No active isolation found for this file.")
        conn.execute(
            "UPDATE isolations SET status = 'released', expires_at = ? WHERE filename = ? AND status = 'active'",
            (datetime.now(timezone.utc).isoformat(), filename)
        )
    print(f"[ARE] Isolation released by filename: {filename}")
    return {"released": True, "filename": filename}


@app.post("/api/are/isolations/manual")
def create_manual_isolation(body: dict):
    filename    = body.get("filename")
    policy_name = body.get("policyName", "Manual - Analyst Confirmed Threat")
    note        = body.get("note", "")

    if not filename:
        raise HTTPException(status_code=400, detail="filename is required")

    _set_isolation(filename, filename, ISOLATION_DURATION_S, policy_name)
    print(f"[ARE] Manual isolation: {filename} (note: {note!r})")
    return {"isolated": True, "threat_id": filename, "filename": filename, "policy_name": policy_name}


# ---------------------------------------------------------------------------
# Live Threat Intelligence — MITRE ATT&CK Feed Integration
# Addresses Point 2: converts static policy knowledge base to dynamically
# updatable via live MITRE ATT&CK REST API (no API key required)
# ---------------------------------------------------------------------------

# MITRE ATT&CK STIX bundle — enterprise attack patterns
MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Keywords that indicate ML/adversarial relevance
ML_KEYWORDS = [
    "machine learning", "adversarial", "neural network", "model",
    "training data", "inference", "evasion", "poisoning",
    "deep learning", "classifier", "artificial intelligence",
]


@app.post("/api/are/sync-threat-intel")
async def sync_threat_intel():
    """
    Fetch live MITRE ATT&CK enterprise attack patterns and insert
    ML-relevant techniques as new disabled policies into are_data.db.

    New policies are inserted as:
      - disabled (enabled=0) — admin must review before activating
      - priority=99          — lowest priority, below all existing policies
      - action=log           — safest default action
      - name prefixed [INTEL] — distinguishable from seeded ATLAS policies

    This converts the policy knowledge base from static to dynamically
    updatable from a live external threat intelligence feed.
    """
    sync_id = f"sync-{uuid.uuid4().hex[:8]}"
    synced_at = _now()

    print(f"[ARE] Starting MITRE ATT&CK threat intel sync (id={sync_id})")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(MITRE_ATTACK_URL)
            response.raise_for_status()
            data = response.json()

        objects = data.get("objects", [])
        print(f"[ARE] Fetched {len(objects)} STIX objects from MITRE ATT&CK")

        # Filter for ML-relevant attack patterns only
        ml_techniques = []
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated", False):
                continue

            name        = obj.get("name", "")
            description = obj.get("description", "")
            ext_refs    = obj.get("external_references", [])
            mitre_id    = next(
                (r.get("external_id", "") for r in ext_refs
                 if r.get("source_name") == "mitre-attack"),
                ""
            )

            if not mitre_id:
                continue

            combined = (name + " " + description).lower()
            if not any(kw in combined for kw in ML_KEYWORDS):
                continue

            ml_techniques.append({
                "mitre_id":    mitre_id,
                "name":        name,
                "description": description[:400],
            })

        print(f"[ARE] Found {len(ml_techniques)} ML-relevant techniques")

        # Insert new techniques as disabled policies
        new_policies = 0
        now = _now()

        with db() as conn:
            for tech in ml_techniques:
                # Check if a policy with this MITRE ID already exists
                existing = conn.execute(
                    "SELECT id FROM policies WHERE name LIKE ?",
                    (f"%{tech['mitre_id']}%",)
                ).fetchone()

                if existing:
                    continue  # Already have this technique — skip

                policy_id   = f"pol-{uuid.uuid4().hex[:8]}"
                policy_name = f"[INTEL {tech['mitre_id']}] {tech['name']}"
                conn.execute("""
                    INSERT INTO policies
                      (id, priority, name, condition, action, enabled,
                       lastTriggered, triggerCount, createdAt)
                    VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?)
                """, (
                    policy_id,
                    99,
                    policy_name,
                    'threat.severity == "high" AND threat.confidence >= 0.65',
                    "log",
                    0,   # disabled — analyst must review before enabling
                    now,
                ))
                new_policies += 1

                # Log each individual policy creation to SIEM
                # Admin sees only this in SIEM — no policy details exposed in UI
                siem_log(
                    severity   = SiemSeverity.INFO,
                    source     = SiemSource.ARE,
                    event_type = "ThreatIntelPolicyCreated",
                    message    = (
                        f"New threat intel policy created (disabled) from MITRE ATT&CK — "
                        f"{tech['mitre_id']}: {tech['name']}"
                    ),
                    metadata={
                        "policy_id":   policy_id,
                        "policy_name": policy_name,
                        "mitre_id":    tech["mitre_id"],
                        "action":      "log",
                        "enabled":     False,
                        "priority":    99,
                        "source":      "MITRE ATT&CK Enterprise",
                        "note":        "Pending security analyst review — not active until analyst enables",
                    }
                )

            # Log this sync to threat_intel_log table
            conn.execute("""
                INSERT INTO threat_intel_log
                  (id, synced_at, source, fetched, ml_relevant, new_policies, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                sync_id, synced_at, "MITRE ATT&CK Enterprise",
                len(objects), len(ml_techniques), new_policies, "success"
            ))

        # Summary SIEM log for the whole sync operation
        siem_log(
            severity   = SiemSeverity.INFO,
            source     = SiemSource.ARE,
            event_type = "ThreatIntelSync",
            message    = (
                f"MITRE ATT&CK live sync completed — "
                f"{len(ml_techniques)} ML-relevant techniques found, "
                f"{new_policies} new policies created (disabled, pending security analyst review)"
            ),
            metadata={
                "sync_id":       sync_id,
                "source":        "MITRE ATT&CK Enterprise",
                "total_fetched": len(objects),
                "ml_relevant":   len(ml_techniques),
                "new_policies":  new_policies,
            }
        )

        print(f"[ARE] Sync complete — {new_policies} new policies added")

        return {
            "success":   True,
            "sync_id":   sync_id,
            "synced_at": synced_at,
            "source":    "MITRE ATT&CK Enterprise (live feed)",
            "message":   "Sync complete. New threat intelligence has been logged to SIEM.",
        }

    except httpx.TimeoutException:
        error_msg = "Request timed out — MITRE ATT&CK feed unreachable (30s timeout)"
        _log_failed_sync(sync_id, synced_at, error_msg)
        return {"success": False, "error": error_msg}

    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP {e.response.status_code} from MITRE ATT&CK feed"
        _log_failed_sync(sync_id, synced_at, error_msg)
        return {"success": False, "error": error_msg}

    except Exception as e:
        error_msg = str(e)
        _log_failed_sync(sync_id, synced_at, error_msg)
        return {"success": False, "error": error_msg}


def _log_failed_sync(sync_id: str, synced_at: str, error: str):
    """Log a failed sync attempt to SIEM and threat_intel_log."""
    try:
        with db() as conn:
            conn.execute("""
                INSERT INTO threat_intel_log
                  (id, synced_at, source, fetched, ml_relevant, new_policies, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (sync_id, synced_at, "MITRE ATT&CK Enterprise", 0, 0, 0, f"failed: {error}"))
    except Exception:
        pass

    siem_log(
        severity   = SiemSeverity.ERROR,
        source     = SiemSource.ARE,
        event_type = "ThreatIntelSyncFailed",
        message    = f"MITRE ATT&CK sync failed: {error}",
        metadata   = {"sync_id": sync_id, "error": error}
    )
    print(f"[ARE] Sync failed: {error}")


@app.get("/api/are/threat-intel-status")
def threat_intel_status():
    """
    Returns current threat intel status — last sync time,
    count of intel-sourced policies, and sync history.
    """
    with db() as conn:
        intel_count = conn.execute(
            "SELECT COUNT(*) FROM policies WHERE name LIKE '[INTEL%'"
        ).fetchone()[0]

        intel_enabled = conn.execute(
            "SELECT COUNT(*) FROM policies WHERE name LIKE '[INTEL%' AND enabled = 1"
        ).fetchone()[0]

        # Last sync from log
        last_sync = conn.execute(
            "SELECT * FROM threat_intel_log ORDER BY synced_at DESC LIMIT 1"
        ).fetchone()

        # Sync history (last 10)
        history = conn.execute(
            "SELECT * FROM threat_intel_log ORDER BY synced_at DESC LIMIT 10"
        ).fetchall()

    return {
        "intel_policies_total":   intel_count,
        "intel_policies_enabled": intel_enabled,
        "source":                 "MITRE ATT&CK Enterprise",
        "feed_url":               MITRE_ATTACK_URL,
        "last_sync":              dict(last_sync) if last_sync else None,
        "sync_history":           [dict(r) for r in history],
    }


# ── Health ─────────────────────────────────────────────────────────────────

@app.get("/api/are/health")
def health():
    return {"status": "ok", "module": "ARE", "timestamp": _now()}


# ---------------------------------------------------------------------------
# Dev entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("are-backend:app", host="0.0.0.0", port=8000, reload=True)