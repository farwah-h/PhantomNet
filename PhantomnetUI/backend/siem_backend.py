"""
PhantomNet++ SIEM Backend — siem_backend.py
Port: 8003

Receives log events from all backends (IVM, ARE, DAG, XAI, AUTH),
applies SHA-3 hashing for log integrity, indexes to local Elasticsearch,
and serves /api/siem/* endpoints to the frontend.

Replaces Logstash in the ELK stack.
siem-logs.tsx frontend replaces Kibana.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

PKT = timezone(timedelta(hours=5))  # Pakistan Standard Time (UTC+5)
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from elasticsearch import Elasticsearch, NotFoundError

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="PhantomNet++ SIEM API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Elasticsearch connection
# ---------------------------------------------------------------------------

ES_HOST  = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX = "phantomnet-siem"

es = Elasticsearch(ES_HOST)

def ensure_index():
    """Create the SIEM index with correct mappings if it doesn't exist."""
    if es.indices.exists(index=ES_INDEX):
        print(f"[SIEM] Index '{ES_INDEX}' already exists.")
        return

    mappings = {
        "mappings": {
            "properties": {
                "log_id":     {"type": "keyword"},
                "timestamp":  {"type": "date"},
                "severity":   {"type": "keyword"},   # Info | Warning | Error | Critical
                "source":     {"type": "keyword"},   # IVM | ARE | DAG | XAI | AUTH | LSE
                "event_type": {"type": "keyword"},   # ThreatDetected | PolicyFired | etc.
                "message":    {"type": "text"},      # full-text searchable
                "metadata":   {"type": "object", "dynamic": True},
                "sha3_hash":  {"type": "keyword"},   # integrity hash
            }
        },
        "settings": {
            "number_of_shards":   1,
            "number_of_replicas": 0,   # single-node dev setup
        }
    }

    es.indices.create(index=ES_INDEX, body=mappings)
    print(f"[SIEM] Index '{ES_INDEX}' created.")

try:
    ensure_index()
    print(f"[SIEM] Connected to Elasticsearch at {ES_HOST}")
except Exception as e:
    print(f"[SIEM] WARNING: Elasticsearch not reachable — {e}")
    print(f"[SIEM] Start Elasticsearch first, then restart this backend.")

# ---------------------------------------------------------------------------
# SHA-3 log integrity
# ---------------------------------------------------------------------------

def sha3_hash(log_id: str, timestamp: str, severity: str,
              source: str, event_type: str, message: str) -> str:
    """
    Compute SHA3-256 hash over the immutable log fields.
    This proves a log entry was not tampered with after writing.
    """
    payload = f"{log_id}|{timestamp}|{severity}|{source}|{event_type}|{message}"
    return hashlib.sha3_256(payload.encode()).hexdigest()

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class LogEntry(BaseModel):
    severity:   str            # Info | Warning | Error | Critical
    source:     str            # IVM | ARE | DAG | XAI | AUTH | LSE
    event_type: str            # ThreatDetected | PolicyFired | SimulationRun | etc.
    message:    str
    metadata:   Optional[Dict[str, Any]] = {}

class LogResponse(BaseModel):
    log_id:    str
    timestamp: str
    sha3_hash: str
    indexed:   bool

# ---------------------------------------------------------------------------
# Core: write a log
# ---------------------------------------------------------------------------

def write_log(entry: LogEntry) -> dict:
    """Hash, timestamp, and index a single log entry to Elasticsearch."""
    log_id    = f"log-{uuid.uuid4().hex[:12]}"
    timestamp = datetime.now(PKT).isoformat()

    # SHA-3 integrity hash over immutable fields
    integrity_hash = sha3_hash(
        log_id, timestamp,
        entry.severity, entry.source,
        entry.event_type, entry.message,
    )

    doc = {
        "log_id":     log_id,
        "timestamp":  timestamp,
        "severity":   entry.severity,
        "source":     entry.source,
        "event_type": entry.event_type,
        "message":    entry.message,
        "metadata":   entry.metadata or {},
        "sha3_hash":  integrity_hash,
    }

    try:
        es.index(index=ES_INDEX, id=log_id, document=doc)
        indexed = True
    except Exception as e:
        print(f"[SIEM] ES index error: {e}")
        indexed = False

    return {**doc, "indexed": indexed}

# ---------------------------------------------------------------------------
# API: receive logs from backends
# ---------------------------------------------------------------------------

@app.post("/api/siem/log")
def receive_log(entry: LogEntry):
    """
    Called by all other backends to submit a log event.
    Applies SHA-3 hash and indexes to Elasticsearch.
    """
    result = write_log(entry)
    print(f"[SIEM] [{result['severity'].upper()}] [{result['source']}] {result['message']}")
    return result


@app.post("/api/siem/log/batch")
def receive_log_batch(entries: List[LogEntry]):
    """Batch ingest — accepts multiple log entries in one call."""
    results = [write_log(e) for e in entries]
    return {"count": len(results), "logs": results}

# ---------------------------------------------------------------------------
# API: query logs for frontend
# ---------------------------------------------------------------------------

@app.get("/api/siem/logs")
def get_logs(
    severity:   Optional[str] = Query(None, description="Filter by severity"),
    source:     Optional[str] = Query(None, description="Filter by source module"),
    search:     Optional[str] = Query(None, description="Full-text search on message"),
    limit:      int           = Query(100,  ge=1, le=1000),
    offset:     int           = Query(0,    ge=0),
):
    """
    Query logs from Elasticsearch with optional filters.
    Used by siem-logs.tsx for the log stream.
    """
    must_clauses   = []
    filter_clauses = []

    # Severity filter
    if severity and severity.lower() != "all":
        filter_clauses.append({"term": {"severity": severity.capitalize()}})

    # Source module filter
    if source and source.lower() != "all":
        filter_clauses.append({"term": {"source": source.upper()}})

    # Full-text search on message field
    if search and search.strip():
        must_clauses.append({
            "match": {
                "message": {
                    "query":    search.strip(),
                    "operator": "and",
                    "fuzziness": "AUTO",
                }
            }
        })

    query = {
        "bool": {
            "must":   must_clauses   if must_clauses   else [{"match_all": {}}],
            "filter": filter_clauses,
        }
    }

    try:
        resp = es.search(
            index=ES_INDEX,
            query=query,
            sort=[{"timestamp": {"order": "desc"}}],
            from_=offset,
            size=limit,
        )

        hits  = resp["hits"]["hits"]
        total = resp["hits"]["total"]["value"]
        logs  = [h["_source"] for h in hits]

        return {"total": total, "offset": offset, "limit": limit, "logs": logs}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Elasticsearch error: {e}")


@app.get("/api/siem/stats")
def get_stats():
    """
    Header metric counts for siem-logs.tsx:
    Total, Critical, Error, Warning, Info
    """
    try:
        agg_query = {
            "size": 0,
            "aggs": {
                "by_severity": {
                    "terms": {"field": "severity", "size": 10}
                }
            }
        }
        resp     = es.search(index=ES_INDEX, aggregations=agg_query["aggs"], size=0)
        total    = resp["hits"]["total"]["value"]
        buckets  = resp["aggregations"]["by_severity"]["buckets"]
        counts   = {b["key"]: b["doc_count"] for b in buckets}

        return {
            "total":    total,
            "critical": counts.get("Critical", 0),
            "error":    counts.get("Error",    0),
            "warning":  counts.get("Warning",  0),
            "info":     counts.get("Info",     0),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Elasticsearch error: {e}")


@app.get("/api/siem/log/{log_id}/verify")
def verify_log_integrity(log_id: str):
    """
    Verify SHA-3 hash of a specific log entry.
    Returns whether the log has been tampered with.
    """
    try:
        doc  = es.get(index=ES_INDEX, id=log_id)["_source"]
        expected = sha3_hash(
            doc["log_id"], doc["timestamp"],
            doc["severity"], doc["source"],
            doc["event_type"], doc["message"],
        )
        valid = expected == doc.get("sha3_hash", "")
        return {
            "log_id":   log_id,
            "valid":    valid,
            "stored":   doc.get("sha3_hash"),
            "computed": expected,
        }
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Log entry not found.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/siem/logs/clear")
def clear_logs():
    """Dev only — wipe the SIEM index and recreate it."""
    try:
        es.indices.delete(index=ES_INDEX)
        ensure_index()
        return {"cleared": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/siem/health")
def health():
    try:
        ping = es.ping()
        info = es.info() if ping else {}
        return {
            "status":          "ok" if ping else "es_unreachable",
            "elasticsearch":   ping,
            "index":           ES_INDEX,
            "es_version":      info.get("version", {}).get("number", "unknown") if ping else None,
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ---------------------------------------------------------------------------
# Dev entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("siem_backend:app", host="0.0.0.0", port=8003, reload=True)