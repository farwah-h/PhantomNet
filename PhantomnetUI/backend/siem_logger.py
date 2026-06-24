"""
siem_logger.py — shared SIEM logging helper (updated with SRC source)
Import this in every backend to send log events to siem_backend.py

Usage:
    from siem_logger import siem_log, SiemSeverity, SiemSource

    siem_log(
        severity   = SiemSeverity.CRITICAL,
        source     = SiemSource.IVM,
        event_type = "ThreatDetected",
        message    = f"Adversarial patch detected on {filename}",
        metadata   = {"threat_id": threat_id, "confidence": 0.87},
    )
"""

import os
import requests
from typing import Any, Dict, Optional

SIEM_URL = os.getenv("SIEM_URL", "http://localhost:8003/api/siem/log")
TIMEOUT  = 2.0   # never block a backend for more than 2s


class SiemSeverity:
    INFO     = "Info"
    WARNING  = "Warning"
    ERROR    = "Error"
    CRITICAL = "Critical"


class SiemSource:
    IVM  = "IVM"    # Intelligent Vision Module (threat detection)
    ARE  = "ARE"    # Autonomous Response Engine
    DAG  = "DAG"    # Dynamic Attack Generator (simulation)
    XAI  = "XAI"   # Explainability Engine
    AUTH = "AUTH"   # Authentication backend
    LSE  = "LSE"    # SIEM itself
    SRC  = "SRC"    # Secure Response & Coordination


def siem_log(
    severity:   str,
    source:     str,
    event_type: str,
    message:    str,
    metadata:   Optional[Dict[str, Any]] = None,
) -> None:
    """
    Fire-and-forget log to SIEM backend.
    Never raises — a SIEM failure must never break the calling backend.
    """
    try:
        requests.post(
            SIEM_URL,
            json={
                "severity":   severity,
                "source":     source,
                "event_type": event_type,
                "message":    message,
                "metadata":   metadata or {},
            },
            timeout=TIMEOUT,
        )
    except Exception:
        pass   # SIEM is best-effort — silent failure is intentional