"""
src_client.py — PhantomNet++ SRC communication helper
======================================================
Drop this file next to your other backends.
Import it anywhere you need to send a message from one module to another.

Usage (replaces a raw requests.post):
--------------------------------------
    from src_client import src_send

    # OLD (unencrypted, unlogged):
    requests.post("http://localhost:8000/api/are/evaluate", json=payload)

    # NEW (encrypted through SRC, auto-logged with signature):
    src_send(
        source      = "IVM",
        destination = "ARE",
        event_type  = "ThreatEscalation",
        message     = f"Adversarial threat {threat_id} detected — sending to ARE",
        metadata    = payload,
    )
    # Then still call ARE directly — SRC logs the intent, the actual
    # call still goes to ARE. This is correct for our architecture.

How it fits into the system:
------------------------------
SRC is a SECURITY LAYER, not a message broker/proxy.
It does not replace the actual API calls — it sits alongside them:

    Step 1: src_send()  → SRC encrypts + logs the event
    Step 2: requests.post() → the actual module call happens as before

This way:
  - Every inter-module event is encrypted and signed in the audit trail
  - If SRC is down, modules still work (fire-and-forget, like siem_log)
  - No refactoring of your existing endpoint logic needed

Never raises — SRC failure must never break a module, same philosophy as siem_logger.
"""

import os
import json
import requests
from typing import Any, Dict, Optional

SRC_URL = os.getenv("SRC_URL", "http://localhost:8006/api/src/send")
TIMEOUT = 2.0   # never block a backend for more than 2 seconds


def src_send(
    source:      str,
    destination: str,
    event_type:  str,
    message:     str,
    metadata:    Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Sends an inter-module communication event through SRC.

    What happens inside SRC when this is called:
      1. Rate limit check for the source module
      2. AES-256-GCM encryption of the message + metadata payload
      3. SHA3-256 hash of the payload computed
      4. HMAC-SHA3-256 signature generated for the full log record
      5. Signed entry written to the audit log database

    Returns the SRC response (log_id, encrypted payload, etc.)
    or None if SRC is unreachable (non-blocking).
    """
    try:
        response = requests.post(
            SRC_URL,
            json={
                "source":      source,
                "destination": destination,
                "event_type":  event_type,
                "message":     message,
                "metadata":    metadata or {},
            },
            timeout=TIMEOUT,
        )
        if response.status_code == 200:
            return response.json()
        else:
            # Rate limited or bad request — log it but don't crash
            print(f"[SRC] Warning: {source}→{destination} rejected — {response.status_code}: {response.text[:100]}")
            return None
    except Exception as e:
        # SRC is down — modules continue working, just without SRC logging
        print(f"[SRC] Unreachable — {source}→{destination} event not logged: {e}")
        return None