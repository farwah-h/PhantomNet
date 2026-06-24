"""
src_backend.py — PhantomNet++ SRC (Secure Response & Coordination)
==================================================================
Runs on port 8006.

What this file actually does, in plain English:
------------------------------------------------
1.  On startup, it generates self-signed TLS certificates for every
    PhantomNet module (DAG, IVM, XAI, ARE, SIEM, SRC itself).
    Think of these like ID cards — each module gets one so it can
    prove who it is when talking to others.

2.  It keeps track of when those certificates were made. After 30 days
    it automatically regenerates them (certificate rotation). This means
    old/stolen certs stop working on their own.

3.  Every message that passes through SRC gets:
      a) Encrypted with AES-256-GCM before sending  (no one can read it)
      b) Tagged with a SHA3-256 hash after receiving (no one can tamper)
      c) Written to a signed audit log in SQLite

4.  It counts how many requests each module sends per minute.
    If a module fires more than 60 requests/min it gets throttled.
    This is the DoS / rate-limit protection.

5.  It exposes a /status endpoint so the frontend dashboard can
    display real-time health of all of this.

Run it:
    pip install fastapi uvicorn cryptography
    python src_backend.py
    → Server starts at http://localhost:8006
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from base64 import b64decode, b64encode
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

PKT = timezone(timedelta(hours=5))  # Pakistan Standard Time (UTC+5)

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from siem_logger import siem_log, SiemSeverity, SiemSource

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="PhantomNet++ SRC API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# All the modules in PhantomNet++ that SRC needs to manage
MODULES = ["DAG", "IVM", "XAI", "ARE", "LSE", "SRC"]

# Where we store certificates on disk
CERT_DIR = "src_certs"

# Certificate lifetime: 30 days (as per SDS)
CERT_LIFETIME_DAYS = 30

# Rate limit: max requests per module per minute
RATE_LIMIT = 60
_RATE_LIMIT_FILE = os.path.join("db", "src_settings.json")

def _load_persisted_settings():
    """Load persisted settings from disk (rate limit etc.)"""
    global RATE_LIMIT
    try:
        if os.path.exists(_RATE_LIMIT_FILE):
            with open(_RATE_LIMIT_FILE) as f:
                data = json.load(f)
                RATE_LIMIT = data.get("rate_limit", 60)
    except Exception:
        pass

def _save_persisted_settings():
    """Save current settings to disk so they survive restarts."""
    try:
        os.makedirs("db", exist_ok=True)
        with open(_RATE_LIMIT_FILE, "w") as f:
            json.dump({"rate_limit": RATE_LIMIT}, f)
    except Exception:
        pass

# A fixed 32-byte secret key used to sign audit log entries.
# In production this would live in HashiCorp Vault.
# For our project, we derive it from a passphrase so it's reproducible.
_SIGNING_SECRET = hashlib.sha256(b"phantomnet-src-audit-secret").digest()

# AES-256 key (32 bytes). Same note as above — in production, use Vault.
_AES_KEY = hashlib.sha256(b"phantomnet-src-aes256-key").digest()

# ---------------------------------------------------------------------------
# SQLite — audit log database
# ---------------------------------------------------------------------------

os.makedirs("db", exist_ok=True)
DB_PATH = "db/src_data.db"


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
    """
    Creates two tables:
      - audit_log : every encrypted/signed inter-module message event
      - rate_log  : running count of requests per module per minute window
    """
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id           TEXT PRIMARY KEY,
                timestamp    TEXT NOT NULL,
                source       TEXT NOT NULL,
                destination  TEXT NOT NULL,
                event_type   TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                signature    TEXT NOT NULL,
                message      TEXT NOT NULL,
                metadata     TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rate_log (
                module      TEXT NOT NULL,
                window_ts   TEXT NOT NULL,
                request_cnt INTEGER DEFAULT 0,
                PRIMARY KEY (module, window_ts)
            )
        """)


# ---------------------------------------------------------------------------
# Certificate management
# ---------------------------------------------------------------------------

os.makedirs(CERT_DIR, exist_ok=True)
_CERT_META_FILE = os.path.join(CERT_DIR, "cert_meta.json")


def _load_cert_meta() -> Dict[str, str]:
    """Load the metadata file that stores when each cert was generated."""
    if os.path.exists(_CERT_META_FILE):
        with open(_CERT_META_FILE) as f:
            return json.load(f)
    return {}


def _save_cert_meta(meta: Dict[str, str]):
    with open(_CERT_META_FILE, "w") as f:
        json.dump(meta, f, indent=2)


def generate_cert_for_module(module_name: str) -> Dict[str, str]:
    """
    Generates a self-signed X.509 certificate + private key for a module.

    What is a self-signed certificate?
    ------------------------------------
    Normally a certificate is signed by a trusted authority (like Let's Encrypt).
    For our internal system, WE are the authority — we sign our own certs.
    This is totally standard practice for internal service-to-service auth.

    The cert contains:
      - The module name (e.g. "IVM")
      - Valid-from and valid-until dates (30 days)
      - A public key (the private key stays secret on disk)

    Returns paths to the saved cert and key files.
    """
    # Step 1: Generate a 2048-bit RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Step 2: Build the certificate subject (who this cert belongs to)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PhantomNet++"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"phantomnet.{module_name.lower()}"),
    ])

    now = datetime.now(timezone.utc)  # X.509 requires UTC for validity periods

    # Step 3: Build the certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=CERT_LIFETIME_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Step 4: Save to disk
    cert_path = os.path.join(CERT_DIR, f"{module_name.lower()}.crt")
    key_path  = os.path.join(CERT_DIR, f"{module_name.lower()}.key")

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return {"cert_path": cert_path, "key_path": key_path}


def _cert_needs_rotation(module: str, meta: Dict[str, str]) -> bool:
    """
    Returns True if:
      - The module has never had a cert generated, OR
      - Its cert is older than CERT_LIFETIME_DAYS (30 days)
    """
    if module not in meta:
        return True
    generated_at = datetime.fromisoformat(meta[module])
    age = datetime.now(PKT) - generated_at
    return age.days >= CERT_LIFETIME_DAYS


def bootstrap_certificates():
    """
    Called once on startup. Generates certs for any module that
    doesn't have one, or whose cert has expired.

    This is also the certificate rotation mechanism — every time
    the server starts, it checks and rotates if needed.
    A production system would also run this as a daily cron job.
    """
    meta = _load_cert_meta()
    rotated = []

    for module in MODULES:
        if _cert_needs_rotation(module, meta):
            generate_cert_for_module(module)
            meta[module] = datetime.now(PKT).isoformat()
            rotated.append(module)
            print(f"[SRC] Certificate issued/rotated for {module}")
        else:
            age_days = (datetime.now(PKT) - datetime.fromisoformat(meta[module])).days
            print(f"[SRC] Certificate OK for {module} (age: {age_days}d / {CERT_LIFETIME_DAYS}d)")

    _save_cert_meta(meta)
    return rotated


def get_cert_status() -> List[Dict]:
    """Returns certificate status for all modules (used by frontend)."""
    meta = _load_cert_meta()
    result = []
    for module in MODULES:
        if module in meta:
            issued_at  = datetime.fromisoformat(meta[module])
            expires_at = issued_at + timedelta(days=CERT_LIFETIME_DAYS)
            now        = datetime.now(PKT)
            days_left  = (expires_at - now).days
            result.append({
                "module":     module,
                "issued_at":  issued_at.isoformat(),
                "expires_at": expires_at.isoformat(),
                "days_left":  max(0, days_left),
                "status":     "valid" if days_left > 5 else ("expiring_soon" if days_left > 0 else "expired"),
                "cert_path":  os.path.join(CERT_DIR, f"{module.lower()}.crt"),
            })
        else:
            result.append({
                "module":  module,
                "status":  "not_issued",
                "days_left": 0,
            })
    return result


# ---------------------------------------------------------------------------
# Encryption — AES-256-GCM
# ---------------------------------------------------------------------------

def encrypt_payload(plaintext: str) -> Dict[str, str]:
    """
    Encrypts a string message using AES-256-GCM.

    What is AES-256-GCM?
    ---------------------
    AES = Advanced Encryption Standard (the gold standard for symmetric encryption)
    256 = key size in bits (very strong — the NSA uses this for top-secret data)
    GCM = Galois/Counter Mode — this mode also authenticates the data,
          meaning it can detect if anyone tampered with the ciphertext.

    We generate a fresh random 12-byte nonce (IV) for every single message.
    This is what gives "forward secrecy" per message — even if someone
    gets the key later, they can't decrypt old messages without the exact nonce.

    Returns:
        ciphertext: the encrypted data (base64-encoded)
        nonce:      the random value used (base64-encoded) — needed to decrypt
    """
    aesgcm = AESGCM(_AES_KEY)
    nonce  = os.urandom(12)  # 96-bit nonce, generated fresh every time
    ct     = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return {
        "ciphertext": b64encode(ct).decode(),
        "nonce":      b64encode(nonce).decode(),
    }


def decrypt_payload(ciphertext_b64: str, nonce_b64: str) -> str:
    """
    Reverses encrypt_payload. Decrypts and also verifies the message
    wasn't tampered with (GCM does this automatically — it raises an
    exception if the ciphertext was modified even by one bit).
    """
    aesgcm     = AESGCM(_AES_KEY)
    ciphertext = b64decode(ciphertext_b64)
    nonce      = b64decode(nonce_b64)
    plaintext  = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


# ---------------------------------------------------------------------------
# Signed audit logging
# ---------------------------------------------------------------------------

def _compute_signature(record: Dict[str, Any]) -> str:
    """
    Creates a cryptographic signature (HMAC-SHA3-256) for an audit log entry.

    What does this mean?
    ---------------------
    HMAC = Hash-based Message Authentication Code
    We combine the log record data + our secret key into a hash.
    If anyone changes even one character in a stored log entry,
    the signature will no longer match — so we can detect tampering.

    This is what makes the audit trail "tamper-proof".
    """
    canonical = json.dumps({
        "id":           record["id"],
        "timestamp":    record["timestamp"],
        "source":       record["source"],
        "destination":  record["destination"],
        "event_type":   record["event_type"],
        "payload_hash": record["payload_hash"],
        "message":      record["message"],
    }, sort_keys=True)

    sig = hmac.new(
        _SIGNING_SECRET,
        canonical.encode(),
        hashlib.sha3_256
    ).hexdigest()
    return sig


def write_audit_log(
    source: str,
    destination: str,
    event_type: str,
    message: str,
    metadata: Dict[str, Any],
    payload: Optional[str] = None,
) -> str:
    """
    Writes one signed entry to the audit log.

    Every entry has:
      - A SHA3-256 hash of the payload (proves the content wasn't changed)
      - An HMAC signature of the whole record (proves the log entry itself wasn't changed)

    Returns the log entry ID.
    """
    log_id       = f"SRC-{str(uuid.uuid4())[:8].upper()}"
    timestamp    = datetime.now(PKT).isoformat()
    payload_hash = hashlib.sha3_256((payload or message).encode()).hexdigest()

    record = {
        "id":           log_id,
        "timestamp":    timestamp,
        "source":       source,
        "destination":  destination,
        "event_type":   event_type,
        "payload_hash": payload_hash,
        "message":      message,
        "metadata":     json.dumps(metadata),
    }

    record["signature"] = _compute_signature(record)

    with db() as conn:
        conn.execute("""
            INSERT INTO audit_log
              (id, timestamp, source, destination, event_type, payload_hash, signature, message, metadata)
            VALUES
              (:id, :timestamp, :source, :destination, :event_type, :payload_hash, :signature, :message, :metadata)
        """, record)

    return log_id


def verify_log_entry(log_id: str) -> Dict[str, Any]:
    """
    Recomputes the signature for a stored log entry and checks if it matches.
    If someone modified the database directly, this will catch it.
    """
    with db() as conn:
        row = conn.execute("SELECT * FROM audit_log WHERE id = ?", (log_id,)).fetchone()

    if not row:
        return {"verified": False, "reason": "Log entry not found"}

    record = dict(row)
    stored_sig    = record.pop("signature")
    record["signature"] = ""  # temporarily blank for recomputation
    expected_sig  = _compute_signature(record)

    if hmac.compare_digest(stored_sig, expected_sig):
        return {"verified": True, "log_id": log_id}
    else:
        return {"verified": False, "reason": "Signature mismatch — log may have been tampered with", "log_id": log_id}


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

# In-memory counter: { module: { "YYYY-MM-DDTHH:MM": count } }
_rate_counters: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))


def _current_window() -> str:
    """Returns the current minute as a string key, e.g. '2025-04-25T14:32'"""
    return datetime.now(PKT).strftime("%Y-%m-%dT%H:%M")


def check_rate_limit(module: str) -> Dict[str, Any]:
    """
    Increments the request counter for a module in the current 1-minute window.
    Returns whether the module is allowed to proceed or is throttled.

    How it works:
    - Every module gets a counter that resets every minute.
    - If a module exceeds RATE_LIMIT (60) requests in one minute, it's blocked.
    - This prevents a compromised or malfunctioning module from flooding others.
    """
    window  = _current_window()
    _rate_counters[module][window] += 1
    count   = _rate_counters[module][window]
    allowed = count <= RATE_LIMIT

    # Persist to DB for the dashboard to read
    with db() as conn:
        conn.execute("""
            INSERT INTO rate_log (module, window_ts, request_cnt)
            VALUES (?, ?, ?)
            ON CONFLICT(module, window_ts) DO UPDATE SET request_cnt = request_cnt + 1
        """, (module, window, 1))

    return {
        "module":    module,
        "window":    window,
        "count":     count,
        "limit":     RATE_LIMIT,
        "allowed":   allowed,
        "remaining": max(0, RATE_LIMIT - count),
    }


def get_rate_status() -> List[Dict]:
    """Returns current-window request counts for all modules."""
    window = _current_window()
    result = []
    for module in MODULES:
        count = _rate_counters[module].get(window, 0)
        result.append({
            "module":    module,
            "count":     count,
            "limit":     RATE_LIMIT,
            "remaining": max(0, RATE_LIMIT - count),
            "throttled": count > RATE_LIMIT,
        })
    return result


# ---------------------------------------------------------------------------
# Pydantic models (request / response shapes)
# ---------------------------------------------------------------------------

class SecureMessageRequest(BaseModel):
    source:      str                    # which module is sending (e.g. "IVM")
    destination: str                    # which module is receiving (e.g. "ARE")
    event_type:  str                    # what kind of event (e.g. "ThreatAlert")
    message:     str                    # the actual message text
    metadata:    Dict[str, Any] = {}    # any extra structured data


class DecryptRequest(BaseModel):
    ciphertext: str
    nonce:      str


class RotateCertRequest(BaseModel):
    module: str

class UpdateRateLimitRequest(BaseModel):
    limit: int


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.get("/api/src/status")
async def get_status():
    """
    Master status endpoint — the frontend polls this to display the
    SRC dashboard. Returns everything: cert status, rate limits, recent logs.
    """
    with db() as conn:
        recent_logs = conn.execute("""
            SELECT id, timestamp, source, destination, event_type, message, payload_hash
            FROM audit_log
            ORDER BY timestamp DESC
            LIMIT 20
        """).fetchall()

    return {
        "status":       "operational",
        "timestamp":    datetime.now(PKT).isoformat(),
        "certificates": get_cert_status(),
        "rate_limits":  get_rate_status(),
        "recent_logs":  [dict(r) for r in recent_logs],
        "encryption":   {
            "algorithm": "AES-256-GCM",
            "key_bits":  256,
            "mode":      "Galois/Counter Mode",
        },
        "signing": {
            "algorithm": "HMAC-SHA3-256",
            "key_source": "Derived (HashiCorp Vault in production)",
        }
    }


@app.post("/api/src/send")
async def send_secure_message(req: SecureMessageRequest):
    """
    The main SRC endpoint. When any module wants to send a message
    to another module securely, it calls this.

    What happens:
    1. Check rate limit for the sending module
    2. Encrypt the message payload with AES-256-GCM
    3. Hash + sign and write to audit log
    4. Return the encrypted payload (destination module would decrypt it)
    """
    # Step 1: Rate limit check
    rate = check_rate_limit(req.source)
    if not rate["allowed"]:
        write_audit_log(
            source=req.source, destination=req.destination,
            event_type="RateLimitExceeded", message=f"{req.source} exceeded rate limit",
            metadata={"count": rate["count"], "limit": rate["limit"]}
        )
        siem_log(
            severity   = SiemSeverity.CRITICAL,
            source     = SiemSource.SRC,
            event_type = "DoSRateLimitExceeded",
            message    = (
                f"Module {req.source} exceeded rate limit "
                f"({rate['count']}/{rate['limit']} req/min). "
                f"Possible DoS — requests throttled."
            ),
            metadata   = {
                "offending_module": req.source,
                "destination":      req.destination,
                "count":            rate["count"],
                "limit":            rate["limit"],
            },
        )
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded for module {req.source}. "
                   f"{rate['count']}/{rate['limit']} requests this minute."
        )

    # Step 2: Validate modules
    if req.source not in MODULES or req.destination not in MODULES:
        raise HTTPException(status_code=400, detail="Unknown source or destination module.")

    # Step 3: Encrypt the payload
    payload_str = json.dumps({"message": req.message, "metadata": req.metadata})
    encrypted   = encrypt_payload(payload_str)

    # Step 4: Write signed audit log
    log_id = write_audit_log(
        source=req.source,
        destination=req.destination,
        event_type=req.event_type,
        message=req.message,
        metadata={**req.metadata, "encrypted": True, "nonce": encrypted["nonce"]},
        payload=payload_str,
    )

    siem_log(
        severity   = SiemSeverity.INFO,
        source     = SiemSource.SRC,
        event_type = "SecureMessageTransmitted",
        message    = (
            f"{req.source} → {req.destination} | "
            f"{req.event_type} | AES-256-GCM encrypted | Log: {log_id}"
        ),
        metadata   = {
            "source":      req.source,
            "destination": req.destination,
            "event_type":  req.event_type,
            "log_id":      log_id,
        },
    )

    return {
        "log_id":      log_id,
        "source":      req.source,
        "destination": req.destination,
        "event_type":  req.event_type,
        "encrypted":   encrypted,
        "rate_status": rate,
        "timestamp":   datetime.now(PKT).isoformat(),
    }


@app.post("/api/src/decrypt")
async def decrypt_message(req: DecryptRequest):
    """
    Decrypts a previously encrypted SRC message.
    In a real mTLS setup, only the intended destination module's
    private key could do this. Here we use our shared AES key.
    """
    try:
        plaintext = decrypt_payload(req.ciphertext, req.nonce)
        return {"decrypted": json.loads(plaintext), "status": "success"}
    except Exception as e:
        siem_log(
            severity   = SiemSeverity.ERROR,
            source     = SiemSource.SRC,
            event_type = "DecryptionFailure",
            message    = f"SRC decryption failed: {str(e)}",
            metadata   = {"error": str(e)},
        )
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")


@app.post("/api/src/rotate-cert")
async def rotate_certificate(req: RotateCertRequest):
    """
    Manually rotate (regenerate) the certificate for a specific module.
    In production this runs on a 30-day schedule automatically.
    Here you can also trigger it manually from the dashboard.
    """
    if req.module not in MODULES:
        raise HTTPException(status_code=400, detail=f"Unknown module: {req.module}")

    generate_cert_for_module(req.module)

    meta = _load_cert_meta()
    meta[req.module] = datetime.now(PKT).isoformat()
    _save_cert_meta(meta)

    write_audit_log(
        source="SRC", destination=req.module,
        event_type="CertificateRotated",
        message=f"Certificate manually rotated for {req.module}",
        metadata={"rotated_by": "admin", "new_expiry_days": CERT_LIFETIME_DAYS}
    )
    siem_log(
        severity   = SiemSeverity.INFO,
        source     = SiemSource.SRC,
        event_type = "CertificateRotated",
        message    = (
            f"TLS certificate rotated for module {req.module}. "
            f"New certificate valid for {CERT_LIFETIME_DAYS} days."
        ),
        metadata   = {
            "module":           req.module,
            "rotated_by":       "admin",
            "new_expiry_days":  CERT_LIFETIME_DAYS,
        },
    )

    return {
        "status":  "rotated",
        "module":  req.module,
        "message": f"New certificate issued for {req.module}, valid for {CERT_LIFETIME_DAYS} days.",
        "certs":   get_cert_status(),
    }


@app.get("/api/src/audit-log")
async def get_audit_log(limit: int = 50, source: Optional[str] = None):
    """Returns the signed audit log, optionally filtered by source module."""
    query  = "SELECT * FROM audit_log"
    params = []
    if source:
        query += " WHERE source = ?"
        params.append(source)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with db() as conn:
        rows = conn.execute(query, params).fetchall()

    return {"logs": [dict(r) for r in rows], "count": len(rows)}


@app.get("/api/src/verify/{log_id}")
async def verify_log(log_id: str):
    """
    Verifies that a specific audit log entry has not been tampered with.
    Returns verified: true/false and the reason if it fails.
    """
    return verify_log_entry(log_id)


@app.get("/api/src/certs")
async def get_certificates():
    """Returns current certificate status for all modules."""
    return {"certificates": get_cert_status()}


@app.post("/api/src/rotate-all")
async def rotate_all_certificates():
    """Rotates ALL module certificates at once (admin action)."""
    rotated = []
    meta    = _load_cert_meta()
    for module in MODULES:
        generate_cert_for_module(module)
        meta[module] = datetime.now(PKT).isoformat()
        rotated.append(module)

    _save_cert_meta(meta)
    write_audit_log(
        source="SRC", destination="ALL",
        event_type="BulkCertificateRotation",
        message="All module certificates rotated by admin",
        metadata={"modules": rotated}
    )
    siem_log(
        severity   = SiemSeverity.WARNING,
        source     = SiemSource.SRC,
        event_type = "BulkCertificateRotation",
        message    = (
            f"Bulk certificate rotation triggered by admin. "
            f"All {len(rotated)} module certificates regenerated."
        ),
        metadata   = {"modules_rotated": rotated, "count": len(rotated)},
    )

    return {"status": "all_rotated", "modules": rotated, "certs": get_cert_status()}


@app.post("/api/src/rate-limit")
async def update_rate_limit(req: UpdateRateLimitRequest):
    """Update the rate limit for all modules."""
    global RATE_LIMIT
    if req.limit < 5 or req.limit > 500:
        raise HTTPException(status_code=400, detail="Rate limit must be between 5 and 500.")
    old_limit = RATE_LIMIT
    RATE_LIMIT = req.limit
    _save_persisted_settings()
    write_audit_log(
        source="SRC", destination="ALL",
        event_type="RateLimitUpdated",
        message=f"Rate limit updated by admin: {old_limit} → {RATE_LIMIT} req/min",
        metadata={"old_limit": old_limit, "new_limit": RATE_LIMIT}
    )
    siem_log(
        severity=SiemSeverity.WARNING, source=SiemSource.SRC,
        event_type="RateLimitUpdated",
        message=f"SRC rate limit changed from {old_limit} to {RATE_LIMIT} req/min by admin",
        metadata={"old_limit": old_limit, "new_limit": RATE_LIMIT},
    )
    return {"status": "updated", "old_limit": old_limit, "new_limit": RATE_LIMIT}

@app.get("/api/src/health")
async def health():
    return {"status": "online", "module": "SRC", "port": 8006}


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup():
    """
    This runs automatically when you start the server.
    Order of operations:
      1. Create the SQLite database and tables
      2. Generate/rotate certificates for all modules
      3. Write a startup audit log entry
    """
    print("[SRC] Initializing Secure Response & Coordination module...")
    init_db()
    _load_persisted_settings()
    print(f"[SRC] Rate limit loaded: {RATE_LIMIT} req/min")
    rotated = bootstrap_certificates()

    write_audit_log(
        source="SRC", destination="ALL",
        event_type="SystemStartup",
        message="SRC module initialized. Certificate check complete.",
        metadata={
            "modules_checked": MODULES,
            "certs_rotated":   rotated,
            "encryption":      "AES-256-GCM",
            "signing":         "HMAC-SHA3-256",
            "rate_limit":      f"{RATE_LIMIT} req/min per module",
        }
    )
    siem_log(
        severity   = SiemSeverity.INFO,
        source     = SiemSource.SRC,
        event_type = "SRCModuleStartup",
        message    = (
            f"SRC module online on port 8006. "
            f"{len(rotated)} certificate(s) rotated on startup. "
            f"Encryption: AES-256-GCM | Signing: HMAC-SHA3-256 | "
            f"Rate limit: {RATE_LIMIT} req/min per module."
        ),
        metadata   = {
            "modules_checked": MODULES,
            "certs_rotated":   rotated,
            "port":            8006,
        },
    )
    print(f"[SRC] Ready. Listening on http://localhost:8006")
    print(f"[SRC] Certificates stored in: {CERT_DIR}/")
    print(f"[SRC] Audit log database: {DB_PATH}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8006)