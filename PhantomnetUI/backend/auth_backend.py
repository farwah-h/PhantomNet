"""
PhantomNet++ — Authentication Backend (auth_backend.py)
FastAPI on port 8002

Endpoints:
  POST   /api/auth/login                   → verify credentials, return user info
  GET    /api/auth/users                   → list all users
  POST   /api/auth/users                   → create a new user
  PATCH  /api/auth/users/{user_id}/toggle  → activate/deactivate user
  DELETE /api/auth/users/{user_id}         → delete user

Database: auth.db (SQLite) — auto-created on startup
Passwords: bcrypt hashed — never stored in plaintext
"""

from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

PKT = timezone(timedelta(hours=5))  # Pakistan Standard Time (UTC+5)

import bcrypt
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from siem_logger import siem_log, SiemSeverity, SiemSource
from pydantic import BaseModel

# ── App setup ──────────────────────────────────────────────────────────────────
app = FastAPI(title="PhantomNet++ Auth API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Database ───────────────────────────────────────────────────────────────────
DB_PATH = Path(__file__).parent / "db" / "auth.db"
DB_PATH.parent.mkdir(exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    display_name  TEXT NOT NULL,
    role          TEXT NOT NULL CHECK(role IN ('admin', 'security_analyst', 'user')),
    password_hash TEXT NOT NULL,
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    last_login    TEXT
);
"""

DEFAULT_USERS = [
    {
        "email":        "admin@phantomnet.io",
        "display_name": "System Admin",
        "role":         "admin",
        "password":     "admin1234",
    },
    {
        "email":        "analyst@phantomnet.io",
        "display_name": "Security Analyst",
        "role":         "security_analyst",
        "password":     "analyst1234",
    },
    {
        "email":        "user@phantomnet.io",
        "display_name": "Standard User",
        "role":         "user",
        "password":     "user1234",
    },
]


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.executescript(SCHEMA)
        cur = conn.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            for u in DEFAULT_USERS:
                pw_hash = bcrypt.hashpw(u["password"].encode(), bcrypt.gensalt()).decode()
                conn.execute(
                    """INSERT INTO users (id, email, display_name, role, password_hash, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (str(uuid.uuid4()), u["email"], u["display_name"], u["role"], pw_hash,
                    datetime.now(PKT).isoformat())
                )
            print("✅ Default users seeded into auth.db")
        else:
            print("✅ auth.db already has users — skipping seed")


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def row_to_user(row: sqlite3.Row) -> dict:
    return {
        "id":          row["id"],
        "email":       row["email"],
        "displayName": row["display_name"],
        "role":        row["role"],
        "isActive":    bool(row["is_active"]),
        "createdAt":   row["created_at"],
        "lastLogin":   row["last_login"],
    }


# ── Pydantic models ────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email:    str
    password: str


class CreateUserRequest(BaseModel):
    email:       str
    displayName: str
    role:        str
    password:    str


# ── Startup ────────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup():
    init_db()
    print(f"🔐 Auth backend running — database: {DB_PATH}")


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/api/auth/health")
def health():
    return {"status": "ok", "service": "phantomnet-auth"}


@app.post("/api/auth/login")
def login(body: LoginRequest):
    email = body.email.strip().lower()
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ? AND is_active = 1", (email,)
        ).fetchone()

    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    siem_log(
        severity   = SiemSeverity.INFO,
        source     = SiemSource.AUTH,
        event_type = "UserLogin",
        message    = f"User logged in: {body.email}",
        metadata   = {"email": body.email}
    )

    with db() as conn:
        conn.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now(PKT).isoformat(), row["id"])
        )

    return {"success": True, "user": row_to_user(row)}


@app.get("/api/auth/users")
def list_users():
    with db() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY role, email").fetchall()
    return {"users": [row_to_user(r) for r in rows]}


@app.post("/api/auth/users", status_code=201)
def create_user(body: CreateUserRequest):
    if body.role not in ("admin", "security_analyst", "user"):
        raise HTTPException(status_code=400, detail="Invalid role.")
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    email = body.email.strip().lower()

    with db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Email already registered.")

        user_id = str(uuid.uuid4())
        pw_hash = hash_password(body.password)
        conn.execute(
            """INSERT INTO users (id, email, display_name, role, password_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, email, body.displayName, body.role, pw_hash,
             datetime.now(PKT).isoformat())
        )

    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    return {"success": True, "user": row_to_user(row)}


@app.patch("/api/auth/users/{user_id}/toggle")
def toggle_user(user_id: str):
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found.")
        new_state = 0 if row["is_active"] else 1
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_state, user_id))

    return {"success": True, "isActive": bool(new_state)}


@app.delete("/api/auth/users/{user_id}", status_code=204)
def delete_user(user_id: str):
    with db() as conn:
        row = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found.")
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("auth_backend:app", host="0.0.0.0", port=8002, reload=True)