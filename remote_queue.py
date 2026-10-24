"""Persistent device pairing and allowlisted command queue for Cutie."""
import hashlib
import json
import secrets
import sqlite3
import time
from pathlib import Path
from contextlib import contextmanager

from fastapi import APIRouter, Header, HTTPException, Request

router = APIRouter()
ADMIN_CHECK = None

DB_PATH = Path(__import__("os").environ.get(
    "CUTIE_DATA_DIR",
    str(Path(__file__).resolve().parent / "data")
)) / "remote_queue.sqlite3"

DB_PATH.parent.mkdir(parents=True, exist_ok=True)

ALLOWED_TASKS = {"status", "scan", "build"}
MAX_DELIVERY_ATTEMPTS = 3
DELIVERY_LEASE_SECONDS = 60



def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def set_admin_checker(checker):
    global ADMIN_CHECK
    ADMIN_CHECK = checker


def check_admin(token):
    if ADMIN_CHECK is None:
        raise HTTPException(503, "Admin authentication is not configured.")
    ADMIN_CHECK(token)


async def read_json_object(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body.")

    if not isinstance(body, dict):
        raise HTTPException(400, "JSON body must be an object.")

    return body


def require_device(token):
    if not token:
        raise HTTPException(401, "Device token required.")
    with connect() as db:
        row = db.execute(
            "SELECT device_id FROM devices WHERE token_hash=? AND revoked=0",
            (digest(token),)
        ).fetchone()
        if row is None:
            raise HTTPException(401, "Invalid or revoked device token.")
        db.execute(
            "UPDATE devices SET last_seen=? WHERE device_id=?",
            (int(time.time()), row["device_id"])
        )
        return row["device_id"]

@contextmanager
def connect():
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS pair_codes (
            code_hash TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            last_seen INTEGER
        );
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            task TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            result TEXT,
            attempts INTEGER NOT NULL DEFAULT 0,
            lease_until INTEGER,
            lease_token TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(device_id)
        );
        CREATE INDEX IF NOT EXISTS idx_commands_device_status
        ON commands(device_id, status, id);
        """)
        # Migrate databases created before delivery retry support.
        columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(commands)").fetchall()
        }
        if "attempts" not in columns:
            db.execute(
                "ALTER TABLE commands ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0"
            )
        if "lease_until" not in columns:
            db.execute("ALTER TABLE commands ADD COLUMN lease_until INTEGER")
        if "lease_token" not in columns:
            db.execute("ALTER TABLE commands ADD COLUMN lease_token TEXT")
        db.execute("PRAGMA journal_mode=WAL")


@router.post("/api/admin/pairing-code")
def create_pairing_code(x_admin_token: str | None = Header(default=None)):
    check_admin(x_admin_token)
    code = secrets.token_urlsafe(18)
    now = int(time.time())
    with connect() as db:
        db.execute("INSERT INTO pair_codes(code_hash, expires_at) VALUES (?, ?)",
                   (digest(code), now + 300))
    # Show this code only to the authenticated admin, once.
    return {"pairing_code": code, "expires_in_seconds": 300}

@router.post("/api/device/pair")
async def pair_device(request: Request):
    body = await read_json_object(request)
    code = str(body.get("pairing_code", ""))
    device_id = str(body.get("device_id", "")).strip()[:100]
    name = str(body.get("name", "Cutie Android")).strip()[:100]
    if not code or not device_id:
        raise HTTPException(400, "pairing_code and device_id are required.")
    if not name:
        raise HTTPException(400, "name must not be empty.")
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        pair = db.execute(
            "SELECT code_hash FROM pair_codes WHERE code_hash=? AND used=0 AND expires_at>=?",
            (digest(code), now)
        ).fetchone()
        if not pair:
            raise HTTPException(401, "Pairing code invalid, expired, or already used.")
        existing = db.execute(
            "SELECT revoked FROM devices WHERE device_id=?", (device_id,)
        ).fetchone()
        if existing is not None and not existing["revoked"]:
            raise HTTPException(409, "Device is already paired.")

        db.execute("UPDATE pair_codes SET used=1 WHERE code_hash=?", (digest(code),))

        if existing is not None:
            # Do not carry unfinished work across a revoked-device re-pair.
            db.execute(
                """UPDATE commands
                   SET status='failed',
                       result=?,
                       lease_until=NULL,
                       lease_token=NULL,
                       updated_at=?
                   WHERE device_id=? AND status IN ('queued', 'delivered')""",
                (
                    json.dumps({"error": "device re-paired; pending command cancelled"}),
                    now,
                    device_id,
                ),
            )
            db.execute(
                "UPDATE devices SET name=?,token_hash=?,created_at=?,"
                "revoked=0,last_seen=? WHERE device_id=?",
                (name, digest(token), now, now, device_id)
            )
        else:
            db.execute(
                "INSERT INTO devices(device_id,name,token_hash,created_at,last_seen) "
                "VALUES(?,?,?,?,?)",
                (device_id, name, digest(token), now, now)
            )
    # The plaintext token is returned once and is never stored.
    return {"ok": True, "device_id": device_id, "device_token": token}

@router.get("/api/device/commands")
def poll_commands(authorization: str | None = Header(default=None)):
    token = None
    if authorization:
        scheme, separator, credential = authorization.partition(" ")
        if separator and scheme.lower() == "bearer" and credential.strip():
            token = credential.strip()
    device_id = require_device(token)
    now = int(time.time())

    with connect() as db:
        db.execute("BEGIN IMMEDIATE")

        # Requeue expired deliveries, or fail commands that exhausted retries.
        db.execute(
            """UPDATE commands
               SET status='queued', lease_until=NULL, lease_token=NULL, updated_at=?
               WHERE device_id=? AND status='delivered'
                 AND lease_until IS NOT NULL AND lease_until<=?
                 AND attempts<?""",
            (now, device_id, now, MAX_DELIVERY_ATTEMPTS)
        )
        db.execute(
            """UPDATE commands
               SET status='failed',
                   result=?,
                   lease_until=NULL,
                   lease_token=NULL,
                   updated_at=?
               WHERE device_id=? AND status='delivered'
                 AND lease_until IS NOT NULL AND lease_until<=?
                 AND attempts>=?""",
            (
                json.dumps({"error": "delivery attempts exhausted"}),
                now, device_id, now, MAX_DELIVERY_ATTEMPTS
            )
        )

        rows = db.execute(
            """SELECT id,task,created_at,attempts
               FROM commands
               WHERE device_id=? AND status='queued' AND attempts<?
               ORDER BY id LIMIT 10""",
            (device_id, MAX_DELIVERY_ATTEMPTS)
        ).fetchall()

        commands = []
        for row in rows:
            attempt = row["attempts"] + 1
            lease_until = now + DELIVERY_LEASE_SECONDS
            lease_token = secrets.token_urlsafe(24)
            cur = db.execute(
                """UPDATE commands
                   SET status='delivered', attempts=?, lease_until=?,
                       lease_token=?, updated_at=?
                   WHERE id=? AND device_id=? AND status='queued'""",
                (attempt, lease_until, lease_token, now, row["id"], device_id)
            )
            if cur.rowcount == 1:
                commands.append({
                    "id": row["id"],
                    "task": row["task"],
                    "created_at": row["created_at"],
                    "attempt": attempt,
                    "lease_token": lease_token,
                    "lease_seconds": DELIVERY_LEASE_SECONDS
                })

        return {"commands": commands}

@router.post("/api/device/commands/{command_id}/result")
async def command_result(command_id: int, request: Request,
                         authorization: str | None = Header(default=None)):
    token = None
    if authorization:
        scheme, separator, credential = authorization.partition(" ")
        if separator and scheme.lower() == "bearer" and credential.strip():
            token = credential.strip()
    device_id = require_device(token)
    body = await read_json_object(request)
    status = body.get("status")
    if status not in {"completed", "failed"}:
        raise HTTPException(400, "status must be completed or failed.")
    attempt = body.get("attempt")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise HTTPException(400, "A valid integer attempt is required.")

    lease_token = body.get("lease_token")
    if not isinstance(lease_token, str) or len(lease_token) < 20:
        raise HTTPException(400, "A valid lease_token is required.")

    result = json.dumps(body.get("result", ""), ensure_ascii=False)[:8000]
    now = int(time.time())
    with connect() as db:
        cur = db.execute(
            """UPDATE commands
               SET status=?, result=?, updated_at=?,
                   lease_until=NULL, lease_token=NULL
               WHERE id=? AND device_id=? AND status='delivered'
                 AND attempts=? AND lease_token=?
                 AND lease_until IS NOT NULL AND lease_until>?""",
            (status, result, now, command_id, device_id, attempt, lease_token, now)
        )
        if cur.rowcount != 1:
            raise HTTPException(404, "Command not found or no longer awaiting a result.")
    return {"ok": True}

@router.post("/api/admin/commands")
async def enqueue_command(request: Request,
                          x_admin_token: str | None = Header(default=None)):
    check_admin(x_admin_token)
    body = await read_json_object(request)
    device_id = str(body.get("device_id", "")).strip()
    task = str(body.get("task", "")).strip()
    if task not in ALLOWED_TASKS:
        raise HTTPException(400, "Allowed tasks: status, scan, build.")
    now = int(time.time())
    with connect() as db:
        if not db.execute(
            "SELECT 1 FROM devices WHERE device_id=? AND revoked=0", (device_id,)
        ).fetchone():
            raise HTTPException(404, "Paired device not found.")
        cur = db.execute(
            "INSERT INTO commands(device_id,task,created_at,updated_at) VALUES(?,?,?,?)",
            (device_id, task, now, now)
        )
        command_id = cur.lastrowid
    return {"ok": True, "command_id": command_id, "status": "queued"}

@router.get("/api/admin/devices")
def list_devices(x_admin_token: str | None = Header(default=None)):
    check_admin(x_admin_token)
    with connect() as db:
        rows = db.execute(
            "SELECT device_id,name,created_at,revoked,last_seen FROM devices ORDER BY created_at DESC"
        ).fetchall()
        return {"devices": [dict(r) for r in rows]}

@router.post("/api/admin/devices/{device_id}/revoke")
def revoke_device(device_id: str, x_admin_token: str | None = Header(default=None)):
    check_admin(x_admin_token)
    now = int(time.time())
    with connect() as db:
        cur = db.execute(
            "UPDATE devices SET revoked=1 WHERE device_id=?",
            (device_id,),
        )
        if cur.rowcount != 1:
            raise HTTPException(404, "Device not found.")

        # Cancel unfinished work when a device is revoked.
        db.execute(
            """UPDATE commands
               SET status='failed',
                   result=?,
                   lease_until=NULL,
                   lease_token=NULL,
                   updated_at=?
               WHERE device_id=? AND status IN ('queued', 'delivered')""",
            (
                json.dumps({"error": "device revoked; pending command cancelled"}),
                now,
                device_id,
            ),
        )
    return {"ok": True, "revoked": device_id}
