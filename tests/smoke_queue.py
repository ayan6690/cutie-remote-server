import asyncio
import importlib
import os
import sys
import tempfile
import types
from pathlib import Path


# Minimal FastAPI import shim. This is NOT an HTTP/ASGI test.
fake = types.ModuleType("fastapi")


class HTTPException(Exception):
    def __init__(self, status_code, detail=None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class APIRouter:
    def post(self, *a, **kw):
        return lambda fn: fn

    def get(self, *a, **kw):
        return lambda fn: fn


def Header(default=None, **kw):
    return default


class Request:
    pass


fake.APIRouter = APIRouter
fake.HTTPException = HTTPException
fake.Header = Header
fake.Request = Request
sys.modules["fastapi"] = fake

with tempfile.TemporaryDirectory(prefix="cutie-queue-test-") as tmp:
    os.environ["CUTIE_DATA_DIR"] = tmp
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    sys.modules.pop("remote_queue", None)
    q = importlib.import_module("remote_queue")
    q.init_db()

    q.set_admin_checker(
        lambda token: (
            None if token == "test-admin"
            else (_ for _ in ()).throw(HTTPException(401, "bad admin"))
        )
    )

    class FakeRequest:
        def __init__(self, body):
            self.body = body

        async def json(self):
            return self.body

    def expect_http(code, fn, *args, **kwargs):
        try:
            result = fn(*args, **kwargs)
            if hasattr(result, "__await__"):
                result = asyncio.run(result)
        except HTTPException as exc:
            assert exc.status_code == code, (
                f"Expected HTTP {code}, got {exc.status_code}: {exc.detail}"
            )
            return
        raise AssertionError(f"Expected HTTP {code}, got result: {result!r}")

    # Pairing code generation and one-time pairing
    code_data = q.create_pairing_code(x_admin_token="test-admin")
    code = code_data["pairing_code"]
    assert code_data["expires_in_seconds"] == 300

    paired = asyncio.run(q.pair_device(FakeRequest({
        "pairing_code": code,
        "device_id": "test-phone",
        "name": "Test Phone",
    })))
    token = paired["device_token"]
    assert token and paired["device_id"] == "test-phone"

    # Token must not be stored in plaintext
    with q.connect() as db:
        row = db.execute(
            "SELECT token_hash FROM devices WHERE device_id=?",
            ("test-phone",),
        ).fetchone()
        assert row["token_hash"] == q.digest(token)
        assert row["token_hash"] != token

    expect_http(
        401, q.pair_device,
        FakeRequest({
            "pairing_code": code,
            "device_id": "another-phone",
        }),
    )

    # Only allowlisted tasks can be queued
    expect_http(
        400, q.enqueue_command,
        FakeRequest({"device_id": "test-phone", "task": "delete"}),
        x_admin_token="test-admin",
    )

    queued = asyncio.run(q.enqueue_command(
        FakeRequest({"device_id": "test-phone", "task": "status"}),
        x_admin_token="test-admin",
    ))
    command_id = queued["command_id"]
    assert queued["status"] == "queued"

    # Device polling delivers a leased command
    delivered = q.poll_commands(authorization=f"Bearer {token}")
    item = next(c for c in delivered["commands"] if c["id"] == command_id)
    assert item["attempt"] == 1
    assert len(item["lease_token"]) >= 20

    # Valid lease accepts a result
    result = asyncio.run(q.command_result(
        command_id,
        FakeRequest({
            "status": "completed",
            "attempt": item["attempt"],
            "lease_token": item["lease_token"],
            "result": {"ok": True},
        }),
        authorization=f"Bearer {token}",
    ))
    assert result["ok"] is True

    # A completed command cannot accept a second result
    expect_http(
        404, q.command_result, command_id,
        FakeRequest({
            "status": "completed",
            "attempt": item["attempt"],
            "lease_token": item["lease_token"],
        }),
        authorization=f"Bearer {token}",
    )

    # An expired lease must reject a late result
    late = asyncio.run(q.enqueue_command(
        FakeRequest({"device_id": "test-phone", "task": "scan"}),
        x_admin_token="test-admin",
    ))
    late_item = next(
        c for c in q.poll_commands(authorization=f"Bearer {token}")["commands"]
        if c["id"] == late["command_id"]
    )
    with q.connect() as db:
        db.execute(
            "UPDATE commands SET lease_until=0 WHERE id=?",
            (late["command_id"],),
        )

    expect_http(
        404, q.command_result, late["command_id"],
        FakeRequest({
            "status": "completed",
            "attempt": late_item["attempt"],
            "lease_token": late_item["lease_token"],
        }),
        authorization=f"Bearer {token}",
    )

    # Revocation blocks future polling
    q.revoke_device("test-phone", x_admin_token="test-admin")
    expect_http(401, q.poll_commands, authorization=f"Bearer {token}")

    # Re-pairing a revoked device rotates its token
    new_code = q.create_pairing_code(
        x_admin_token="test-admin"
    )["pairing_code"]
    paired_again = asyncio.run(q.pair_device(FakeRequest({
        "pairing_code": new_code,
        "device_id": "test-phone",
        "name": "Test Phone",
    })))
    assert paired_again["device_token"] != token
    expect_http(401, q.poll_commands, authorization=f"Bearer {token}")
    with q.connect() as db:
        old_command = db.execute(
            "SELECT status, lease_until, lease_token FROM commands WHERE id=?",
            (late["command_id"],),
        ).fetchone()
        assert old_command["status"] == "failed"
        assert old_command["lease_until"] is None
        assert old_command["lease_token"] is None

    assert q.poll_commands(
        authorization=f"Bearer {paired_again['device_token']}"
    )["commands"] == []

    print("PASS: one-time pairing code")
    print("PASS: device token stored as a hash")
    print("PASS: task allowlist")
    print("PASS: queue delivery and valid result")
    print("PASS: duplicate result rejected")
    print("PASS: expired lease result rejected")
    print("PASS: revoked token rejected")
    print("PASS: re-pair rotates token")
    print("NOTE: these are direct function tests, not HTTP tests")
