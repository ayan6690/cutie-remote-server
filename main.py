
import os
import hmac
from datetime import datetime, timezone
from typing import Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="Cutie Remote Server",
    version="1.0.0",
    description="Private API for Cutie AI"
)

API_KEY = os.getenv("CUTIE_API_KEY", "")
PAIRING_CODE = os.getenv("CUTIE_PAIRING_CODE", "")

FEATURES = {
    "remote_phone_monitor": False,
    "remote_camera": False,
    "remote_microphone": False,
    "sms_monitor": False,
    "whatsapp_automation": False,
    "remote_build": False,
}

# Demo-only in-memory command list.
# It resets when the server restarts.
commands = []


def require_admin(x_api_key: str | None):
    if not API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Server admin key is not configured"
        )

    if not x_api_key or not hmac.compare_digest(
        x_api_key, API_KEY
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )


class PairRequest(BaseModel):
    device_name: str = Field(min_length=1, max_length=80)
    pairing_code: str = Field(min_length=8, max_length=200)


class CommandRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=100)
    task: Literal["status", "scan", "build"]


@app.get("/")
def root():
    return {
        "service": "Cutie Remote Server",
        "status": "online",
        "docs": "/docs"
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat()
    }


@app.get("/v1/admin/status")
def admin_status(x_api_key: str | None = Header(default=None)):
    require_admin(x_api_key)
    return {
        "server": "online",
        "version": app.version,
        "command_requests": len(commands)
    }


@app.get("/v1/features")
def get_features(x_api_key: str | None = Header(default=None)):
    require_admin(x_api_key)
    return {"features": FEATURES}


@app.post("/v1/device/pair")
def pair_device(
    body: PairRequest,
    x_api_key: str | None = Header(default=None)
):
    require_admin(x_api_key)

    if not PAIRING_CODE or not hmac.compare_digest(
        body.pairing_code, PAIRING_CODE
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid pairing code"
        )

    # This validates the code only. Persistent device pairing
    # and per-device tokens are not implemented yet.
    return {
        "accepted": True,
        "device_name": body.device_name,
        "message": "Code accepted; device registration is not yet persistent"
    }


@app.post("/v1/commands")
def submit_command(
    body: CommandRequest,
    x_api_key: str | None = Header(default=None)
):
    require_admin(x_api_key)

    if len(commands) >= 100:
        raise HTTPException(
            status_code=429,
            detail="Demo command queue is full"
        )

    command = {
        "id": len(commands) + 1,
        "device_id": body.device_id,
        "task": body.task,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    commands.append(command)

    # This records a request only. It does not execute anything.
    return {
        "accepted": True,
        "command": command,
        "message": "Recorded only; no device is connected to execute it"
    }


@app.get("/v1/commands")
def list_commands(x_api_key: str | None = Header(default=None)):
    require_admin(x_api_key)
    return {"commands": commands}
