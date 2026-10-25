import importlib
import os
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CUTIE_API_KEY", "test-admin-key")
    monkeypatch.setenv("CUTIE_PAIRING_CODE", "test-pairing-code")
    monkeypatch.setenv("CUTIE_DATA_DIR", str(tmp_path))

    # Ensure app and queue initialize with isolated test settings.
    sys.modules.pop("main", None)
    sys.modules.pop("remote_queue", None)
    main = importlib.import_module("main")

    with TestClient(main.app) as test_client:
        yield test_client


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200


def test_existing_v1_routes_remain_available(client):
    # Inspect the public OpenAPI schema rather than FastAPI internals.
    response = client.get("/openapi.json")
    assert response.status_code == 200

    paths = response.json()["paths"]
    assert "/v1/admin/status" in paths
    assert "/v1/features" in paths
    assert "/v1/device/pair" in paths
    assert "/v1/commands" in paths


def test_admin_status_requires_authentication(client):
    response = client.get("/v1/admin/status")
    assert response.status_code in (401, 403)


def test_pairing_code_requires_admin_token(client):
    response = client.post("/api/admin/pairing-code")
    assert response.status_code in (401, 403)


def test_pair_endpoint_rejects_non_object_json(client):
    response = client.post(
        "/api/device/pair",
        json=["not", "an", "object"],
    )
    assert response.status_code == 400


def test_pair_endpoint_rejects_invalid_json(client):
    response = client.post(
        "/api/device/pair",
        content="{invalid-json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400


def test_admin_command_rejects_non_object_json(client):
    response = client.post(
        "/api/admin/commands",
        json=["not", "an", "object"],
        headers={"X-Admin-Token": "test-admin-key"},
    )
    assert response.status_code == 400


def test_pair_queue_and_revoke_over_http(client, tmp_path):
    import sqlite3

    admin = {"X-Admin-Token": "test-admin-key"}

    code_response = client.post(
        "/api/admin/pairing-code",
        headers=admin,
    )
    assert code_response.status_code == 200
    pairing_code = code_response.json()["pairing_code"]

    pair_response = client.post(
        "/api/device/pair",
        json={
            "pairing_code": pairing_code,
            "device_id": "http-test-phone",
            "name": "HTTP Test Phone",
        },
    )
    assert pair_response.status_code == 200
    device_token = pair_response.json()["device_token"]
    assert device_token

    queue_response = client.post(
        "/api/admin/commands",
        headers=admin,
        json={"device_id": "http-test-phone", "task": "status"},
    )
    assert queue_response.status_code == 200
    command_id = queue_response.json()["command_id"]

    device_headers = {"Authorization": f"Bearer {device_token}"}
    poll_response = client.get(
        "/api/device/commands",
        headers=device_headers,
    )
    assert poll_response.status_code == 200
    command = next(
        item for item in poll_response.json()["commands"]
        if item["id"] == command_id
    )

    revoke_response = client.post(
        "/api/admin/devices/http-test-phone/revoke",
        headers=admin,
    )
    assert revoke_response.status_code == 200

    assert client.get(
        "/api/device/commands",
        headers=device_headers,
    ).status_code == 401

    result_response = client.post(
        f"/api/device/commands/{command_id}/result",
        headers=device_headers,
        json={
            "status": "completed",
            "attempt": command["attempt"],
            "lease_token": command["lease_token"],
            "result": {"ok": True},
        },
    )
    assert result_response.status_code == 401

    with sqlite3.connect(tmp_path / "remote_queue.sqlite3") as db:
        row = db.execute(
            "SELECT status, lease_until, lease_token FROM commands WHERE id=?",
            (command_id,),
        ).fetchone()

    assert row is not None
    assert row[0] == "failed"
    assert row[1] is None
    assert row[2] is None


def test_http_rejects_task_outside_allowlist(client):
    response = client.post(
        "/api/admin/commands",
        headers={"X-Admin-Token": "test-admin-key"},
        json={"device_id": "unknown-device", "task": "delete"},
    )
    assert response.status_code == 400

def test_firebase_check_requires_admin_authentication(client):
    response = client.post("/api/admin/firebase-check")
    assert response.status_code == 401


def test_firebase_check_rejects_wrong_admin_token(client):
    response = client.post(
        "/api/admin/firebase-check",
        headers={"X-Admin-Token": "wrong-token"},
    )
    assert response.status_code == 401


def test_firebase_check_fails_safely_without_credentials(client, monkeypatch):
    monkeypatch.delenv("FIREBASE_SERVICE_ACCOUNT_JSON", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("FIREBASE_PROJECT_ID", raising=False)

    response = client.post(
        "/api/admin/firebase-check",
        headers={"X-Admin-Token": "test-admin-key"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "Firebase connection check failed. Check server logs and credentials."
    )
    assert "private_key" not in response.text.lower()
    assert "service-account" not in response.text.lower()
