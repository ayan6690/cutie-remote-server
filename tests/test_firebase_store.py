import firebase_store
import sys
import types


class FakeSnapshot:
    exists = True

    def __init__(self, nonce):
        self.nonce = nonce

    def to_dict(self):
        return {"nonce": self.nonce}


class FakeDocument:
    def __init__(self):
        self.data = None
        self.deleted = False

    def set(self, data):
        self.data = data

    def get(self):
        return FakeSnapshot(self.data["nonce"])

    def delete(self):
        self.deleted = True


class FakeCollection:
    def __init__(self, document):
        self.document_ref = document

    def document(self, _name):
        return self.document_ref


class FakeDB:
    def __init__(self, document):
        self.document_ref = document

    def collection(self, _name):
        return FakeCollection(self.document_ref)


class FakeFirestore:
    SERVER_TIMESTAMP = "fake-server-timestamp"

    def __init__(self, db):
        self.db = db

    def client(self, app=None):
        return self.db


def test_firestore_check_writes_reads_and_deletes_temp_document(monkeypatch):
    document = FakeDocument()
    fake_firestore = FakeFirestore(FakeDB(document))
    monkeypatch.setattr(
        firebase_store, "_build_firebase_app",
        lambda: type("FakeApp", (), {"project_id": "test-project"})(),
    )

    fake_admin = types.ModuleType("firebase_admin")
    fake_admin.firestore = fake_firestore
    monkeypatch.setitem(sys.modules, "firebase_admin", fake_admin)
    monkeypatch.setitem(sys.modules, "firebase_admin.firestore", fake_firestore)
    monkeypatch.setenv("FIREBASE_PROJECT_ID", "test-project")

    result = firebase_store.verify_firestore_connection()

    assert result["firebase"] == "connected"
    assert result["firestore"] == "read_write_ok"
    assert result["project_id"] == "test-project"
    assert document.deleted is True
    assert document.data["purpose"] == "connection-check"


def test_firestore_check_fails_when_readback_nonce_mismatches(monkeypatch):
    document = FakeDocument()
    fake_firestore = FakeFirestore(FakeDB(document))
    monkeypatch.setattr(
        firebase_store, "_build_firebase_app",
        lambda: type("FakeApp", (), {"project_id": "test-project"})(),
    )

    fake_admin = types.ModuleType("firebase_admin")
    fake_admin.firestore = fake_firestore
    monkeypatch.setitem(sys.modules, "firebase_admin", fake_admin)
    monkeypatch.setitem(sys.modules, "firebase_admin.firestore", fake_firestore)
    monkeypatch.setattr(
        document, "get",
        lambda: FakeSnapshot("wrong-nonce"),
    )

    import pytest
    with pytest.raises(RuntimeError, match="read-back verification failed"):
        firebase_store.verify_firestore_connection()

    assert document.deleted is True
