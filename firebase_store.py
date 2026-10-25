"""Secure Firebase Admin / Firestore connection verification."""
import json
import os
import uuid


def _build_firebase_app():
    import firebase_admin
    from firebase_admin import credentials

    try:
        return firebase_admin.get_app()
    except ValueError:
        pass

    project_id = os.getenv("FIREBASE_PROJECT_ID", "").strip()
    service_account_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
    credentials_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()

    if service_account_json:
        try:
            service_account_info = json.loads(service_account_json)
        except (ValueError, TypeError) as exc:
            raise RuntimeError("Firebase service-account JSON is invalid") from exc

        if not isinstance(service_account_info, dict):
            raise RuntimeError("Firebase service-account JSON must be an object")

        key_project_id = str(service_account_info.get("project_id", "")).strip()
        if project_id and key_project_id and project_id != key_project_id:
            raise RuntimeError("Firebase project ID does not match service-account credentials")

        project_id = project_id or key_project_id
        credential = credentials.Certificate(service_account_info)

    elif credentials_path:
        if not os.path.isfile(credentials_path):
            raise RuntimeError("Firebase credentials file was not found")
        credential = credentials.Certificate(credentials_path)

    else:
        raise RuntimeError(
            "Configure FIREBASE_SERVICE_ACCOUNT_JSON or GOOGLE_APPLICATION_CREDENTIALS"
        )

    options = {"projectId": project_id} if project_id else None
    return firebase_admin.initialize_app(credential, options=options)


def verify_firestore_connection():
    from firebase_admin import firestore

    app = _build_firebase_app()
    db = firestore.client(app=app)
    nonce = uuid.uuid4().hex
    doc_ref = db.collection("_cutie_connection_checks").document(nonce)

    try:
        doc_ref.set({
            "purpose": "connection-check",
            "nonce": nonce,
            "created_at": firestore.SERVER_TIMESTAMP,
        })
        snapshot = doc_ref.get()

        if not snapshot.exists or snapshot.to_dict().get("nonce") != nonce:
            raise RuntimeError("Firestore read-back verification failed")

        return {
            "firebase": "connected",
            "firestore": "read_write_ok",
            "project_id": os.getenv("FIREBASE_PROJECT_ID", "").strip()
            or app.project_id,
        }
    finally:
        # Temporary verification document; don't hide deletion failures.
        doc_ref.delete()
