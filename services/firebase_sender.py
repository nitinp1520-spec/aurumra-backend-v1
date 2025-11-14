# firebase_sender.py — FCM v1 Sender (HTTPX + Google OAuth)
# backend/app/services/firebase_sender.py

import os
import json
import time
import httpx
from pathlib import Path
from typing import Dict, Any

from google.oauth2 import service_account
from google.auth.transport.requests import Request

# -----------------------------------------
# Load Firebase Service Account JSON (ENV)
# -----------------------------------------

firebase_key_raw = os.getenv("FIREBASE_SERVICE_ACCOUNT")

if not firebase_key_raw:
    print("❌ ERROR: FIREBASE_SERVICE_ACCOUNT missing in Railway variables")
    firebase_credentials = None
else:
    try:
        service_account_json = json.loads(firebase_key_raw)
        firebase_credentials = service_account.Credentials.from_service_account_info(
            service_account_json,
            scopes=["https://www.googleapis.com/auth/firebase.messaging"],
        )
        print("✅ Firebase Service Account loaded (FCM v1 HTTP)")
    except Exception as e:
        firebase_credentials = None
        print(f"❌ ERROR: Invalid FIREBASE_SERVICE_ACCOUNT JSON → {e}")

# -----------------------------------------
# Token cache (1 hour expiration)
# -----------------------------------------
_cached_token: Dict[str, Any] = {
    "token": None,
    "expiry": 0
}

def get_access_token() -> str:
    """Generate or refresh OAuth2 token for FCM v1 API."""
    global _cached_token

    now = time.time()
    if _cached_token["token"] and now < _cached_token["expiry"]:
        return _cached_token["token"]

    if not firebase_credentials:
        raise Exception("Firebase credentials missing. Cannot generate token.")

    # Refresh token
    request = Request()
    firebase_credentials.refresh(request)

    token = firebase_credentials.token
    expiry = now + 3500  # ~1 hour

    _cached_token["token"] = token
    _cached_token["expiry"] = expiry

    return token


# -----------------------------------------
# Send Notification using FCM v1 REST API
# -----------------------------------------
async def send_fcm_http_v1(device_token: str, title: str, body: str, data=None):
    """Send push notification using Firebase Cloud Messaging v1 API."""
    if not firebase_credentials:
        return {"error": "Firebase credentials not loaded"}

    project_id = firebase_credentials.project_id
    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"

    headers = {
        "Authorization": f"Bearer {get_access_token()}",
        "Content-Type": "application/json; UTF-8",
    }

    message = {
        "message": {
            "token": device_token,
            "notification": {
                "title": title,
                "body": body
            },
            "data": {k: str(v) for k, v in (data or {}).items()},
        }
    }

    async with httpx.AsyncClient() as client:
        r = await client.post(url, headers=headers, json=message)

        if r.status_code >= 400:
            print("❌ FCM v1 Error →", r.text)
            return {"error": r.text}

        print("📨 FCM v1 Notification Sent →", r.text)
        return {"success": True, "response": r.json()}
