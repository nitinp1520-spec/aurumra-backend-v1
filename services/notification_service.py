# notification_service.py — Aurumra Wallet (FCM v1 Ready)

import os
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

import google.auth
from google.oauth2 import service_account
import google.auth.transport.requests

# -------------------------------------------------------------------
# Resolve Folder Paths
# -------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent  # /app
CONFIG_DIR = BASE_DIR / "config"
SECURE_DIR = BASE_DIR / "secure"
DB_PATH = SECURE_DIR / "aurumra.db"

SECURE_DIR.mkdir(exist_ok=True)

# -------------------------------------------------------------------
# Load Service Account JSON (firebase-key.json)
# -------------------------------------------------------------------
SERVICE_ACCOUNT_FILE = CONFIG_DIR / "firebase-key.json"

if not SERVICE_ACCOUNT_FILE.exists():
    print("❌ ERROR: firebase-key.json missing in app/config/")
else:
    print("✅ Firebase Service Account detected.")

# Firebase Project ID
PROJECT_ID = "aurumra-wallet-438d7"

# OAuth scope for FCM v1
SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]

# -------------------------------------------------------------------
# Create OAuth2 Access Token
# -------------------------------------------------------------------
def get_access_token() -> str:
    """
    Create a Google OAuth2 access token using service account file.
    """
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES
    )
    auth_req = google.auth.transport.requests.Request()
    credentials.refresh(auth_req)
    return credentials.token


# ===================================================================
#   DEVICE TOKEN STORAGE
# ===================================================================
def register_tokens(tokens: List[str]):
    """
    Store device tokens in SQLite.
    Ensures no duplicate entries.
    """
    if not tokens:
        return {"registered": 0}

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS device_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE
        )
    """)

    count = 0
    for token in tokens:
        try:
            cur.execute("INSERT OR IGNORE INTO device_tokens (token) VALUES (?)", (token,))
            count += 1
        except:
            pass

    conn.commit()
    conn.close()

    return {"registered": count}


# ===================================================================
#   SEND PUSH NOTIFICATION (FCM HTTP v1)
# ===================================================================
import requests

def send_push_notification(title: str, body: str, data: Optional[dict] = None):
    """
    Send a push notification to ALL registered devices.
    Uses FCM HTTP v1 (OAuth2).
    """

    # Load tokens
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT token FROM device_tokens")
    rows = cur.fetchall()
    conn.close()

    tokens = [row[0] for row in rows]

    if not tokens:
        return {"status": "no_tokens"}

    url = f"https://fcm.googleapis.com/v1/projects/{PROJECT_ID}/messages:send"

    access_token = get_access_token()
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json; UTF-8",
    }

    results = []

    for token in tokens:
        payload = {
            "message": {
                "token": token,
                "notification": {
                    "title": title,
                    "body": body
                },
                "data": data or {}
            }
        }

        try:
            response = requests.post(url, headers=headers, json=payload)
            results.append(response.json())
        except Exception as e:
            results.append({"error": str(e)})

    return {
        "status": "sent",
        "count": len(tokens),
        "responses": results
    }


# ===================================================================
#   SHORTCUT — Broadcast Transaction Notification
# ===================================================================
def broadcast_transaction_notification(amount, symbol="MATIC"):
    """
    Sends notification: 'You received X MATIC'
    """
    title = "💰 Incoming Transaction"
    body = f"You received {amount} {symbol}"

    return send_push_notification(title, body, data={"amount": str(amount)})

