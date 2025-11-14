# notification_service.py — Firebase Admin Push Notifications
# backend/app/services/notification_service.py

import firebase_admin
from firebase_admin import credentials, messaging
from pathlib import Path
import os
import sqlite3
import json

# -----------------------------------------
# Paths
# -----------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent  # /app
CONFIG_DIR = BASE_DIR / "config"
DB_PATH = BASE_DIR / "secure" / "aurumra.db"

# -----------------------------------------
# Initialize Firebase Admin (Using ENV VAR)
# -----------------------------------------

firebase_key_raw = os.getenv("FIREBASE_SERVICE_ACCOUNT")

if not firebase_key_raw:
    raise Exception("❌ ERROR: FIREBASE_SERVICE_ACCOUNT env variable missing!")

try:
    firebase_key_dict = json.loads(firebase_key_raw)
except Exception as e:
    raise Exception(f"❌ ERROR: Unable to parse FIREBASE_SERVICE_ACCOUNT JSON → {e}")

cred = credentials.Certificate(firebase_key_dict)

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)


# =========================================================
# Device Token System (Stores device tokens)
# =========================================================

def _db():
    return sqlite3.connect(DB_PATH)


def register_tokens(tokens):
    """
    Store FCM tokens for push notifications.
    Used by /register_device in main.py
    """
    if not tokens:
        return {"registered": 0}

    conn = _db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS device_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE
        )
    """)

    for token in tokens:
        try:
            cur.execute("INSERT OR IGNORE INTO device_tokens (token) VALUES (?)", (token,))
        except Exception:
            pass

    conn.commit()
    conn.close()

    return {"registered": len(tokens)}


# =========================================================
# BROADCAST Push Notifications
# =========================================================

def broadcast_transaction_notification(title, message, data=None):
    """
    Sends a push notification to ALL device tokens.
    Called in main.py after a user sends a transaction.
    """

    conn = _db()
    cur = conn.cursor()

    cur.execute("SELECT token FROM device_tokens")
    rows = cur.fetchall()
    conn.close()

    tokens = [r[0] for r in rows]

    if not tokens:
        print("⚠️ No devices registered.")
        return {"sent": 0}

    # Split into batches of 500
    batch_size = 500
    batches = [tokens[i:i + batch_size] for i in range(0, len(tokens), batch_size)]

    total_sent = 0
    failures = 0
    responses = []

    for batch in batches:
        multicast = messaging.MulticastMessage(
            notification=messaging.Notification(
                title=title,
                body=message
            ),
            data={k: str(v) for k, v in (data or {}).items()},
            tokens=batch
        )

        try:
            result = messaging.send_multicast(multicast)
            responses.append(result)
            total_sent += result.success_count
            failures += result.failure_count
            print(f"📨 FCM Batch: {result.success_count} sent, {result.failure_count} failed")
        except Exception as e:
            print(f"⚠️ Firebase error: {e}")

    return {
        "sent": total_sent,
        "failed": failures,
        "responses": responses
    }


# =========================================================
# Topic-based Notification (used by listener.py)
# =========================================================

def send_incoming_tx_notification(address, amount, inr_value):
    """
    Used by listener.py → sends push when incoming MATIC arrives.
    Device must subscribe to /topics/<wallet_address>
    """

    try:
        message = messaging.Message(
            notification=messaging.Notification(
                title="💰 Incoming Transaction",
                body=f"You received {amount:.4f} MATIC (≈₹{inr_value:.2f})"
            ),
            topic=address.lower()
        )

        response = messaging.send(message)
        print(f"📨 Topic Push Sent → {response}")

    except Exception as e:
        print(f"⚠️ Push Error: {e}")
