# listener.py — Incoming TX watcher (Polygon Amoy) + Push
# - Polls Covalent for each wallet in DB
# - Stores native MATIC values in app/database/wallet.db
# - Reads Expo tokens from devices table
# - Notifies device for every incoming tx
# - Clean path-handling (project-relative)
# - Loop interval: 15 seconds

import os
import time
import requests
import sqlite3
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv


# =========================================================
# Resolve project root:  app/listeners/ → project root
# =========================================================
CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parents[2]        # F:\WALLET V.01.0
APP_DIR = PROJECT_ROOT / "app"
CONFIG_DIR = APP_DIR / "config"
DB_DIR = APP_DIR / "database"


# =========================================================
# Load .env from app/config
# =========================================================
load_dotenv(CONFIG_DIR / ".env")

COVALENT_API_KEY = os.getenv("COVALENT_API_KEY")
if not COVALENT_API_KEY:
    print("❌ ERROR: Missing COVALENT_API_KEY in app/config/.env")
    time.sleep(2)

CHAIN_ID = "80002"  # Polygon Amoy Testnet
BASE_URL = "https://api.covalenthq.com/v1"

DB_PATH = DB_DIR / "wallet.db"


# =========================================================
# DB Helpers
# =========================================================
def db():
    return sqlite3.connect(DB_PATH)


def ensure_schema():
    conn = db()
    cur = conn.cursor()

    # Wallets table (already exists but ensure minimal fields)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT UNIQUE,
            encrypted_private_key TEXT,
            wallet_password_hash TEXT,
            created_at TEXT
        )
    """)

    # Device tokens for Expo push notifications
    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            wallet_address TEXT PRIMARY KEY,
            expo_token TEXT
        )
    """)

    # Incoming transaction log
    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            hash TEXT PRIMARY KEY,
            address TEXT,
            direction TEXT,
            amount REAL,
            value_raw TEXT,
            symbol TEXT,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()


# =========================================================
# Get Expo Push Token
# =========================================================
def get_expo_token(wallet_address: str):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT expo_token FROM devices WHERE wallet_address = ?", (wallet_address.lower(),))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


# =========================================================
# Send Push Notification
# =========================================================
def send_incoming_tx_notification(wallet_address: str, amount: float, inr_value: float):
    token = get_expo_token(wallet_address)
    if not token:
        print(f"⚠️ No expo token registered for {wallet_address}")
        return

    message = {
        "to": token,
        "sound": "default",
        "title": "💰 Incoming Transaction",
        "body": f"{amount:.6f} MATIC received (~₹{round(inr_value, 2)})",
        "priority": "high"
    }

    try:
        r = requests.post("https://api.expo.dev/v2/push/send", json=message, timeout=10)
        print("📨 Push Response:", r.text)
    except Exception as e:
        print("⚠️ Push Error:", e)


# =========================================================
# Price Conversion (INR)
# =========================================================
def get_matic_price_in_inr() -> float:
    try:
        r = requests.get("https://api.coinbase.com/v2/prices/MATIC-INR/spot", timeout=10).json()
        return float(r["data"]["amount"])
    except Exception:
        return 0.0


# =========================================================
# Fetch Incoming Transactions (Covalent)
# =========================================================
def fetch_incoming(address: str):
    url = f"{BASE_URL}/{CHAIN_ID}/address/{address}/transactions_v3/"
    params = {"key": COVALENT_API_KEY}

    try:
        data = requests.get(url, params=params, timeout=20).json()
    except Exception as e:
        print("⚠️ Covalent Error:", e)
        return []

    if "data" not in data or "items" not in data["data"]:
        return []

    # Return only incoming transfers
    return [
        t for t in data["data"]["items"]
        if t.get("to_address") and t["to_address"].lower() == address.lower()
    ]


# =========================================================
# Insert Incoming Transaction
# =========================================================
def insert_transaction(tx_hash: str, address: str, amt_matic: float, raw_value: str, ts: str):
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO transactions (hash, address, direction, amount, value_raw, symbol, timestamp)
            VALUES (?, ?, 'IN', ?, ?, 'MATIC', ?)
        """, (tx_hash, address.lower(), amt_matic, raw_value, ts))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()


# =========================================================
# Main Monitor Loop
# =========================================================
def monitor_wallets():
    ensure_schema()

    print("🚀 LISTENER STARTED — Polygon Amoy incoming monitor running...\n")

    while True:
        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT address FROM wallets")
        rows = cur.fetchall()
        conn.close()

        wallets = [r[0] for r in rows if r and r[0]]

        if not wallets:
            print("ℹ️ No wallets yet... waiting.")
            time.sleep(15)
            continue

        for address in wallets:
            print(f"🔍 Checking {address}")

            incoming = fetch_incoming(address)

            for tx in incoming:
                tx_hash = tx.get("tx_hash")
                value_raw = str(tx.get("value", "0"))
                amount_matic = int(value_raw) / 1e18

                # Timestamp
                ts_raw = tx.get("block_signed_at", "")
                timestamp = ts_raw.replace("Z", "") if ts_raw else datetime.utcnow().isoformat()

                # Insert into DB (skip if already inserted)
                insert_transaction(tx_hash, address, amount_matic, value_raw, timestamp)

                # INR Conversion
                inr_price = get_matic_price_in_inr()
                inr_value = amount_matic * inr_price

                # Push Notification
                send_incoming_tx_notification(address, amount_matic, inr_value)

                print(f"✅ Incoming {amount_matic:.6f} MATIC (~₹{inr_value:.2f}) → {address}")

        print("\n⏳ Sleeping 15s...\n")
        time.sleep(15)


# =========================================================
# Run Entry
# =========================================================
if __name__ == "__main__":
    monitor_wallets()
