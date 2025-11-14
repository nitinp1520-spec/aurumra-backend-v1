"""
listener_mainnet.py — Polygon Mainnet incoming tx watcher + Expo push
- Identical behavior to listener_amoy.py but uses Polygon Mainnet CHAIN_ID 137
"""

import os
import time
import logging
from pathlib import Path
import requests
import sqlite3
from datetime import datetime
from dotenv import load_dotenv
from typing import Optional, List, Tuple, Dict, Any

# --- project / config paths (works regardless of current cwd) ---
THIS_FILE = Path(__file__).resolve()
PROJECT_ROOT = THIS_FILE.parents[2]
ENV_PATH = PROJECT_ROOT / "app" / "config" / ".env"
DB_PATH = PROJECT_ROOT / "app" / "database" / "wallet.db"
SECURE_DIR = PROJECT_ROOT / "app" / "secure"
LOG_FILE = SECURE_DIR / "listener_mainnet.log"

SECURE_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("listener_mainnet")

if ENV_PATH.exists():
    load_dotenv(dotenv_path=str(ENV_PATH))
else:
    load_dotenv()

COVALENT_API_KEY = os.getenv("COVALENT_API_KEY", "").strip()
BASE_URL = "https://api.covalenthq.com/v1"
CHAIN_ID = os.getenv("LISTENER_CHAIN_ID", "137")  # default 137 (Polygon Mainnet)
POLL_SECONDS = int(os.getenv("LISTENER_POLL_SECONDS", "15"))
HTTP_TIMEOUT = float(os.getenv("LISTENER_HTTP_TIMEOUT", "20"))

def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_schema() -> None:
    conn = _db_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT UNIQUE,
            encrypted_private_key TEXT,
            wallet_password_hash TEXT,
            created_at TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            wallet_address TEXT PRIMARY KEY,
            expo_token TEXT
        )
    """)
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

def get_expo_token(wallet_address: str) -> Optional[str]:
    conn = _db_conn()
    cur = conn.cursor()
    cur.execute("SELECT expo_token FROM devices WHERE wallet_address = ?", (wallet_address.lower(),))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def send_expo_push(expo_token: str, title: str, body: str, extra: Optional[Dict[str, Any]] = None) -> bool:
    payload = {
        "to": expo_token,
        "sound": "default",
        "title": title,
        "body": body,
        "priority": "high",
    }
    if extra:
        payload["data"] = extra
    try:
        r = requests.post("https://api.expo.dev/v2/push/send", json=payload, timeout=HTTP_TIMEOUT)
        logger.info("Expo push response: %s", r.text)
        return r.status_code == 200
    except Exception as e:
        logger.exception("Expo push failed: %s", e)
        return False

def get_matic_price_in_inr() -> float:
    try:
        r = requests.get("https://api.coinbase.com/v2/prices/MATIC-INR/spot", timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        j = r.json()
        return float(j.get("data", {}).get("amount", 0.0))
    except Exception as e:
        logger.debug("Could not fetch MATIC-INR price: %s", e)
        return 0.0

def fetch_incoming_for_address(address: str) -> List[Dict[str, Any]]:
    if not COVALENT_API_KEY:
        logger.warning("COVALENT_API_KEY not set; skipping fetch.")
        return []
    url = f"{BASE_URL}/{CHAIN_ID}/address/{address}/transactions_v3/"
    params = {"key": COVALENT_API_KEY}
    try:
        r = requests.get(url, params=params, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        j = r.json()
    except Exception as e:
        logger.debug("Covalent request failed for %s: %s", address, e)
        return []
    items = j.get("data", {}).get("items", []) or []
    incoming = [tx for tx in items if tx.get("to_address") and tx["to_address"].lower() == address.lower()]
    return incoming

def insert_tx_record(tx_hash: str, address: str, amount_matic: float, value_raw: str, ts_iso: str) -> None:
    conn = _db_conn()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO transactions (hash, address, direction, amount, value_raw, symbol, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (tx_hash, address.lower(), "IN", float(amount_matic), str(value_raw), "MATIC", ts_iso))
        conn.commit()
        logger.info("Inserted tx %s for %s amount %s", tx_hash, address, amount_matic)
    except sqlite3.IntegrityError:
        logger.debug("Tx already exists (skipping): %s", tx_hash)
    except Exception as e:
        logger.exception("Failed to insert tx: %s", e)
    finally:
        conn.close()

def normalize_timestamp(ts_raw: str) -> str:
    try:
        return ts_raw.replace("Z", "")
    except Exception:
        return datetime.utcnow().isoformat(timespec="seconds")

def monitor_loop() -> None:
    ensure_schema()
    logger.info("Listener (Mainnet) started. Chain ID: %s. Poll interval: %ss", CHAIN_ID, POLL_SECONDS)
    while True:
        try:
            conn = _db_conn()
            cur = conn.cursor()
            cur.execute("SELECT address FROM wallets")
            rows = cur.fetchall()
            conn.close()

            addresses = [r["address"] for r in rows if r and r["address"]]
            if not addresses:
                logger.info("No wallets in DB. Sleeping %s seconds.", POLL_SECONDS)
                time.sleep(POLL_SECONDS)
                continue

            for addr in addresses:
                logger.info("Checking wallet (Mainnet): %s", addr)
                incoming = fetch_incoming_for_address(addr)
                for tx in incoming:
                    tx_hash = tx.get("tx_hash") or tx.get("tx_hash_hex") or tx.get("tx_hash")
                    value_raw = str(tx.get("value", "0")) or str(tx.get("value_quoted", "0"))
                    try:
                        amount = int(value_raw) / 10**18
                    except Exception:
                        amount = float(tx.get("value_quote", 0)) if tx.get("value_quote") else 0.0

                    ts_raw = tx.get("block_signed_at", "")
                    ts = normalize_timestamp(ts_raw) if ts_raw else datetime.utcnow().isoformat(timespec="seconds")

                    insert_tx_record(tx_hash, addr, amount, value_raw, ts)

                    price_inr = get_matic_price_in_inr()
                    inr_value = amount * price_inr if price_inr else 0.0

                    expo_token = get_expo_token(addr)
                    if expo_token:
                        title = "💰 Incoming MATIC (Mainnet)"
                        body = f"{amount:.6f} MATIC received (~₹{round(inr_value,2)})"
                        send_expo_push(expo_token, title, body, extra={"tx_hash": tx_hash, "chain": CHAIN_ID})
                    else:
                        logger.info("No Expo token for %s — skipping push", addr)

                    logger.info("Incoming for %s: %s MATIC (tx %s)", addr, amount, tx_hash)

            logger.debug("Sleeping %s seconds", POLL_SECONDS)
        except Exception as e:
            logger.exception("Unhandled error in monitor loop: %s", e)
        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    print("🚀 Listener Running — Polygon Mainnet (live)")
    logger.info("Starting listener_mainnet.py")
    monitor_loop()
