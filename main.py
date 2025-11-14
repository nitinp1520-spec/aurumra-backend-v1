# ======================================================================
# main.py — Aurumra Wallet Backend (Polygon-ready with new structure)
# Folder structure:
#   app/
#       main.py
#       config/.env
#       services/wallet.py
#       services/notification_service.py
#       secure/
#       database/
# ======================================================================

import os
import json
import time
import logging
import asyncio
import sqlite3
from pathlib import Path
from functools import wraps
from typing import Optional, List, Dict, Any, Tuple, Callable

import httpx
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from argon2 import PasswordHasher, exceptions as argon2_exceptions

# ----------------------------------------------------------------------
# Load environment from /app/config/.env
# ----------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
ENV_PATH = CONFIG_DIR / ".env"
load_dotenv(ENV_PATH)

# ----------------------------------------------------------------------
# Import Wallet & Notification Services
# ----------------------------------------------------------------------
from services.wallet import (
    create_wallet,
    restore_wallet,
    load_wallet,
    send_eth,
    send_erc20,
    send_nft,
    get_nfts,
    CHAINS,
    ERC20_ABI,
    get_w3,
)

# Try to import notification service
try:
    from services.notification_service import (
        register_tokens as _register_tokens,
        broadcast_transaction_notification as _broadcast_tx,
    )
except Exception:
    _register_tokens = None
    _broadcast_tx = None

# ----------------------------------------------------------------------
# App + CORS + Logging
# ----------------------------------------------------------------------
app = FastAPI(
    title="Aurumra Wallet Backend",
    description="Secure multi-chain wallet backend",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------------------------------------------------
# Directories
# ----------------------------------------------------------------------
SECURE_DIR = BASE_DIR / "secure"
SECURE_DIR.mkdir(exist_ok=True)

DATABASE_DIR = BASE_DIR / "database"
DATABASE_DIR.mkdir(exist_ok=True)

LOG_FILE = SECURE_DIR / "aurumra_backend.log"
MASTER_FILE = SECURE_DIR / "master.json"
TX_LOG_FILE = SECURE_DIR / "transactions.json"
WALLET_FILE = SECURE_DIR / "aurumra_wallet.json"
DB_PATH = SECURE_DIR / "aurumra.db"

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("aurumra_backend")

# ----------------------------------------------------------------------
# Env variables
# ----------------------------------------------------------------------
INFURA_KEY = os.getenv("INFURA_KEY", "").strip()
ADMIN_WALLET_COMMON = os.getenv("ADMIN_WALLET_COMMON", "").strip()
POLL_SECONDS = int(os.getenv("INCOMING_POLL_SECONDS", "10"))
POLYGON_USDT_ADDRESS = os.getenv(
    "POLYGON_USDT_ADDRESS",
    "0xC2132D05D31c914a87C6611C10748AEb04B58e8F"
).strip()

COINGECKO_API = (
    "https://api.coingecko.com/api/v3/simple/price"
    "?ids=ethereum,polygon,binancecoin&vs_currencies=usd"
)

# ======================================================================
# SQLite: Aurumra Internal Registry
# ======================================================================
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS wallets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT UNIQUE NOT NULL,
                label TEXT,
                created_at INTEGER NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS seen_incoming (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain TEXT NOT NULL,
                tx_hash TEXT NOT NULL UNIQUE
            )
        """)
        conn.commit()

init_db()

def upsert_wallet_address(address: str, label: Optional[str] = None):
    if not address:
        return
    ts = int(time.time())
    with get_db() as conn:
        conn.execute("""
            INSERT INTO wallets (address, label, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(address) DO UPDATE SET
            label=COALESCE(excluded.label, wallets.label)
        """, (address.lower(), label, ts))
        conn.commit()

def address_exists(address: str) -> bool:
    with get_db() as conn:
        cur = conn.execute("SELECT 1 FROM wallets WHERE address=?", (address.lower(),))
        return cur.fetchone() is not None

def list_tracked_addresses() -> List[str]:
    with get_db() as conn:
        cur = conn.execute("SELECT address FROM wallets")
        return [r[0] for r in cur.fetchall()]

def mark_seen_incoming(chain: str, tx_hash: str) -> bool:
    try:
        with get_db() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO seen_incoming (chain, tx_hash) VALUES (?, ?)",
                (chain, tx_hash),
            )
            conn.commit()
            return cur.rowcount > 0
    except Exception:
        return False

# ======================================================================
# Master Password (Argon2)
# ======================================================================
ph = PasswordHasher()

def set_master_password(password: str) -> str:
    hashed = ph.hash(password)
    MASTER_FILE.write_text(hashed, encoding="utf-8")
    return hashed

def get_hashed_master_password() -> str:
    if not MASTER_FILE.exists():
        raise FileNotFoundError("Master password not set.")
    return MASTER_FILE.read_text().strip()

def verify_master_password(password: str) -> bool:
    try:
        hashed = get_hashed_master_password()
        return ph.verify(hashed, password)
    except Exception:
        return False

# ======================================================================
# Request Models
# ======================================================================
class MasterWalletRequest(BaseModel):
    master_password: str
    wallet_password: str

class RestoreWalletRequest(MasterWalletRequest):
    seed_phrase: str

class CheckBalanceRequest(MasterWalletRequest):
    chain_name: str

class SendRequest(MasterWalletRequest):
    chain_name: str
    to_address: str
    amount: Optional[float] = None
    token_address: Optional[str] = None
    token_id: Optional[int] = None
    type: str = "native"

class TokenInfoRequest(MasterWalletRequest):
    chain_name: str
    token_address: str

class NFTRequest(MasterWalletRequest):
    chain_name: str

class UpdateMasterRequest(BaseModel):
    old_password: str
    new_password: str

class InitMasterBody(BaseModel):
    password: str

class WalletRequest(MasterWalletRequest):
    chain_name: Optional[str] = None

# ======================================================================
# Helpers
# ======================================================================
def success_response(data: dict, message: str = "Success"):
    return {"status": "ok", "message": message, "data": data}

def calculate_service_fee(amount: float, internal: bool):
    if not amount or amount <= 0:
        return 0.0
    rate = 0.0001 if internal else 0.0002
    return round(amount * rate, 18)

def validate_chain_name(chain_name: str):
    if chain_name not in CHAINS:
        raise HTTPException(status_code=400, detail=f"Unsupported chain: {chain_name}")

async def _maybe_call(func, *args, **kwargs):
    if not func: return None
    if asyncio.iscoroutinefunction(func):
        return await func(*args, **kwargs)
    return await asyncio.to_thread(func, *args, **kwargs)

# ======================================================================
# ROUTES
# ======================================================================

@app.get("/")
def root():
    return {"message": "🪙 Aurumra Wallet backend running successfully!"}

@app.post("/initialize_master")
def initialize_master(body: InitMasterBody):
    if MASTER_FILE.exists():
        raise HTTPException(status_code=403, detail="Master password already set.")
    hashed = set_master_password(body.password)
    return success_response({"hash_preview": hashed[:20]}, "Master password initialized")

# ----------------------------------------------------------------------
# Auth decorator
# ----------------------------------------------------------------------
def require_master(param: str = "request"):
    def decorator(fn):
        @wraps(fn)
        async def wrapper(*args, **kw):
            obj = kw.get(param)
            if obj is None:
                for a in args:
                    if hasattr(a, "master_password"):
                        obj = a
                        break
            if not obj or not obj.master_password:
                raise HTTPException(status_code=401, detail="Master password required")

            if not verify_master_password(obj.master_password):
                raise HTTPException(status_code=401, detail="Unauthorized")

            return await fn(*args, **kw)
        return wrapper
    return decorator

# ----------------------------------------------------------------------
# CREATE WALLET
# ----------------------------------------------------------------------
@app.post("/create_wallet")
@require_master("request")
async def api_create(request: MasterWalletRequest):
    wallet = await asyncio.to_thread(create_wallet, request.wallet_password)
    upsert_wallet_address(wallet["address"])
    return success_response(wallet, "Wallet created")

# ----------------------------------------------------------------------
# RESTORE WALLET
# ----------------------------------------------------------------------
@app.post("/restore_wallet")
@require_master("request")
async def api_restore(request: RestoreWalletRequest):
    wallet = await asyncio.to_thread(restore_wallet, request.seed_phrase, request.wallet_password)
    upsert_wallet_address(wallet["address"])
    return success_response(wallet, "Wallet restored")

# ----------------------------------------------------------------------
# RECEIVE ADDRESS
# ----------------------------------------------------------------------
@app.post("/receive")
@require_master("request")
async def api_receive(request: MasterWalletRequest):
    wallet = await asyncio.to_thread(load_wallet, request.wallet_password)
    return success_response({"address": wallet["address"]}, "Receive address fetched")

# ----------------------------------------------------------------------
# CHECK BALANCE
# ----------------------------------------------------------------------
@app.post("/check_balance")
@require_master("request")
async def api_balance(request: CheckBalanceRequest):
    validate_chain_name(request.chain_name)
    wallet = await asyncio.to_thread(load_wallet, request.wallet_password)
    w3, chain = await asyncio.to_thread(get_w3, request.chain_name)
    wei = await asyncio.to_thread(lambda: w3.eth.get_balance(wallet["address"]))
    native = float(w3.from_wei(wei, "ether"))
    return success_response({
        "address": wallet["address"],
        "balance": native,
        "symbol": chain.get("symbol")
    })

# ----------------------------------------------------------------------
# SEND
# ----------------------------------------------------------------------
@app.post("/send")
@require_master("request")
async def api_send(request: SendRequest):
    validate_chain_name(request.chain_name)
    wallet = await asyncio.to_thread(load_wallet, request.wallet_password)
    w3, chain = await asyncio.to_thread(get_w3, request.chain_name)

    internal = address_exists(request.to_address)
    fee_preview = calculate_service_fee(request.amount, internal)

    if request.type == "native":
        tx, net_fee, _, total = await asyncio.to_thread(
            send_eth,
            request.to_address,
            request.amount,
            wallet,
            chain["rpc"],
            chain["chainId"],
            internal,
        )
    elif request.type == "erc20":
        tx, net_fee, _, total = await asyncio.to_thread(
            send_erc20,
            request.token_address,
            request.to_address,
            request.amount,
            wallet,
            chain["rpc"],
            chain["chainId"],
            internal,
        )
    else:
        tx, net_fee, _, total = await asyncio.to_thread(
            send_nft,
            wallet,
            request.chain_name,
            request.to_address,
            request.token_id,
            request.token_address,
            "erc721",
            request.amount or 0.0,
            internal,
        )

    return success_response({
        "tx_hash": tx,
        "network_fee": net_fee,
        "service_fee_preview": fee_preview,
        "total_amount": total
    }, "Transaction sent")

# ----------------------------------------------------------------------
# NFT LIST
# ----------------------------------------------------------------------
@app.post("/nfts")
@require_master("request")
async def api_nfts(request: NFTRequest):
    validate_chain_name(request.chain_name)
    wallet = await asyncio.to_thread(load_wallet, request.wallet_password)
    nft_list = await asyncio.to_thread(get_nfts, wallet["address"], request.chain_name)
    return success_response({"nfts": nft_list})

# ----------------------------------------------------------------------
# TX HISTORY (local)
# ----------------------------------------------------------------------
@app.post("/tx_history")
@require_master("request")
async def tx_history(request: WalletRequest):
    if not TX_LOG_FILE.exists():
        return success_response({"transactions": []})

    try:
        txs = json.loads(TX_LOG_FILE.read_text())
    except:
        txs = []

    if request.chain_name:
        txs = [t for t in txs if t.get("chain") == request.chain_name]

    return success_response({"transactions": txs})

# ----------------------------------------------------------------------
# REGISTER DEVICE (for notifications)
# ----------------------------------------------------------------------
@app.post("/register_device")
async def register_device_api(request: Request):
    body = await request.json()
    tokens = body.get("tokens", [])
    if not tokens:
        return success_response({"registered": 0})
    result = await _maybe_call(_register_tokens, tokens)
    return success_response(result or {}, "Device registered")

# ======================================================================
# Incoming Transfer Detector
# ======================================================================
LAST_BLOCK_FILE = SECURE_DIR / "last_blocks.json"
if not LAST_BLOCK_FILE.exists():
    LAST_BLOCK_FILE.write_text("{}")

def _read_last_blocks():
    try: return json.loads(LAST_BLOCK_FILE.read_text())
    except: return {}

def _write_last_blocks(d):
    LAST_BLOCK_FILE.write_text(json.dumps(d, indent=2))

async def _scan_polygon_once():
    chain_name = "Polygon" if "Polygon" in CHAINS else list(CHAINS.keys())[0]
    w3, chain = get_w3(chain_name)
    tracked = [a.lower() for a in list_tracked_addresses()]
    if not tracked: return

    last = _read_last_blocks()
    start = last.get(chain_name, w3.eth.block_number - 1)
    latest = w3.eth.block_number
    end = min(start + 4, latest)

    for blk in range(start, end + 1):
        try:
            block = w3.eth.get_block(blk, full_transactions=True)
        except:
            continue

        for tx in block.transactions:
            to_addr = (tx.to or "").lower()
            if to_addr in tracked:
                tx_hash = tx.hash.hex()
                if mark_seen_incoming(chain_name, tx_hash):
                    amount = float(w3.from_wei(tx.value, "ether"))
                    log = {
                        "direction": "incoming",
                        "chain": chain_name,
                        "amount": amount,
                        "to": to_addr,
                        "tx_hash": tx_hash,
                        "ts": int(time.time())
                    }
                    if TX_LOG_FILE.exists():
                        try:
                            arr = json.loads(TX_LOG_FILE.read_text())
                        except:
                            arr = []
                    else:
                        arr = []
                    arr.append(log)
                    TX_LOG_FILE.write_text(json.dumps(arr, indent=2))

    last[chain_name] = end + 1
    _write_last_blocks(last)

async def _incoming_loop():
    while True:
        try:
            await _scan_polygon_once()
        except Exception as e:
            logger.error(f"Incoming scan error: {e}")
        await asyncio.sleep(POLL_SECONDS)

@app.on_event("startup")
async def startup():
    asyncio.create_task(_incoming_loop())

# ======================================================================
# ENTRYPOINT
# ======================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
