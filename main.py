import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import base64
import ipaddress
import uuid as uuid_lib
from datetime import datetime, timezone, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

import uvicorn
import httpx
import psutil
import bcrypt
from jose import jwt, JWTError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import aiosqlite
import logging
import logging.config

try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

try:
    import asyncpg
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        }
    },
    "handlers": {"json_console": {"class": "logging.StreamHandler", "formatter": "json"}},
    "root": {"level": "INFO", "handlers": ["json_console"]},
}
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("SulgX")
print("--- APPLICATION IS STARTING ---")
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret_key": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "jwt_algorithm": "HS256",
    "jwt_expire_minutes": 10080,
    "db_path": os.environ.get("DB_PATH", "/data/panel.db"),
    "admin_password": os.environ.get("ADMIN_PASSWORD", "admin"),
    "database_url": os.environ.get("DATABASE_URL", ""),
}

if HAS_POSTGRES:
    ADDRESS_INTEGRITY_ERRORS = (aiosqlite.IntegrityError, asyncpg.exceptions.UniqueViolationError)
else:
    ADDRESS_INTEGRITY_ERRORS = (aiosqlite.IntegrityError,)

db_conn: Optional[aiosqlite.Connection] = None
db_lock = asyncio.Lock()
ENABLE_LOGGING = True
KEEP_ALIVE_INTERVAL = 300
TIMEZONE_OFFSET = 0.0
KEEP_ALIVE_ENABLED = True
KEEP_ALIVE_MODE = "simple"

traffic_buffer_lock = asyncio.Lock()
traffic_buffer = {
    "hourly": defaultdict(int),
    "daily": defaultdict(int),
}

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

_scan_lock = asyncio.Lock()

if CONFIG["database_url"] and HAS_POSTGRES:
    DB_BACKEND = "postgresql"
    pg_pool: Optional[asyncpg.Pool] = None

    async def init_pg():
        global pg_pool
        pg_pool = await asyncpg.create_pool(CONFIG["database_url"], min_size=2, max_size=10)
        async with pg_pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS links (
                    uid TEXT PRIMARY KEY, label TEXT NOT NULL,
                    limit_bytes BIGINT DEFAULT 0, used_bytes BIGINT DEFAULT 0,
                    max_connections INT DEFAULT 0, created_at TEXT NOT NULL,
                    active BOOLEAN DEFAULT TRUE, expires_at TEXT,
                    custom_path TEXT DEFAULT '', custom_sni TEXT DEFAULT '',
                    custom_host TEXT DEFAULT '', custom_fp TEXT DEFAULT 'chrome',
                    color TEXT DEFAULT '#39ff14',
                    flag TEXT DEFAULT '',
                    fragment TEXT DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS hourly_traffic (hour TEXT PRIMARY KEY, bytes BIGINT DEFAULT 0);
                CREATE TABLE IF NOT EXISTS daily_traffic (day TEXT PRIMARY KEY, bytes BIGINT DEFAULT 0);
                CREATE TABLE IF NOT EXISTS custom_addresses (id SERIAL PRIMARY KEY, address TEXT NOT NULL UNIQUE);
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS login_logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    ip TEXT,
                    success BOOLEAN DEFAULT TRUE,
                    user_agent TEXT DEFAULT '',
                    path TEXT DEFAULT ''
                );
            """)
            try:
                await conn.execute("ALTER TABLE links ADD COLUMN IF NOT EXISTS flag TEXT DEFAULT ''")
            except Exception:
                pass
            try:
                await conn.execute("ALTER TABLE links ADD COLUMN IF NOT EXISTS fragment TEXT DEFAULT ''")
            except Exception:
                pass

    async def db_execute(sqlite_q: str, pg_q: str, params: tuple = ()):
        async with pg_pool.acquire() as conn:
            await conn.execute(pg_q, *params)

    async def db_fetchall(sqlite_q: str, pg_q: str, params: tuple = ()) -> list:
        async with pg_pool.acquire() as conn:
            rows = await conn.fetch(pg_q, *params)
            return [dict(r) for r in rows]

    async def db_fetchone(sqlite_q: str, pg_q: str, params: tuple = ()) -> Optional[dict]:
        async with pg_pool.acquire() as conn:
            row = await conn.fetchrow(pg_q, *params)
            return dict(row) if row else None

    async def get_db():
        return None
else:
    DB_BACKEND = "sqlite"

    async def init_db():
        global db_conn
        db_path = CONFIG["db_path"]
        try:
            test_file = os.path.join(os.path.dirname(db_path), ".write_test")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
        except Exception:
            logger.warning(f"Cannot write to {db_path}, falling back to /tmp/panel.db")
            CONFIG["db_path"] = "/tmp/panel.db"
            db_path = "/tmp/panel.db"
        db_conn = await aiosqlite.connect(db_path)
        db_conn.row_factory = aiosqlite.Row
        await db_conn.execute("PRAGMA journal_mode=WAL")
        await db_conn.executescript("""
            CREATE TABLE IF NOT EXISTS links (
                uid TEXT PRIMARY KEY, label TEXT NOT NULL,
                limit_bytes INTEGER DEFAULT 0, used_bytes INTEGER DEFAULT 0,
                max_connections INTEGER DEFAULT 0, created_at TEXT NOT NULL,
                active INTEGER DEFAULT 1, expires_at TEXT,
                custom_path TEXT DEFAULT '', custom_sni TEXT DEFAULT '',
                custom_host TEXT DEFAULT '', custom_fp TEXT DEFAULT 'chrome',
                color TEXT DEFAULT '#39ff14',
                flag TEXT DEFAULT '',
                fragment TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS hourly_traffic (hour TEXT PRIMARY KEY, bytes INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS daily_traffic (day TEXT PRIMARY KEY, bytes INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS custom_addresses (id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT,
                success INTEGER DEFAULT 1,
                user_agent TEXT DEFAULT '',
                path TEXT DEFAULT ''
            );
        """)
        try:
            await db_conn.execute("ALTER TABLE links ADD COLUMN flag TEXT DEFAULT ''")
        except Exception:
            pass
        try:
            await db_conn.execute("ALTER TABLE links ADD COLUMN fragment TEXT DEFAULT ''")
        except Exception:
            pass
        await db_conn.commit()

    async def db_execute(sqlite_q: str, pg_q: str = "", params: tuple = ()):
        async with db_lock:
            await db_conn.execute(sqlite_q, params)
            await db_conn.commit()

    async def db_fetchall(sqlite_q: str, pg_q: str = "", params: tuple = ()) -> list:
        async with db_lock:
            cur = await db_conn.execute(sqlite_q, params)
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def db_fetchone(sqlite_q: str, pg_q: str = "", params: tuple = ()) -> Optional[dict]:
        async with db_lock:
            cur = await db_conn.execute(sqlite_q, params)
            row = await cur.fetchone()
        return dict(row) if row else None

    async def get_db():
        return db_conn

async def flush_traffic_buffer():
    while True:
        await asyncio.sleep(10)
        try:
            async with traffic_buffer_lock:
                if not traffic_buffer["hourly"] and not traffic_buffer["daily"]:
                    continue
                for hour, bytes_val in traffic_buffer["hourly"].items():
                    await db_execute(
                        "INSERT INTO hourly_traffic (hour, bytes) VALUES (?,?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                        "INSERT INTO hourly_traffic (hour, bytes) VALUES ($1,$2) ON CONFLICT (hour) DO UPDATE SET bytes = hourly_traffic.bytes + $2",
                        (hour, bytes_val, bytes_val)
                    )
                for day, bytes_val in traffic_buffer["daily"].items():
                    await db_execute(
                        "INSERT INTO daily_traffic (day, bytes) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                        "INSERT INTO daily_traffic (day, bytes) VALUES ($1,$2) ON CONFLICT (day) DO UPDATE SET bytes = daily_traffic.bytes + $2",
                        (day, bytes_val, bytes_val)
                    )
                traffic_buffer["hourly"].clear()
                traffic_buffer["daily"].clear()
        except Exception as e:
            logger.error(f"flush_traffic_buffer error: {e}", exc_info=True)

async def add_traffic_to_buffer(hour: str, day: str, size: int):
    async with traffic_buffer_lock:
        traffic_buffer["hourly"][hour] += size
        traffic_buffer["daily"][day] += size

async def sync_usage_to_db():
    while True:
        await asyncio.sleep(30)
        try:
            async with LINKS_LOCK:
                for uid, link in LINKS.items():
                    await db_execute(
                        "UPDATE links SET used_bytes = ? WHERE uid = ?",
                        "UPDATE links SET used_bytes = $1 WHERE uid = $2",
                        (link["used_bytes"], uid)
                    )
        except Exception as e:
            logger.error(f"sync_usage_to_db error: {e}", exc_info=True)

async def load_initial_data():
    rows = await db_fetchall("SELECT * FROM links", "SELECT * FROM links")
    async with LINKS_LOCK:
        for r in rows:
            LINKS[r["uid"]] = dict(r)
    addr_rows = await db_fetchall("SELECT address FROM custom_addresses", "SELECT address FROM custom_addresses")
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = [r["address"] for r in addr_rows]
    if not CUSTOM_ADDRESSES:
        CUSTOM_ADDRESSES.append("www.speedtest.net")
    if not LINKS:
        default_uuid = str(uuid_lib.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        default_link = {
            "uid": default_uuid, "label": "This Server is Free", "limit_bytes": 0, "used_bytes": 0,
            "max_connections": 0, "created_at": now, "active": 1, "expires_at": None,
            "custom_path": "", "custom_sni": "", "custom_host": "", "custom_fp": "chrome",
            "color": "#39ff14", "flag": "", "fragment": ""
        }
        async with LINKS_LOCK:
            LINKS[default_uuid] = default_link
        await db_execute(
            "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, flag, fragment) VALUES (?,?,?,?,?,1,?,'','')",
            "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, flag, fragment) VALUES ($1,$2,$3,$4,$5,TRUE,$6,'','')",
            (default_uuid, "This Server is Free", 0, 0, now, None),
        )
    total_usage = sum(link.get("used_bytes", 0) for link in LINKS.values())
    stats["total_bytes"] = total_usage

async def _keepalive_simple_loop():
    global KEEP_ALIVE_INTERVAL, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    while True:
        await asyncio.sleep(KEEP_ALIVE_INTERVAL)
        if not KEEP_ALIVE_ENABLED or KEEP_ALIVE_MODE != "simple":
            continue
        domain = get_domain()
        if domain == "localhost":
            continue
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"https://{domain}/health")
                if resp.status_code == 200:
                    logger.info(f"Simple keep-alive successful: {domain}/health")
        except Exception:
            pass

async def _keepalive_advanced_loop():
    global KEEP_ALIVE_INTERVAL, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    await asyncio.sleep(30)
    while True:
        if not KEEP_ALIVE_ENABLED or KEEP_ALIVE_MODE != "advanced":
            await asyncio.sleep(KEEP_ALIVE_INTERVAL)
            continue
        domain = os.environ.get("DOMAIN", "").strip()
        port = os.environ.get("PORT", "8000")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
        target_urls = []
        if domain:
            if not domain.startswith(("http://", "https://")):
                target_urls.append(f"https://{domain}/login")
                target_urls.append(f"http://{domain}/login")
            else:
                target_urls.append(f"{domain}/login")
        target_urls.append(f"http://127.0.0.1:{port}/login")
        async with httpx.AsyncClient(verify=False, timeout=15.0, headers=headers) as client:
            success = False
            for url in target_urls:
                try:
                    final_url = url + ("&" if "?" in url else "?") + f"_nocache={secrets.token_hex(4)}"
                    resp = await client.get(final_url, follow_redirects=True)
                    if resp.status_code == 200:
                        logger.info(f"Advanced keep-alive successful: {url}")
                        success = True
                        break
                except Exception as e:
                    logger.debug(f"Advanced keep-alive attempt failed for {url}: {e}")
            if not success:
                logger.warning("Advanced keep-alive: all attempts failed.")
        await asyncio.sleep(KEEP_ALIVE_INTERVAL)

async def cleanup_link_cache():
    while True:
        await asyncio.sleep(600)
        now = time.time()
        expired = [k for k, v in link_cache.items() if v["expires"] <= now]
        for k in expired:
            del link_cache[k]

@asynccontextmanager
async def lifespan(app: FastAPI):
    global TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_INTERVAL, KEEP_ALIVE_MODE
    if DB_BACKEND == "postgresql":
        await init_pg()
    else:
        await init_db()
    await load_initial_data()

    sk = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'jwt_secret_key'",
        "SELECT value FROM settings WHERE key = 'jwt_secret_key'"
    )
    if sk:
        CONFIG["secret_key"] = sk["value"]
    else:
        await db_execute(
            "INSERT INTO settings (key, value) VALUES ('jwt_secret_key', ?)",
            "INSERT INTO settings (key, value) VALUES ('jwt_secret_key', $1)",
            (CONFIG["secret_key"],)
        )

    hash_row = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'admin_password_hash'",
        "SELECT value FROM settings WHERE key = 'admin_password_hash'",
    )
    global ADMIN_PASSWORD_HASH
    if hash_row:
        ADMIN_PASSWORD_HASH = hash_row["value"]
    else:
        ADMIN_PASSWORD_HASH = bcrypt.hashpw(CONFIG["admin_password"].encode(), bcrypt.gensalt()).decode()
        await db_execute(
            "INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?)",
            "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1)",
            (ADMIN_PASSWORD_HASH,),
        )

    log_row = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'log_enabled'",
        "SELECT value FROM settings WHERE key = 'log_enabled'"
    )
    global ENABLE_LOGGING
    ENABLE_LOGGING = (log_row and log_row["value"] == "1") if log_row else True

    tz_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='timezone_offset'",
        "SELECT value FROM settings WHERE key='timezone_offset'"
    )
    if tz_row and tz_row["value"]:
        try:
            TIMEZONE_OFFSET = float(tz_row["value"])
        except:
            TIMEZONE_OFFSET = 0.0

    ke_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='keep_alive_enabled'",
        "SELECT value FROM settings WHERE key='keep_alive_enabled'"
    )
    if ke_row and ke_row["value"] is not None:
        KEEP_ALIVE_ENABLED = (ke_row["value"] == "1")

    km_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='keep_alive_mode'",
        "SELECT value FROM settings WHERE key='keep_alive_mode'"
    )
    if km_row and km_row["value"]:
        KEEP_ALIVE_MODE = km_row["value"]

    interval_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='keep_alive_interval'",
        "SELECT value FROM settings WHERE key='keep_alive_interval'"
    )
    if interval_row and interval_row["value"]:
        try:
            KEEP_ALIVE_INTERVAL = max(60, int(interval_row["value"]))
        except:
            pass

    asyncio.create_task(_keepalive_simple_loop())
    asyncio.create_task(_keepalive_advanced_loop())
    asyncio.create_task(cleanup_idle_connections())
    asyncio.create_task(telegram_reporter())
    asyncio.create_task(flush_traffic_buffer())
    asyncio.create_task(sync_usage_to_db())
    asyncio.create_task(auto_disable_expired_links())
    asyncio.create_task(cleanup_link_cache())
    yield
    if DB_BACKEND == "sqlite" and db_conn:
        await db_conn.close()

app = FastAPI(title="SulgX Panel", lifespan=lifespan, docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

connections: dict = {}
connections_lock = asyncio.Lock()
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
    "upload_bytes": 0,
    "download_bytes": 0,
}
error_logs: deque = deque(maxlen=2000)

CACHE_TTL = 60
link_cache: dict = {}

SESSION_COOKIE = "SulgX_session"
UNLIMITED_QUOTA_BYTES = 53687091200000

ADMIN_PASSWORD_HASH: str = ""
ENABLE_LOGGING: bool = True
KEEP_ALIVE_ENABLED: bool = True
KEEP_ALIVE_MODE: str = "simple"

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def create_jwt_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=CONFIG["jwt_expire_minutes"]))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, CONFIG["secret_key"], algorithm=CONFIG["jwt_algorithm"])

def decode_jwt_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, CONFIG["secret_key"], algorithms=[CONFIG["jwt_algorithm"]])
    except JWTError:
        return None

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token or not decode_jwt_token(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def cleanup_idle_connections():
    while True:
        await asyncio.sleep(60)
        now = time.time()
        async with connections_lock:
            idle = [cid for cid, info in connections.items() if now - info.get("last_active", 0) > 300]
        for cid in idle:
            ws = connection_sockets.get(cid)
            if ws:
                try: await ws.close(code=1000, reason="idle timeout")
                except Exception: pass
            async with connections_lock: connections.pop(cid, None)
            connection_sockets.pop(cid, None)

async def auto_disable_expired_links():
    while True:
        await asyncio.sleep(60)
        try:
            row = await db_fetchone("SELECT value FROM settings WHERE key='auto_disable_enabled'", "SELECT value FROM settings WHERE key='auto_disable_enabled'")
            if row and row["value"] != "1":
                continue
            now = datetime.now(timezone.utc)
            async with LINKS_LOCK:
                for uid, link in LINKS.items():
                    if link.get("active") and link.get("expires_at"):
                        exp = parse_expires_at(link["expires_at"])
                        if exp and exp < now:
                            link["active"] = 0
                            await db_execute("UPDATE links SET active = 0 WHERE uid = ?", "UPDATE links SET active = FALSE WHERE uid = $1", (uid,))
                            log_event("Auto", f"Expired inbound {link['label']} auto-disabled")
        except Exception as e:
            logger.error(f"auto_disable_expired_links error: {e}", exc_info=True)

async def telegram_reporter():
    while True:
        interval_hours = 1
        row = await db_fetchone("SELECT value FROM settings WHERE key = 'telegram_interval'", "SELECT value FROM settings WHERE key = 'telegram_interval'")
        if row and row["value"]:
            try: interval_hours = float(row["value"])
            except: interval_hours = 1
        await asyncio.sleep(3600 * interval_hours)
        en_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_report_enabled'", "SELECT value FROM settings WHERE key='telegram_report_enabled'")
        if en_row and en_row["value"] != "1":
            continue
        try:
            token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'", "SELECT value FROM settings WHERE key = 'tg_bot_token'")
            chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'", "SELECT value FROM settings WHERE key = 'tg_chat_id'")
            if token_row and chat_row and token_row["value"] and chat_row["value"]:
                msg = (
                    f"📊 SulgX Panel Stats\n"
                    f"🕒 Uptime: {uptime()}\n"
                    f"🔗 Conns: {len(connections)}\n"
                    f"📦 Traffic: {round(stats['total_bytes']/(1024*1024),2)} MB\n"
                    f"📡 Requests: {stats['total_requests']}\n"
                    f"❌ Errors: {stats['total_errors']}"
                )
                url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(url, json={"chat_id": chat_row["value"], "text": msg})
        except Exception:
            pass

def get_domain() -> str:
    domain = (
        os.environ.get("DOMAIN") or
        os.environ.get("RENDER_EXTERNAL_URL") or
        os.environ.get("RAILWAY_PUBLIC_DOMAIN") or
        "localhost"
    )
    return domain.replace("https://", "").replace("http://", "")

def validate_address(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr.strip('[]'))
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(addr.strip('[]'), strict=False)
        return True
    except ValueError:
        pass
    return re.match(r'^[a-zA-Z0-9\-_.%]+$', addr) is not None

def format_host_port(host: str, port: int = 443) -> str:
    host = host.strip('[]')
    try:
        ipaddress.IPv6Address(host)
        return f"[{host}]:{port}"
    except ipaddress.AddressValueError:
        return f"{host}:{port}"

def code_to_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    code = code.upper()
    try:
        return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
    except:
        return ""

def generate_vless_link(uid: str, remark: str = "SulgX", address: str = None, extra: dict = None) -> str:
    cache_key = f"{uid}:{remark}:{address}:{json.dumps(extra) if extra else ''}"
    if cache_key in link_cache and link_cache[cache_key]["expires"] > time.time():
        return link_cache[cache_key]["link"]
    domain = get_domain()
    addr = address if address else domain
    path = (extra.get("custom_path") or f"/ws/{uid}") if extra else f"/ws/{uid}"
    sni = (extra.get("custom_sni") or domain) if extra else domain
    host = (extra.get("custom_host") or domain) if extra else domain
    fp = (extra.get("custom_fp") or "chrome") if extra else "chrome"
    fragment = extra.get("fragment", "") if extra else ""
    params = {
        "encryption": "none", "security": "tls", "type": "ws",
        "host": host, "path": path, "sni": sni, "fp": fp, "alpn": "http/1.1"
    }
    if fragment:
        params["fragment"] = fragment
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    link = f"vless://{uid}@{format_host_port(addr, 443)}?{query}#{quote(remark)}"
    link_cache[cache_key] = {"link": link, "expires": time.time() + CACHE_TTL}
    return link

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    u = unit.upper()
    if u == "GB": return int(value * 1024**3)
    if u == "MB": return int(value * 1024**2)
    if u == "KB": return int(value * 1024)
    return int(value)

def parse_expires_at(raw: Optional[str]) -> Optional[datetime]:
    if not raw: return None
    try:
        s = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except Exception: return None

def seconds_until_expiry(expires_at_str: Optional[str]) -> Optional[int]:
    exp = parse_expires_at(expires_at_str)
    if exp is None: return None
    return max(0, int((exp - datetime.now(timezone.utc)).total_seconds()))

async def count_connections_for_link(uid: str) -> int:
    async with connections_lock:
        return sum(1 for info in connections.values() if info.get("uuid") == uid)

async def close_connections_for_link(uid: str):
    async with connections_lock:
        to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try: await ws.close(code=1000, reason="link deleted/blocked")
            except Exception: pass
        async with connections_lock: connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    async with connections_lock: link_ip_map.pop(uid, None)

def log_event(etype: str, message: str, ip: str = "", ua: str = ""):
    error_logs.append({
        "time": datetime.now(timezone.utc).isoformat(),
        "type": etype,
        "error": message or "(no detail)",
        "ip": ip,
        "ua": ua,
    })

# ═══ ROUTES ═══

@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {"service": "SulgX Panel", "version": "1.1.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    async with connections_lock: cnt = len(connections)
    return {"status": "ok", "connections": cnt, "uptime": uptime()}

@app.get("/favicon.ico")
async def favicon():
    return Response(content=b"", media_type="image/x-icon", status_code=204)

@app.get("/api/public-settings")
async def public_settings():
    rows = await db_fetchall("SELECT key, value FROM settings WHERE key IN ('footer_text')",
                             "SELECT key, value FROM settings WHERE key IN ('footer_text')")
    result = {}
    for r in rows:
        result[r["key"]] = r["value"]
    return result

@app.post("/api/login")
@limiter.limit("5/minute")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    success = verify_password(password, ADMIN_PASSWORD_HASH)
    asyncio.create_task(log_login(ip, success, user_agent, "/api/login"))
    if not success:
        log_event("Auth", f"Failed login attempt from {ip}", ip, user_agent)
        raise HTTPException(status_code=401, detail="Invalid password")
    log_event("Auth", f"Successful panel login from {ip}", ip, user_agent)
    token = create_jwt_token({"sub": "admin"})
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=CONFIG["jwt_expire_minutes"]*60,
                    httponly=True, samesite="lax", secure=True if get_domain()!="localhost" else False, path="/")
    return resp

async def log_login(ip: str, success: bool, ua: str, path: str):
    if not ENABLE_LOGGING:
        return
    try:
        await db_execute(
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path) VALUES (?,?,?,?,?)",
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path) VALUES ($1,$2,$3,$4,$5)",
            (datetime.now(timezone.utc).isoformat(), ip, 1 if success else 0, ua, path)
        )
        if success:
            await notify_telegram_login(ip, ua)
    except Exception as e:
        logger.error(f"log_login error: {e}")

async def notify_telegram_login(ip: str, ua: str):
    notif_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_notify_enabled'", "SELECT value FROM settings WHERE key='telegram_notify_enabled'")
    if notif_row and notif_row["value"] != "1":
        return
    token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'", "SELECT value FROM settings WHERE key = 'tg_bot_token'")
    chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'", "SELECT value FROM settings WHERE key = 'tg_chat_id'")
    if not token_row or not chat_row or not token_row["value"] or not chat_row["value"]:
        return
    lang = 'en'
    lang_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_lang'", "SELECT value FROM settings WHERE key='telegram_lang'")
    if lang_row and lang_row["value"] == 'fa':
        lang = 'fa'
    templates_key = f'telegram_templates_{lang}'
    tmpl_row = await db_fetchone(f"SELECT value FROM settings WHERE key='{templates_key}'", f"SELECT value FROM settings WHERE key='{templates_key}'")
    templates = {}
    if tmpl_row and tmpl_row["value"]:
        try: templates = json.loads(tmpl_row["value"])
        except: pass
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    if lang == 'fa':
        default_login = f"🔐 ورود SulgX\n🌐 IP: {ip}\n🤖 UA: {ua}\n📅 {now_str}"
    else:
        default_login = f"🔐 SulgX Panel login\n🌐 IP: {ip}\n🤖 UA: {ua}\n📅 {now_str}"
    msg = templates.get('login', default_login)
    msg = msg.replace("{ip}", ip).replace("{ua}", ua).replace("{time}", now_str)
    panel_url = f"https://{get_domain()}/panel"
    msg += f'\n\n<a href="{panel_url}">Open SulgX Panel</a>'
    url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(url, json={"chat_id": chat_row["value"], "text": msg, "parse_mode": "HTML"})
    except Exception:
        pass

@app.post("/api/logout")
async def api_logout(request: Request):
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(_: str = Depends(require_auth)):
    return {"authenticated": True}

@app.post("/api/change-password")
@limiter.limit("3/minute")
async def api_change_password(request: Request, _=Depends(require_auth)):
    global ADMIN_PASSWORD_HASH
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if not verify_password(current, ADMIN_PASSWORD_HASH):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not re.search(r'[A-Z]', new) or not re.search(r'[a-z]', new) or not re.search(r'[0-9]', new):
        raise HTTPException(status_code=400, detail="Password must contain uppercase, lowercase, and digit")
    new_hash = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
    ADMIN_PASSWORD_HASH = new_hash
    await db_execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password_hash', ?)",
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
        (new_hash,),
    )
    log_event("Security", "Admin password changed")
    return {"ok": True}

@app.get("/api/settings")
async def get_settings(_=Depends(require_auth)):
    keys = ['tg_bot_token', 'max_scan_ips', 'tg_chat_id', 'footer_text', 'default_path', 'log_enabled', 'timezone_offset',
            'default_limit_bytes', 'default_expiry_days', 'default_max_connections',
            'telegram_events', 'telegram_interval', 'keep_alive_interval', 'keep_alive_enabled', 'keep_alive_mode',
            'log_max_entries', 'scanner_timeout', 'theme_color',
            'telegram_templates_en', 'telegram_templates_fa', 'telegram_lang', 'default_lang',
            'auto_disable_enabled', 'telegram_report_enabled', 'telegram_notify_enabled',
            'monthly_limit_gb']
    result = {}
    for k in keys:
        row = await db_fetchone("SELECT value FROM settings WHERE key = ?", "SELECT value FROM settings WHERE key = $1", (k,))
        result[k] = row["value"] if row else ""
    return result

@app.post("/api/settings")
async def save_settings(request: Request, _=Depends(require_auth)):
    global ENABLE_LOGGING, TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_INTERVAL, KEEP_ALIVE_MODE
    body = await request.json()
    for k in ('tg_bot_token', 'tg_chat_id', 'max_scan_ips', 'footer_text', 'default_path', 'log_enabled', 'timezone_offset',
              'default_limit_bytes', 'default_expiry_days', 'default_max_connections',
              'telegram_events', 'telegram_interval', 'keep_alive_interval', 'keep_alive_enabled', 'keep_alive_mode',
              'log_max_entries', 'scanner_timeout', 'theme_color',
              'telegram_templates_en', 'telegram_templates_fa', 'telegram_lang', 'default_lang',
              'auto_disable_enabled', 'telegram_report_enabled', 'telegram_notify_enabled',
              'monthly_limit_gb'):
        if k in body:
            val = str(body[k]).strip()
            await db_execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
                (k, val),
            )
    if 'log_enabled' in body:
        ENABLE_LOGGING = body['log_enabled'] == '1'
    if 'keep_alive_enabled' in body:
        KEEP_ALIVE_ENABLED = body['keep_alive_enabled'] == '1'
    if 'keep_alive_mode' in body:
        KEEP_ALIVE_MODE = body['keep_alive_mode']
    if 'keep_alive_interval' in body:
        try:
            KEEP_ALIVE_INTERVAL = max(60, int(body['keep_alive_interval']))
        except:
            pass
    if 'timezone_offset' in body:
        try:
            TIMEZONE_OFFSET = float(body['timezone_offset'])
        except:
            TIMEZONE_OFFSET = 0.0
    return {"ok": True}

@app.post("/api/settings/reset")
@limiter.limit("3/minute")
async def reset_settings(request: Request, _=Depends(require_auth)):
    PROTECTED_KEYS = {'jwt_secret_key', 'admin_password_hash'}
    all_keys = await db_fetchall("SELECT key FROM settings", "SELECT key FROM settings")
    for row in all_keys:
        k = row["key"]
        if k not in PROTECTED_KEYS:
            await db_execute("DELETE FROM settings WHERE key = ?", "DELETE FROM settings WHERE key = $1", (k,))
    global ENABLE_LOGGING, KEEP_ALIVE_INTERVAL, TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    ENABLE_LOGGING = True
    KEEP_ALIVE_INTERVAL = 300
    TIMEZONE_OFFSET = 0.0
    KEEP_ALIVE_ENABLED = True
    KEEP_ALIVE_MODE = "simple"
    log_event("Settings", "All settings reset to defaults")
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    global TIMEZONE_OFFSET
    async with connections_lock: conn_count = len(connections)
    cpu = 0.0
    try:
        cpu = await asyncio.to_thread(psutil.cpu_percent, 0.1)
        if cpu == 0.0:
            try:
                with open('/proc/loadavg', 'r') as f:
                    cpu = float(f.readline().split()[0]) * 10
            except:
                cpu = None
    except:
        try:
            with open('/proc/loadavg', 'r') as f:
                cpu = float(f.readline().split()[0]) * 10
        except:
            cpu = None
    mem_percent = 0
    try: mem_percent = psutil.virtual_memory().percent
    except: pass
    disk_percent = 0; disk_free = 0.0
    try:
        disk = psutil.disk_usage("/")
        disk_percent = disk.percent
        disk_free = round(disk.free / (1024**3), 1)
    except: pass
    now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
    today_str = now.strftime("%Y-%m-%d")
    rows = await db_fetchall(
        "SELECT hour, bytes FROM hourly_traffic WHERE hour LIKE ? ORDER BY hour ASC",
        "SELECT hour, bytes FROM hourly_traffic WHERE hour LIKE $1 ORDER BY hour ASC",
        (today_str + '%',)
    )
    hourly_dict = {f"{h:02d}:00": 0 for h in range(24)}
    for r in rows:
        hour_part = r["hour"][-5:] if len(r["hour"]) >= 5 else r["hour"]
        if hour_part in hourly_dict:
            hourly_dict[hour_part] = r["bytes"]
    async with traffic_buffer_lock:
        for h_key, b_val in traffic_buffer["hourly"].items():
            hour_part = h_key[-5:] if len(h_key) >= 5 else h_key
            if hour_part in hourly_dict:
                hourly_dict[hour_part] += b_val
    sorted_hours = [f"{h:02d}:00" for h in range(24)]
    hourly_data = {h: hourly_dict[h] for h in sorted_hours}
    month_start = now.strftime("%Y-%m") + "-01"
    monthly_bytes = 0
    month_rows = await db_fetchall(
        "SELECT SUM(bytes) as total FROM daily_traffic WHERE day >= ?",
        "SELECT SUM(bytes) as total FROM daily_traffic WHERE day >= $1",
        (month_start,)
    )
    if month_rows and month_rows[0]["total"]:
        monthly_bytes = month_rows[0]["total"]
    monthly_limit = 0
    limit_row = await db_fetchone("SELECT value FROM settings WHERE key='monthly_limit_gb'", "SELECT value FROM settings WHERE key='monthly_limit_gb'")
    if limit_row and limit_row["value"]:
        try: monthly_limit = float(limit_row["value"]) * 1024**3
        except: pass
    return {
        "active_connections": conn_count,
        "total_traffic_mb": round(stats["total_bytes"]/(1024*1024),2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "recent_errors": list(error_logs)[-20:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": cpu,
        "memory_percent": mem_percent,
        "disk_percent": disk_percent,
        "disk_free_gb": disk_free,
        "hourly_traffic": hourly_data,
        "hourly_labels": sorted_hours,
        "upload_bytes": stats["upload_bytes"],
        "download_bytes": stats["download_bytes"],
        "monthly_usage_bytes": monthly_bytes,
        "monthly_limit_bytes": int(monthly_limit),
    }

@app.get("/stats/detailed")
async def get_detailed_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    active = sum(1 for l in links if l["active"])
    inactive = sum(1 for l in links if not l["active"])
    expired = 0
    now = datetime.now(timezone.utc)
    for l in links:
        if l.get("expires_at"):
            exp = parse_expires_at(l["expires_at"])
            if exp and exp < now:
                expired += 1
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_row = await db_fetchone("SELECT bytes FROM daily_traffic WHERE day = ?", "SELECT bytes FROM daily_traffic WHERE day = $1", (today,))
    today_bytes = today_row["bytes"] if today_row else 0
    daily_rows = await db_fetchall("SELECT day, bytes FROM daily_traffic ORDER BY day DESC LIMIT 7",
                                   "SELECT day, bytes FROM daily_traffic ORDER BY day DESC LIMIT 7")
    daily_traffic = {row["day"]: row["bytes"] for row in daily_rows}
    return {
        "total_links": len(links),
        "active_links": active,
        "inactive_links": inactive,
        "expired_links": expired,
        "today_traffic_bytes": today_bytes,
        "daily_traffic": daily_traffic,
    }

@app.get("/api/login-logs")
async def get_login_logs(_=Depends(require_auth)):
    rows = await db_fetchall(
        "SELECT timestamp, ip, success, user_agent, path FROM login_logs ORDER BY timestamp DESC LIMIT 20",
        "SELECT timestamp, ip, success, user_agent, path FROM login_logs ORDER BY timestamp DESC LIMIT 20"
    )
    return {"logs": [dict(r) for r in rows]}

@app.get("/api/logs")
async def get_logs(_=Depends(require_auth)):
    return {"logs": list(error_logs)}

@app.delete("/api/logs/clear")
async def clear_logs(_=Depends(require_auth)):
    error_logs.clear()
    await db_execute("DELETE FROM login_logs", "DELETE FROM login_logs")
    return {"ok": True}

@app.get("/api/logs/size")
async def logs_size(_=Depends(require_auth)):
    total_chars = sum(len(json.dumps(log)) for log in error_logs)
    return {"count": len(error_logs), "size_kb": round(total_chars / 1024, 2)}

@app.get("/api/backup/full")
async def full_backup(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    async with CUSTOM_ADDRESSES_LOCK:
        addrs = list(CUSTOM_ADDRESSES)
    rows = await db_fetchall("SELECT key, value FROM settings", "SELECT key, value FROM settings")
    settings = {r["key"]: r["value"] for r in rows}
    backup = {"links": links, "addresses": addrs, "settings": settings}
    return backup

MAX_RESTORE_SIZE = 5 * 1024 * 1024

@app.post("/api/restore")
async def restore_backup(request: Request, _=Depends(require_auth)):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_RESTORE_SIZE:
        raise HTTPException(status_code=413, detail="Backup file too large")
    body = await request.json()
    if "settings" in body:
        for k, v in body["settings"].items():
            await db_execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
                (k, str(v))
            )
    if "addresses" in body:
        await db_execute("DELETE FROM custom_addresses", "DELETE FROM custom_addresses")
        async with CUSTOM_ADDRESSES_LOCK:
            CUSTOM_ADDRESSES[:] = []
            for a in body["addresses"]:
                addr = str(a).strip()
                if addr and validate_address(addr):
                    CUSTOM_ADDRESSES.append(addr)
                    try:
                        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
                    except ADDRESS_INTEGRITY_ERRORS:
                        pass
    if "links" in body:
        await db_execute("DELETE FROM links", "DELETE FROM links")
        async with LINKS_LOCK:
            LINKS.clear()
        for link in body["links"]:
            uid = link.get("uid") or str(uuid_lib.uuid4())
            label = link.get("label", "Restored")
            limit_bytes = int(link.get("limit_bytes", 0))
            used_bytes = int(link.get("used_bytes", 0))
            max_conn = int(link.get("max_connections", 0))
            created_at = link.get("created_at") or datetime.now(timezone.utc).isoformat()
            active = 1 if link.get("active", True) else 0
            expires_at = link.get("expires_at")
            custom_path = link.get("custom_path", "")
            custom_sni = link.get("custom_sni", "")
            custom_host = link.get("custom_host", "")
            custom_fp = link.get("custom_fp", "chrome")
            color = link.get("color", "#39ff14")
            flag = link.get("flag", "")
            fragment = link.get("fragment", "")
            await db_execute(
                "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
                (uid, label, limit_bytes, used_bytes, max_conn, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment),
            )
            async with LINKS_LOCK:
                LINKS[uid] = {
                    "uid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": used_bytes,
                    "max_connections": max_conn, "created_at": created_at, "active": active,
                    "expires_at": expires_at, "custom_path": custom_path, "custom_sni": custom_sni,
                    "custom_host": custom_host, "custom_fp": custom_fp, "color": color, "flag": flag, "fragment": fragment,
                }
    return {"ok": True}

# ═══ INBOUNDS ═══

@app.post("/api/links")
@limiter.limit("10/minute")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "This Server is Free").strip()[:60]
    uuid_input = (body.get("uuid") or "").strip()
    if not label:
        raise HTTPException(status_code=400, detail="Remark is required")
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Remark must contain only English letters, numbers, and characters: - _ . space")
    if uuid_input:
        try:
            uuid_lib.UUID(uuid_input)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid UUID format")
        uid = uuid_input
    else:
        uid = str(uuid_lib.uuid4())
    async with LINKS_LOCK:
        if uid in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this UUID already exists")
    default_limit = 0
    def_limit_row = await db_fetchone("SELECT value FROM settings WHERE key='default_limit_bytes'", "SELECT value FROM settings WHERE key='default_limit_bytes'")
    if def_limit_row and def_limit_row["value"]:
        default_limit = int(def_limit_row["value"])
    default_expiry_days = 0
    def_exp_row = await db_fetchone("SELECT value FROM settings WHERE key='default_expiry_days'", "SELECT value FROM settings WHERE key='default_expiry_days'")
    if def_exp_row and def_exp_row["value"]:
        default_expiry_days = int(def_exp_row["value"])
    default_max_conn = 0
    def_conn_row = await db_fetchone("SELECT value FROM settings WHERE key='default_max_connections'", "SELECT value FROM settings WHERE key='default_max_connections'")
    if def_conn_row and def_conn_row["value"]:
        default_max_conn = int(def_conn_row["value"])

    limit_val = float(body.get("limit_value") or default_limit)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_val <= 0 else parse_size_to_bytes(limit_val, limit_unit)
    max_conn = int(body.get("max_connections") or default_max_conn)
    if max_conn < 0: max_conn = 0
    days_valid = body.get("days_valid") if body.get("days_valid") is not None else default_expiry_days
    expires_at = None
    try:
        days_valid = int(days_valid)
        if days_valid > 0: expires_at = (datetime.now(timezone.utc) + timedelta(days=days_valid)).isoformat()
    except (ValueError, TypeError): pass
    now = datetime.now(timezone.utc).isoformat()
    custom_path = body.get("custom_path", "")
    custom_sni = body.get("custom_sni", "")
    custom_host = body.get("custom_host", "")
    custom_fp = body.get("custom_fp", "chrome")
    color = body.get("color", "#39ff14")
    flag = body.get("flag", "")
    fragment = body.get("fragment", "")
    if flag:
        flag = flag.strip()[:2]
        if not re.match(r'^[a-zA-Z]{2}$', flag):
            flag = ""
        else:
            flag = flag.upper()
    if fragment:
        fragment = fragment.strip()[:50]
    link_data = {
        "uid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "created_at": now, "active": 1,
        "expires_at": expires_at,
        "custom_path": custom_path, "custom_sni": custom_sni,
        "custom_host": custom_host, "custom_fp": custom_fp, "color": color,
        "flag": flag, "fragment": fragment,
    }
    async with LINKS_LOCK:
        LINKS[uid] = link_data
    await db_execute(
        "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES (?,?,?,?,?,1,?,?,?,?,?,?,?,?)",
        "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES ($1,$2,$3,$4,$5,TRUE,$6,$7,$8,$9,$10,$11,$12,$13)",
        (uid, label, limit_bytes, max_conn, now, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment),
    )
    extra = {"custom_path": custom_path, "custom_sni": custom_sni, "custom_host": custom_host, "custom_fp": custom_fp, "fragment": fragment}
    log_event("Inbound", f"Created inbound {label} ({uid})")
    return {
        "uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "active": True, "created_at": now,
        "expires_at": expires_at, "color": color, "flag": flag, "fragment": fragment,
        "vless_link": generate_vless_link(uid, remark=f"SulgX-{label}", extra=extra),
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    async with LINKS_LOCK:
        items = list(LINKS.values())
    items.sort(key=lambda x: x["created_at"], reverse=True)
    result = []
    for row in items:
        uid = row["uid"]
        extra = {
            "custom_path": row.get("custom_path", ""),
            "custom_sni": row.get("custom_sni", ""),
            "custom_host": row.get("custom_host", ""),
            "custom_fp": row.get("custom_fp", "chrome"),
            "fragment": row.get("fragment", ""),
        }
        result.append({
            "uuid": uid,
            "label": row["label"],
            "limit_bytes": row["limit_bytes"],
            "used_bytes": row["used_bytes"],
            "max_connections": row["max_connections"],
            "active": bool(row["active"]),
            "created_at": row["created_at"],
            "expires_at": row.get("expires_at"),
            "custom_path": extra["custom_path"],
            "custom_sni": extra["custom_sni"],
            "custom_host": extra["custom_host"],
            "custom_fp": extra["custom_fp"],
            "color": row.get("color", "#39ff14"),
            "flag": row.get("flag", ""),
            "fragment": row.get("fragment", ""),
            "current_connections": await count_connections_for_link(uid),
            "vless_link": generate_vless_link(uid, remark=f"SulgX-{row['label']}", extra=extra),
        })
    return {"links": result}

@app.get("/api/export-links")
async def export_links(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    return JSONResponse(content=links)

@app.post("/api/import-links")
async def import_links(request: Request, _=Depends(require_auth)):
    body = await request.json()
    imported = 0
    if not isinstance(body, list):
        raise HTTPException(status_code=400, detail="Expected a list of links")
    for item in body:
        if not isinstance(item, dict):
            continue
        uid_input = item.get("uid") or str(uuid_lib.uuid4())
        try:
            uuid_lib.UUID(uid_input)
        except ValueError:
            continue
        label = item.get("label", "Imported")[:60]
        if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
            continue
        limit_bytes = int(item.get("limit_bytes", 0))
        used_bytes = int(item.get("used_bytes", 0))
        max_conn = int(item.get("max_connections", 0))
        created_at = item.get("created_at") or datetime.now(timezone.utc).isoformat()
        active = 1 if item.get("active", True) else 0
        expires_at = item.get("expires_at")
        custom_path = item.get("custom_path", "")
        custom_sni = item.get("custom_sni", "")
        custom_host = item.get("custom_host", "")
        custom_fp = item.get("custom_fp", "chrome")
        color = item.get("color", "#39ff14")
        flag = item.get("flag", "")
        fragment = item.get("fragment", "")
        if flag:
            flag = flag.strip()[:2]
            if not re.match(r'^[a-zA-Z]{2}$', flag):
                flag = ""
            else:
                flag = flag.upper()
        async with LINKS_LOCK:
            if uid_input in LINKS:
                continue
            LINKS[uid_input] = {
                "uid": uid_input, "label": label, "limit_bytes": limit_bytes, "used_bytes": used_bytes,
                "max_connections": max_conn, "created_at": created_at, "active": active,
                "expires_at": expires_at, "custom_path": custom_path, "custom_sni": custom_sni,
                "custom_host": custom_host, "custom_fp": custom_fp, "color": color, "flag": flag, "fragment": fragment,
            }
        await db_execute(
            "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
            (uid_input, label, limit_bytes, used_bytes, max_conn, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment),
        )
        imported += 1
    return {"ok": True, "imported": imported}

@app.patch("/api/links/batch")
async def batch_links(request: Request, _=Depends(require_auth)):
    body = await request.json()
    uids = body.get("uids", [])
    action = body.get("action", "")
    async with LINKS_LOCK:
        for uid in uids:
            link = LINKS.get(uid)
            if not link: continue
            if action == "activate":
                link["active"] = 1
                await db_execute("UPDATE links SET active=1 WHERE uid=?", "UPDATE links SET active=TRUE WHERE uid=$1", (uid,))
            elif action == "deactivate":
                link["active"] = 0
                await db_execute("UPDATE links SET active=0 WHERE uid=?", "UPDATE links SET active=FALSE WHERE uid=$1", (uid,))
                await close_connections_for_link(uid)
            elif action == "reset_usage":
                link["used_bytes"] = 0
                await db_execute("UPDATE links SET used_bytes=0 WHERE uid=?", "UPDATE links SET used_bytes=0 WHERE uid=$1", (uid,))
            elif action == "delete":
                if link.get("label") == "This Server is Free":
                    continue
                await db_execute("DELETE FROM links WHERE uid=?", "DELETE FROM links WHERE uid=$1", (uid,))
                LINKS.pop(uid, None)
                await close_connections_for_link(uid)
    return {"ok": True}

@app.post("/api/links/{uid}/new-uuid")
async def regenerate_uuid(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if LINKS[uid].get("label") == "This Server is Free":
            raise HTTPException(status_code=400, detail="Cannot regenerate UUID for the default inbound.")
        new_uid = str(uuid_lib.uuid4())
        while new_uid in LINKS:
            new_uid = str(uuid_lib.uuid4())
        link = LINKS.pop(uid)
        link["uid"] = new_uid
        LINKS[new_uid] = link
        await db_execute("UPDATE links SET uid=? WHERE uid=?", "UPDATE links SET uid=$1 WHERE uid=$2", (new_uid, uid))
        async with connections_lock:
            to_update = [(cid, info) for cid, info in connections.items() if info.get("uuid") == uid]
            for cid, info in to_update:
                info["uuid"] = new_uid
            if uid in link_ip_map:
                link_ip_map[new_uid] = link_ip_map.pop(uid)
        log_event("Inbound", f"UUID regenerated for {link['label']}: {uid} -> {new_uid}")
        return {"new_uuid": new_uid}

@app.post("/api/links/{uid}/disconnect")
async def disconnect_link(uid: str, _=Depends(require_auth)):
    await close_connections_for_link(uid)
    log_event("Inbound", f"Disconnected all connections for {uid}")
    return {"ok": True}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            raise HTTPException(status_code=404, detail="link not found")
        if link.get("label") == "This Server is Free":
            if "label" in body and body["label"].strip() != "This Server is Free":
                raise HTTPException(status_code=400, detail="Cannot rename the default system inbound.")
        if not link:
            raise HTTPException(status_code=404, detail="link not found")
    updates = {}
    if "active" in body: updates["active"] = int(body["active"])
    if "limit_value" in body:
        limit_val = float(body.get("limit_value") or 0)
        unit = body.get("limit_unit") or "GB"
        updates["limit_bytes"] = 0 if limit_val <= 0 else parse_size_to_bytes(limit_val, unit)
    if "reset_usage" in body and body["reset_usage"]:
        updates["used_bytes"] = 0
    if "label" in body:
        new_label = str(body["label"])[:60]
        updates["label"] = new_label
    if "max_connections" in body:
        mc = int(body["max_connections"] or 0)
        updates["max_connections"] = mc if mc >= 0 else 0
    if "days_valid" in body:
        try:
            dv = int(body["days_valid"])
            if dv > 0: updates["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=dv)).isoformat()
            else: updates["expires_at"] = None
        except (ValueError, TypeError): pass
    if "custom_path" in body: updates["custom_path"] = str(body["custom_path"])[:100]
    if "custom_sni" in body: updates["custom_sni"] = str(body["custom_sni"])[:100]
    if "custom_host" in body: updates["custom_host"] = str(body["custom_host"])[:100]
    if "custom_fp" in body: updates["custom_fp"] = str(body["custom_fp"])[:20]
    if "color" in body: updates["color"] = str(body["color"])[:20]
    if "flag" in body:
        flag_val = str(body["flag"]).strip()[:2]
        if not re.match(r'^[a-zA-Z]{2}$', flag_val):
            flag_val = ""
        else:
            flag_val = flag_val.upper()
        updates["flag"] = flag_val
    if "fragment" in body:
        updates["fragment"] = str(body["fragment"]).strip()[:50]
    if updates:
        async with LINKS_LOCK:
            link.update(updates)
        if DB_BACKEND == "sqlite":
            set_str = ", ".join(f"{k} = ?" for k in updates)
            vals = list(updates.values()) + [uid]
            await db_execute(f"UPDATE links SET {set_str} WHERE uid = ?", "", tuple(vals))
        else:
            set_str = ", ".join(f"{k} = ${i+1}" for i, k in enumerate(updates))
            vals = list(updates.values()) + [uid]
            await db_execute("", f"UPDATE links SET {set_str} WHERE uid = ${len(vals)}", tuple(vals))
    log_event("Inbound", f"Updated inbound {uid}")
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link and link.get("label") == "This Server is Free":
            raise HTTPException(status_code=400, detail="Default inbound (This Server is Free) cannot be deleted.")
    await db_execute("DELETE FROM links WHERE uid = ?", "DELETE FROM links WHERE uid = $1", (uid,))
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    log_event("Inbound", f"Deleted inbound {uid}")
    return {"ok": True}

# ═══ ADDRESSES ═══

@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
@limiter.limit("10/minute")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addr = (body.get("address") or "").strip()
    if not addr or not validate_address(addr):
        raise HTTPException(status_code=400, detail="Invalid address format")
    async with CUSTOM_ADDRESSES_LOCK:
        if addr in CUSTOM_ADDRESSES:
            raise HTTPException(status_code=400, detail="Address already exists")
        CUSTOM_ADDRESSES.append(addr)
    try:
        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
    except ADDRESS_INTEGRITY_ERRORS:
        pass
    log_event("Clean IP", f"Added address {addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.patch("/api/addresses/{index}")
async def edit_address(index: int, request: Request, _=Depends(require_auth)):
    body = await request.json()
    new_addr = (body.get("address") or "").strip()
    if not new_addr or not validate_address(new_addr):
        raise HTTPException(status_code=400, detail="Invalid address format")
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            old = CUSTOM_ADDRESSES[index]
            if new_addr in CUSTOM_ADDRESSES and new_addr != old:
                raise HTTPException(status_code=400, detail="Address already exists")
            CUSTOM_ADDRESSES[index] = new_addr
            await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (old,))
            await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (new_addr,))
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    log_event("Clean IP", f"Edited address from {old} to {new_addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses/batch")
@limiter.limit("5/minute")
async def add_addresses_batch(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addresses = body.get("addresses", [])
    added = 0
    errors = 0
    for addr in addresses:
        if isinstance(addr, str):
            addr = addr.strip()
            if not addr or not validate_address(addr):
                errors += 1
                continue
            async with CUSTOM_ADDRESSES_LOCK:
                if addr not in CUSTOM_ADDRESSES:
                    CUSTOM_ADDRESSES.append(addr)
                    try:
                        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
                    except ADDRESS_INTEGRITY_ERRORS:
                        pass
                    added += 1
                else:
                    errors += 1
    if added > 0:
        log_event("Clean IP", f"Batch added {added} addresses")
    return {"ok": True, "added": added, "errors": errors}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            addr = CUSTOM_ADDRESSES.pop(index)
            await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (addr,))
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    log_event("Clean IP", f"Deleted address {addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses")
async def delete_all_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = ["www.speedtest.net"]
    await db_execute("DELETE FROM custom_addresses", "DELETE FROM custom_addresses")
    log_event("Clean IP", "All addresses deleted")
    return {"ok": True}

@app.post("/api/addresses/bulk-delete")
async def bulk_delete_addresses(request: Request, _=Depends(require_auth)):
    body = await request.json()
    indices = body.get("indices", [])
    async with CUSTOM_ADDRESSES_LOCK:
        for idx in sorted(indices, reverse=True):
            if 0 <= idx < len(CUSTOM_ADDRESSES):
                addr = CUSTOM_ADDRESSES.pop(idx)
                await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (addr,))
    log_event("Clean IP", "Bulk deleted addresses")
    return {"ok": True}

# ═══ USER DASHBOARD & SUBSCRIPTION ═══

@app.get("/user/{uid}")
async def user_dashboard(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            raise HTTPException(status_code=404, detail="User not found or disabled")
        link = dict(link)
    expires = parse_expires_at(link.get("expires_at"))
    if expires and expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="User expired")
    status = "Active ✅"
    if link.get("limit_bytes") > 0 and link["used_bytes"] >= link["limit_bytes"]:
        status = "Quota Exceeded 🚫"
    elif expires and expires < datetime.now(timezone.utc):
        status = "Expired ⏰"
    elif not link["active"]:
        status = "Blocked 🔒"
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    usage_percent = 0 if limit == 0 else min(100, round(used / limit * 100, 1))
    usage_bar_color = "#4ade80" if usage_percent < 80 else ("#fbbf24" if usage_percent < 95 else "#f87171")
    vless_link = generate_vless_link(uid, remark=link["label"])
    sub_url = f"https://{get_domain()}/sub/{uid}"
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={quote(sub_url)}"
    expiry_str = "Unlimited ∞" if not expires else expires.strftime("%Y-%m-%d %H:%M (UTC)")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Dashboard | {link['label']}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',sans-serif;background:#0a0a0a;color:#e0e0e0;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}}
.card{{background:rgba(20,20,20,0.9);border:1px solid rgba(57,255,20,0.15);border-radius:24px;padding:36px 24px;max-width:420px;width:100%;box-shadow:0 0 40px rgba(57,255,20,0.1);text-align:center;}}
h1{{color:#39ff14;font-size:1.8rem;margin-bottom:8px;font-weight:800;}}
.subtitle{{color:#a0a0a0;font-size:0.9rem;margin-bottom:24px;}}
.info-box{{background:rgba(255,255,255,0.03);border-radius:16px;padding:16px;margin-bottom:24px;text-align:left;}}
.row{{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.05);font-size:0.95rem;}}
.row:last-child{{border-bottom:none;}}
.label{{color:#888;font-weight:600;}}
.value{{color:#fff;font-weight:600;}}
.progress-bar-bg{{height:8px;background:rgba(255,255,255,0.1);border-radius:4px;margin-top:12px;overflow:hidden;}}
.progress-bar-fill{{height:100%;width:{usage_percent}%;background:{usage_bar_color};border-radius:4px;transition:width 0.3s;}}
.progress-text{{font-size:0.8rem;color:#aaa;margin-top:4px;text-align:right;}}
.qr{{background:#fff;padding:12px;border-radius:16px;display:inline-block;margin-bottom:24px;}}
.qr img{{display:block;border-radius:8px;}}
.btn{{display:flex;align-items:center;justify-content:center;width:100%;padding:14px;background:linear-gradient(135deg,#39ff14,#1a8c1a);color:#000;font-weight:800;border-radius:12px;text-decoration:none;transition:all 0.2s;margin-bottom:12px;border:none;cursor:pointer;font-family:inherit;font-size:1rem;}}
.btn:hover{{filter:brightness(1.1);box-shadow:0 0 20px rgba(57,255,20,0.3);}}
.btn-outline{{background:transparent;color:#39ff14;border:2px solid rgba(57,255,20,0.3);}}
.btn-outline:hover{{background:rgba(57,255,20,0.1);box-shadow:none;}}
#toast{{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#39ff14;color:#000;padding:10px 20px;border-radius:30px;font-weight:700;opacity:0;transition:opacity 0.3s;pointer-events:none;}}
</style>
</head>
<body>
<div class="card">
    <h1>{link['label']}</h1>
    <div class="subtitle">Secure Subscription Dashboard</div>
    <div class="info-box">
        <div class="row"><span class="label">Status</span><span class="value">{status}</span></div>
        <div class="row"><span class="label">Data Usage</span><span class="value">{_fmt_bytes(used)} / {'∞' if limit == 0 else _fmt_bytes(limit)}</span></div>
        <div class="progress-bar-bg"><div class="progress-bar-fill"></div></div>
        <div class="progress-text">{usage_percent}% used</div>
        <div class="row"><span class="label">Expiration</span><span class="value">{expiry_str}</span></div>
    </div>
    <div class="qr">
        <img src="{qr_url}" alt="Scan to Import" width="200" height="200">
    </div>
    <button class="btn" onclick="copyToClip('{sub_url}', 'Subscription Link Copied!')">🔗 Copy Subscription Link</button>
    <button class="btn btn-outline" onclick="copyToClip('{vless_link}', 'VLESS Link Copied!')">📋 Copy Single VLESS Link</button>
</div>
<div id="toast">Copied!</div>
<script>
function copyToClip(text, msg) {{
    navigator.clipboard.writeText(text).then(() => {{
        const toast = document.getElementById('toast');
        toast.innerText = msg;
        toast.style.opacity = '1';
        setTimeout(() => toast.style.opacity = '0', 2500);
    }});
}}
</script>
</body>
</html>"""
    return HTMLResponse(content=html)

@app.get("/user/{uid}/sub")
@limiter.limit("10/minute")
async def user_subscription(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            raise HTTPException(status_code=404, detail="link not found or disabled")
        link = dict(link)
    expires = parse_expires_at(link.get("expires_at"))
    if expires and expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="link expired")
    status = "active"
    if link.get("limit_bytes") > 0 and link["used_bytes"] >= link["limit_bytes"]:
        status = "quota_exceeded"
    elif expires and expires < datetime.now(timezone.utc):
        status = "expired"
    elif not link["active"]:
        status = "blocked"
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    extra = {
        "custom_path": link.get("custom_path", ""),
        "custom_sni": link.get("custom_sni", ""),
        "custom_host": link.get("custom_host", ""),
        "custom_fp": link.get("custom_fp", "chrome"),
        "fragment": link.get("fragment", ""),
    }
    sub_content = generate_subscription_content(link, uid, addresses, extra, status)
    encoded = base64.b64encode(sub_content.encode()).decode()
    total_bytes = link["limit_bytes"] if link["limit_bytes"] > 0 else UNLIMITED_QUOTA_BYTES
    expire_ts = int(expires.timestamp()) if expires else 0
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": 'attachment; filename="sub.txt"',
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={total_bytes}; expire={expire_ts}",
        "X-Status": status,
    }
    log_event("Subscription", f"Subscription accessed for {link['label']} ({uid}) status={status}", ip=request.client.host)
    return Response(content=encoded, headers=headers)

@app.get("/sub/{uid}")
@limiter.limit("10/minute")
async def subscription_endpoint(uid: str, request: Request):
    return await user_subscription(uid, request)

def generate_subscription_content(link: dict, uid: str, addresses: list, extra: dict = None, status: str = "active") -> str:
    used = link["used_bytes"]; limit = link["limit_bytes"]
    usage_str = f"{_fmt_bytes(used)} / ∞" if limit == 0 else f"{_fmt_bytes(used)} / {_fmt_bytes(limit)}"
    secs_left = seconds_until_expiry(link.get("expires_at"))
    expiry_str = "∞" if secs_left is None else ("Expired" if secs_left == 0 else f"{secs_left//86400} Days Left")
    status_remark = ""
    if status == "quota_exceeded":
        status_remark = "🚫 Quota Exceeded"
    elif status == "expired":
        status_remark = "⏰ Expired"
    elif status == "blocked":
        status_remark = "🔒 Blocked"
    full_remark = f"📊 {usage_str} | ⏳ {expiry_str}"
    if status_remark:
        full_remark += f" | {status_remark}"
    flag_emoji = code_to_flag(link.get("flag", ""))
    if flag_emoji:
        full_remark = flag_emoji + " " + full_remark
    status_node = generate_vless_link(uid, remark=full_remark, address="0.0.0.0", extra=extra)
    server_node = generate_vless_link(uid, remark=f"{flag_emoji}This Service is Free" if flag_emoji else "This Service is Free", extra=extra)
    links = [status_node, server_node]
    for i, addr in enumerate(addresses):
        links.append(generate_vless_link(uid, remark=f"{flag_emoji}SulgX-{link['label']}-IP{i+1}" if flag_emoji else f"SulgX-{link['label']}-IP{i+1}", address=addr, extra=extra))
    return "\n".join(links)

def _fmt_bytes(b: int) -> str:
    if b >= 1_073_741_824: return f"{b/1_073_741_824:.1f}GB"
    if b >= 1_048_576: return f"{b/1_048_576:.1f}MB"
    return f"{b/1024:.1f}KB"

# ═══ SCANNER ═══

@app.websocket("/ws/scanner")
async def scanner_ws(websocket: WebSocket):
    await websocket.accept()
    tasks = []
    try:
        data = await websocket.receive_json()
        items = data.get("ips", [])
        if not isinstance(items, list) or len(items) == 0:
            await websocket.close()
            return
        max_ips = 256
        max_row = await db_fetchone("SELECT value FROM settings WHERE key='max_scan_ips'", "SELECT value FROM settings WHERE key='max_scan_ips'")
        if max_row and max_row["value"]:
            try: max_ips = int(max_row["value"])
            except: pass
        if len(items) > max_ips:
            await websocket.send_json({"done": True, "error": f"Maximum {max_ips} IPs allowed."})
            return
        timeout_str = "4"
        row = await db_fetchone("SELECT value FROM settings WHERE key='scanner_timeout'", "SELECT value FROM settings WHERE key='scanner_timeout'")
        if row and row["value"]:
            timeout_str = row["value"]
        try:
            timeout = float(timeout_str)
            if timeout <= 0: timeout = 4
        except:
            timeout = 4
        sem = asyncio.Semaphore(20)
        async def scan_one(item):
            async with sem:
                ip_str = str(item).strip()
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                        await websocket.send_json({"ip": ip_str, "ok": False, "latency": None})
                        return
                except ValueError:
                    pass
                try:
                    start = time.time()
                    try:
                        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                            resp = await client.get(f"https://{ip_str}:443", follow_redirects=True)
                        latency = round((time.time() - start) * 1000)
                        result = {"ip": ip_str, "ok": True, "latency": latency}
                    except:
                        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip_str, 443), timeout=timeout)
                        latency = round((time.time() - start) * 1000)
                        writer.close()
                        result = {"ip": ip_str, "ok": True, "latency": latency}
                except Exception:
                    result = {"ip": ip_str, "ok": False, "latency": None}
                await websocket.send_json(result)
        tasks = [asyncio.create_task(scan_one(item)) for item in items]
        await asyncio.gather(*tasks)
        await websocket.send_json({"done": True})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Scanner WS error: {e}")
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"Scanner WS: {e}", "type": "Scanner"})
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        try:
            await websocket.close()
        except Exception:
            pass

# ═══ TUNNEL ═══

RELAY_BUF = 512 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24: 
        raise ValueError("VLESS header chunk too small for parsing")
    pos = 1 + 16
    addon_len = first_chunk[pos]
    pos += 1 + addon_len
    if len(first_chunk) < pos + 3:
        raise ValueError("Malformed VLESS header structure")
    command = first_chunk[pos]
    pos += 1
    port = int.from_bytes(first_chunk[pos:pos+2], "big")
    pos += 2
    addr_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        if len(first_chunk) < pos + 4: 
            raise ValueError("Incomplete IPv4 address bytes")
        addr_bytes = first_chunk[pos:pos+4]
        pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        if len(first_chunk) < pos + 1: 
            raise ValueError("Missing domain name length indicator")
        domain_len = first_chunk[pos]
        pos += 1
        if len(first_chunk) < pos + domain_len: 
            raise ValueError("Incomplete domain name bytes")
        address = first_chunk[pos:pos+domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        if len(first_chunk) < pos + 16: 
            raise ValueError("Incomplete IPv6 address bytes")
        addr_bytes = first_chunk[pos:pos+16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else: 
        raise ValueError(f"Unsupported VLESS address type identifier: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            return False
        if link["limit_bytes"] == 0:
            return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            link = LINKS[uid]
            link["used_bytes"] += n
            limit = link["limit_bytes"]
            if limit > 0 and link["used_bytes"] >= limit * 0.9 and (link["used_bytes"] - n) < limit * 0.9:
                log_event("Warning", f"Inbound {link['label']} ({uid}) has used over 90% of quota")
                await notify_telegram_event("quota_90", link["label"], uid)
            elif limit > 0 and link["used_bytes"] >= limit * 0.8 and (link["used_bytes"] - n) < limit * 0.8:
                log_event("Warning", f"Inbound {link['label']} ({uid}) has used over 80% of quota")

async def notify_telegram_event(event: str, label: str, uid: str):
    notif_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_notify_enabled'", "SELECT value FROM settings WHERE key='telegram_notify_enabled'")
    if notif_row and notif_row["value"] != "1":
        return
    token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'", "SELECT value FROM settings WHERE key = 'tg_bot_token'")
    chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'", "SELECT value FROM settings WHERE key = 'tg_chat_id'")
    if not token_row or not chat_row or not token_row["value"] or not chat_row["value"]:
        return
    lang = 'en'
    lang_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_lang'", "SELECT value FROM settings WHERE key='telegram_lang'")
    if lang_row and lang_row["value"] == 'fa':
        lang = 'fa'
    templates_key = f'telegram_templates_{lang}'
    tmpl_row = await db_fetchone(f"SELECT value FROM settings WHERE key='{templates_key}'", f"SELECT value FROM settings WHERE key='{templates_key}'")
    templates = {}
    if tmpl_row and tmpl_row["value"]:
        try: templates = json.loads(tmpl_row["value"])
        except: pass
    if lang == 'fa':
        default_msg = f"رویداد: {event} برای {label}"
    else:
        default_msg = f"Event: {event} for {label}"
    msg = templates.get(event, default_msg)
    msg = msg.replace("{label}", label).replace("{uid}", uid)
    panel_url = f"https://{get_domain()}/panel"
    msg += f'\n\n<a href="{panel_url}">Open SulgX Panel</a>'
    url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(url, json={"chat_id": chat_row["value"], "text": msg, "parse_mode": "HTML"})
    except: pass

async def ws_to_tcp(websocket, writer, conn_id, link_uid):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                log_event("Tunnel", f"Quota exceeded for {link_uid}")
                break
            stats["total_bytes"] += size; stats["upload_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
            local_now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
            hour = local_now.strftime("%Y-%m-%d %H:00")
            day = local_now.strftime("%Y-%m-%d")
            await add_traffic_to_buffer(hour, day, size)
            await add_usage(link_uid, size)
            try:
                writer.write(data); await writer.drain()
            except Exception: break
    except WebSocketDisconnect: pass
    except Exception as e:
        logger.error(f"ws_to_tcp error {conn_id}: {e}", exc_info=True)
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"ws_to_tcp {conn_id}: {e}", "type": "Tunnel"})
    finally:
        try:
            if writer and not writer.is_closing(): writer.write_eof()
        except Exception: pass

async def tcp_to_ws(websocket, reader, conn_id, link_uid):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                log_event("Tunnel", f"Quota exceeded for {link_uid}")
                break
            stats["total_bytes"] += size; stats["download_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
            local_now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
            hour = local_now.strftime("%Y-%m-%d %H:00")
            day = local_now.strftime("%Y-%m-%d")
            await add_traffic_to_buffer(hour, day, size)
            await add_usage(link_uid, size)
            try:
                await websocket.send_bytes((b"\x00\x00" + data) if first else data)
                first = False
            except Exception: break
    except Exception as e:
        logger.error(f"tcp_to_ws error {conn_id}: {e}", exc_info=True)
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"tcp_to_ws {conn_id}: {e}", "type": "Tunnel"})

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    logger.info(f"WS accepted {uuid}")
    writer = None; conn_id = None; client_ip = get_client_ip(websocket)
    try:
        async with LINKS_LOCK:
            link = LINKS.get(uuid)
            if not link or not link["active"]:
                await websocket.close(code=1008, reason="not found or disabled")
                log_event("Tunnel", f"Inactive/not found uuid {uuid}", ip=client_ip)
                return
            max_conn = link.get("max_connections", 0)
        expires = parse_expires_at(link.get("expires_at"))
        if expires and expires < datetime.now(timezone.utc):
            await websocket.close(code=1008, reason="expired")
            log_event("Tunnel", f"Expired uuid {uuid}", ip=client_ip)
            return
        if max_conn > 0:
            if await count_connections_for_link(uuid) >= max_conn:
                await websocket.close(code=1008, reason="connection limit")
                log_event("Tunnel", f"Connection limit reached for {uuid}", ip=client_ip)
                return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        try: command, address, port, initial_payload = await parse_vless_header(first_chunk)
        except ValueError as e:
            logger.warning(f"Invalid VLESS header from {client_ip}: {e}")
            await websocket.close(code=1008, reason="invalid header")
            log_event("Tunnel", f"Invalid header from {client_ip}: {e}")
            return
        conn_id = secrets.token_urlsafe(8)
        now = time.time()
        async with connections_lock:
            connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now(timezone.utc).isoformat(), "bytes": 0, "last_active": now}
            connection_sockets[conn_id] = websocket
            link_ip_map[uuid].add(client_ip)
        stats["total_requests"] += 1
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size; stats["upload_bytes"] += p_size
            await add_usage(uuid, p_size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        sock = writer.get_extra_info('socket')
        if sock: sock.setsockopt(6, 1, 1)
        if initial_payload:
            try: writer.write(initial_payload); await writer.drain()
            except Exception: pass
        up_task = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        down_task = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({up_task, down_task}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel(); await t
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"Tunnel {uuid}: {exc}", "type": "WebSocket"})
        logger.exception("WS error")
    finally:
        if writer:
            try: writer.close(); await writer.wait_closed()
            except Exception: pass
        if conn_id:
            async with connections_lock:
                info = connections.pop(conn_id, None)
                connection_sockets.pop(conn_id, None)
                if info:
                    uid = info.get("uuid"); ip = info.get("ip")
                    if uid and ip:
                        if not any(c.get("uuid")==uid and c.get("ip")==ip for c in connections.values()):
                            if uid in link_ip_map:
                                link_ip_map[uid].discard(ip)
                                if not link_ip_map[uid]: link_ip_map.pop(uid, None)

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded: return forwarded.split(",")[0].strip()
    if websocket.client: return websocket.client.host
    return "unknown"

# ── HTML Panel v1.1.0 ───────────────────────────────────────────────
PANEL_HTML = r"""<!DOCTYPE html><!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>SulgX Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --primary:#22c55e; --primary-light:#4ade80; --primary-dim:rgba(34,197,94,0.14);
  --bg:#0a0a0d; --bg2:#0f0f14; --bg3:#17171f;
  --surface:#121218; --surface2:#15151d; --surface3:#1b1b25;
  --sidebar:#0c0c11;
  --border:rgba(255,255,255,0.07); --border2:rgba(34,197,94,0.3);
  --text:#f2f2f5; --text2:#9a9aa8; --text3:#6b6b78;
  --green:#22c55e; --red:#f87171; --yellow:#fbbf24; --blue:#60a5fa;
  --sidebar-w:220px; --topbar-h:64px; --footer-h:44px;
  --radius:18px; --radius-sm:12px;
  --shadow:0 10px 30px rgba(0,0,0,0.45);
}
body.light-mode{
  --bg:#f3f4f8; --bg2:#ffffff; --bg3:#eceef4;
  --surface:#ffffff; --surface2:#ffffff; --surface3:#f0f1f6;
  --sidebar:#141824;
  --border:rgba(0,0,0,0.08); --border2:rgba(34,197,94,0.35);
  --text:#14141c; --text2:#5a5a68; --text3:#8b8b98;
  --shadow:0 10px 30px rgba(0,0,0,0.08);
}
body.blue-mode{
  --primary:#3b82f6; --primary-light:#93bbfc; --primary-dim:rgba(59,130,246,0.16);
  --bg:#070b14; --bg2:#0c1220; --bg3:#121a2c;
  --surface:#0e1524; --surface2:#111a2c; --surface3:#182338;
  --sidebar:#080d18;
  --border:rgba(59,130,246,0.14); --border2:rgba(59,130,246,0.35);
  --text:#e7edf7; --text2:#8fa0bd; --text3:#5f6f8c;
}
html,body{height:100%;overflow-x:hidden}
body{font-family:'Vazirmatn','Inter',sans-serif;color:var(--text);background:var(--bg);transition:background .3s,color .3s}
body[dir="ltr"]{font-family:'Inter','Vazirmatn',sans-serif}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--primary);border-radius:10px}
a{text-decoration:none;color:inherit}
button,input,select,textarea{font-family:inherit}

/* ===== LOGIN ===== */
#login-page{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;background:radial-gradient(circle at 30% 20%, rgba(34,197,94,0.08), transparent 60%), var(--bg)}
.login-card{max-width:400px;width:100%;padding:40px 32px;text-align:center;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}
.login-logo{font-size:2rem;font-weight:900;color:var(--primary);margin-bottom:4px}
.login-sub{font-size:0.75rem;color:var(--text3);margin-bottom:24px;letter-spacing:2px}

/* ===== APP SHELL ===== */
#dashboard-page{display:flex;min-height:100vh}
.sidebar{width:var(--sidebar-w);flex-shrink:0;background:var(--sidebar);border-inline-start:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;bottom:0;inset-inline-end:0;z-index:150;transition:transform .3s}
body[dir="rtl"] .sidebar{border-inline-start:1px solid var(--border);border-left:none}
.sidebar-brand{display:flex;align-items:center;gap:10px;padding:20px 18px;border-bottom:1px solid var(--border)}
.brand-avatar{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--primary),var(--primary-light));display:flex;align-items:center;justify-content:center;font-weight:900;color:#04140a;font-size:1rem}
.brand-name{font-weight:800;font-size:1.05rem;color:var(--text)}
.sidebar-nav{flex:1;padding:14px 12px;display:flex;flex-direction:column;gap:4px;overflow-y:auto}
.side-link{display:flex;align-items:center;gap:10px;padding:11px 14px;border-radius:var(--radius-sm);color:var(--text3);font-size:0.85rem;font-weight:600;background:none;border:none;cursor:pointer;text-align:inherit;width:100%;transition:all .2s}
.side-link .ic{font-size:1.05rem;width:20px;text-align:center}
.side-link:hover{background:var(--surface3);color:var(--text)}
.side-link.active{background:var(--primary-dim);color:var(--primary)}
.sidebar-foot{padding:14px 16px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:8px}
.sidebar-close{display:none}

.app-content{flex:1;margin-inline-end:var(--sidebar-w);display:flex;flex-direction:column;min-height:100vh}
.topbar{height:var(--topbar-h);display:flex;align-items:center;justify-content:space-between;padding:0 22px;border-bottom:1px solid var(--border);position:sticky;top:0;background:rgba(10,10,13,0.85);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);z-index:90}
body.light-mode .topbar{background:rgba(255,255,255,0.85)}
.topbar-left{display:flex;align-items:center;gap:10px}
.topbar-right{display:flex;align-items:center;gap:10px}
.status-pill{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:20px;background:var(--primary-dim);color:var(--primary);font-weight:700;font-size:0.8rem}
.status-pill .dot{width:7px;height:7px;border-radius:50%;background:var(--primary);box-shadow:0 0 8px var(--primary)}
.page-title-top{font-size:1.1rem;font-weight:800;color:var(--text)}
.icon-btn{width:38px;height:38px;border-radius:11px;background:var(--surface3);border:1px solid var(--border);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:1rem;transition:all .2s}
.icon-btn:hover{color:var(--primary);border-color:var(--primary)}
.hamburger{display:none}
.lang-switch{display:flex;gap:3px;background:var(--surface3);border-radius:10px;padding:3px}
.lang-btn{padding:5px 11px;border:none;background:transparent;color:var(--text3);font-size:0.72rem;font-weight:700;border-radius:7px;cursor:pointer}
.lang-btn.active{background:var(--primary);color:#04140a}

.main{flex:1;padding:22px;max-width:1400px;width:100%;margin:0 auto}
.page{display:none;animation:fadeUp .35s ease}
.page.active{display:block}
@keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.page-header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px}
.page-title{font-size:1.4rem;font-weight:800;color:var(--text)}
.page-sub{font-size:0.85rem;color:var(--text3);margin-top:2px}

/* ===== STAT CARDS (matches reference: label small top, big number below) ===== */
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:16px}
.stat-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:20px 22px;transition:all .25s}
.stat-card:hover{border-color:var(--border2);transform:translateY(-2px)}
.stat-label{font-size:0.8rem;color:var(--text3);font-weight:600;margin-bottom:10px}
.stat-val{font-size:1.7rem;font-weight:800;color:var(--text);font-variant-numeric:tabular-nums}
.stat-unit{font-size:0.8rem;font-weight:500;color:var(--text3);margin-inline-start:4px}

.card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:16px}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:10px}
.card-title{font-size:1rem;font-weight:700;color:var(--text)}
.chart-wrap{height:200px;width:100%}

/* ===== BUTTONS ===== */
.btn{font-size:0.83rem;font-weight:700;border-radius:11px;padding:9px 18px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:all .2s}
.btn-primary{background:var(--primary);color:#04140a}
.btn-primary:hover{background:var(--primary-light)}
.btn-outline{background:var(--surface3);color:var(--text);border:1px solid var(--border)}
.btn-outline:hover{border-color:var(--primary);color:var(--primary)}
.btn-danger{background:rgba(248,113,113,0.12);color:var(--red);border:1px solid rgba(248,113,113,0.22)}
.btn-danger:hover{background:rgba(248,113,113,0.2)}
.btn-sm{padding:6px 13px;font-size:0.75rem;border-radius:9px}

/* ===== TABLE (clean, matches reference "active cards" table) ===== */
.tbl-wrap{overflow-x:auto}
.tbl{width:100%;border-collapse:collapse;font-size:0.85rem}
.tbl th{text-align:inherit;padding:12px 14px;color:var(--text3);font-weight:600;font-size:0.75rem;border-bottom:1px solid var(--border)}
.tbl td{padding:14px;border-bottom:1px solid var(--border);color:var(--text);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:rgba(255,255,255,0.015)}
.status-text{font-weight:700;font-size:0.82rem}
.status-text.on{color:var(--green)}
.status-text.off{color:var(--text3)}
.pill{display:flex;align-items:center;gap:8px}
.pill-used{font-weight:700;color:var(--text);white-space:nowrap}
.pill-bar{flex:1;height:5px;background:var(--border);border-radius:4px;overflow:hidden;min-width:40px}
.pill-fill{height:100%;border-radius:4px;transition:width .6s}
.pill-lim{color:var(--text3);font-size:0.75rem;white-space:nowrap}
.act-group{display:flex;flex-wrap:wrap;gap:6px}
.pbtn{font-size:0.75rem;font-weight:700;padding:6px 14px;border-radius:9px;cursor:pointer;border:none;transition:all .2s;background:var(--surface3);color:var(--text2)}
.pbtn:hover{filter:brightness(1.15)}
.pbtn.copy{background:#1b2a20;color:var(--primary-light)}
.pbtn.sub{background:#152437;color:var(--blue)}
.pbtn.qr{background:#1e2136;color:#a5b4fc}
.pbtn.edit{background:#332a13;color:var(--yellow)}
.pbtn.del{background:#331617;color:var(--red)}
.toggle{width:40px;height:23px;border-radius:12px;background:var(--surface3);position:relative;cursor:pointer;transition:all .3s;border:1px solid var(--border)}
.toggle::after{content:'';position:absolute;width:16px;height:16px;border-radius:50%;background:var(--text3);top:2px;inset-inline-start:3px;transition:all .3s}
.toggle.on{background:var(--primary);border-color:var(--primary)}
.toggle.on::after{inset-inline-start:20px;background:#04140a}

.fi,.fs{padding:10px 14px;border-radius:var(--radius-sm);border:1px solid var(--border);font-size:0.88rem;outline:none;color:var(--text);background:var(--bg2);transition:all .2s;width:100%}
.fi:focus,.fs:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-dim)}
.fl{font-size:0.75rem;font-weight:700;color:var(--text2);margin-bottom:5px;display:block}
.fg{display:flex;flex-direction:column;gap:4px;margin-bottom:14px}
.chip-group{display:flex;flex-wrap:wrap;gap:6px}
.chip{padding:6px 15px;border-radius:20px;font-size:0.78rem;font-weight:700;color:var(--text3);cursor:pointer;border:1px solid var(--border);background:transparent;transition:all .2s}
.chip:hover{border-color:var(--primary);color:var(--text)}
.chip.active{background:var(--primary);color:#04140a;border-color:var(--primary)}

.mo{position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:300;display:none;align-items:center;justify-content:center;backdrop-filter:blur(10px)}
.mo.show{display:flex}
.mo-box{background:var(--surface2);border:1px solid var(--border2);border-radius:var(--radius);padding:26px;width:100%;max-width:480px;max-height:90vh;overflow-y:auto;box-shadow:var(--shadow);position:relative}
.mo-title{font-size:1.1rem;font-weight:800;color:var(--primary);margin-bottom:16px}
.mo-close{position:absolute;top:12px;inset-inline-end:16px;background:transparent;border:none;color:var(--text3);font-size:1.3rem;cursor:pointer}
.mo-close:hover{color:var(--text)}
.toast{position:fixed;bottom:26px;left:50%;transform:translateX(-50%) translateY(20px);background:var(--surface2);color:var(--text);border:1px solid var(--border2);border-radius:12px;padding:13px 26px;font-size:0.85rem;font-weight:600;opacity:0;transition:all .35s;z-index:999;box-shadow:var(--shadow)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.err{border-color:var(--red)}
.sys-bar{height:6px;background:var(--border);border-radius:4px;overflow:hidden}
.sys-fill{height:100%;border-radius:4px;transition:width .6s}
.glass-btn-group{display:flex;flex-wrap:wrap;gap:4px;background:var(--surface3);padding:4px;border-radius:11px}
.glass-btn{flex:1;min-width:70px;background:transparent;border:none;color:var(--text3);padding:8px 12px;border-radius:8px;cursor:pointer;font-weight:600;font-size:0.8rem}
.glass-btn.active{background:var(--primary);color:#04140a}
.status-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(80px,1fr));gap:8px}
.status-card{padding:12px;border-radius:11px;text-align:center;cursor:pointer;font-weight:700;font-size:0.75rem;border:1px solid var(--border);background:var(--surface3);color:var(--text3)}
.status-card.active{border-color:var(--green);background:rgba(34,197,94,0.08);color:var(--green)}
.status-card .icon{font-size:1.3rem;display:block;margin-bottom:4px}
.footer{height:var(--footer-h);display:flex;align-items:center;justify-content:center;font-size:0.75rem;color:var(--text3);border-top:1px solid var(--border)}
.footer-inner{display:flex;gap:16px;flex-wrap:wrap;justify-content:center}
.footer-inner a{color:var(--primary-light);font-weight:600}
.empty{padding:40px 20px;text-align:center;color:var(--text3)}
.addr-scroll{max-height:280px;overflow-y:auto}
.logs-scroll{max-height:350px;overflow-y:auto}
.scan-scroll{max-height:240px;overflow-y:auto}
.railway-hl{background:rgba(168,85,247,0.2)!important;color:#d8b4fe!important;border:1px solid #a855f7!important}

.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:140}

@media(max-width:900px){
  .sidebar{transform:translateX(100%)}
  body[dir="rtl"] .sidebar{transform:translateX(100%)}
  body[dir="ltr"] .sidebar{transform:translateX(-100%)}
  .sidebar.open{transform:translateX(0)}
  .sidebar.open ~ .sidebar-overlay{display:block}
  .app-content{margin-inline-end:0}
  .hamburger{display:flex}
  .sidebar-close{display:block;background:transparent;border:none;color:var(--text3);font-size:1.3rem;cursor:pointer}
  .stats-grid{grid-template-columns:1fr 1fr}
  .main{padding:16px}
}
@media(max-width:480px){
  .stats-grid{grid-template-columns:1fr}
  .topbar{padding:0 14px}
  .page-title-top{display:none}
}
</style>
</head>
<body dir="rtl">
<div class="toast" id="toast"></div>

<div id="login-page" style="display:none">
  <div class="login-card">
    <div class="login-logo">SulgX</div>
    <div class="login-sub">PANEL v1.1.0</div>
    <div id="login-custom-message" style="margin-bottom:18px;color:var(--text2);font-size:0.9rem"></div>
    <div class="fg"><label class="fl">رمز عبور</label><input class="fi" type="password" id="login-pw" placeholder="••••••••" onkeydown="if(event.key==='Enter')doLogin()"></div>
    <button class="btn btn-primary" onclick="doLogin()" style="width:100%;justify-content:center;padding:13px;margin-top:6px">ورود</button>
    <div id="login-err" style="color:var(--red);font-size:0.85rem;margin-top:10px;display:none">رمز عبور اشتباه است</div>
    <div style="margin-top:20px;display:flex;justify-content:center;gap:16px;font-size:0.85rem">
      <a href="https://github.com/SulgX" target="_blank" style="color:var(--text3)">GitHub</a>
      <a href="https://t.me/SulgX" target="_blank" style="color:var(--text3)">Telegram</a>
    </div>
  </div>
</div>

<div id="dashboard-page" style="display:none">
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-brand">
      <div class="brand-avatar">V</div>
      <div class="brand-name">Vipira</div>
      <button class="sidebar-close" id="sidebar-close-btn" style="margin-inline-start:auto">✕</button>
    </div>
    <nav class="sidebar-nav" id="mainNav">
      <button class="side-link active" data-page="dashboard"><span class="ic">🏠</span><span data-en="Dashboard" data-fa="داشبورد">داشبورد</span></button>
      <button class="side-link" data-page="inbounds"><span class="ic">📡</span><span data-en="Inbounds" data-fa="اینباندها">اینباندها</span></button>
      <button class="side-link" data-page="addresses"><span class="ic">🛡️</span><span data-en="Clean IP" data-fa="آی‌پی تمیز">آی‌پی تمیز</span></button>
      <button class="side-link" data-page="ipscanner"><span class="ic">🔍</span><span data-en="Scanner" data-fa="اسکنر">اسکنر</span></button>
      <button class="side-link" data-page="logs"><span class="ic">📋</span><span data-en="Logs" data-fa="لاگ‌ها">لاگ‌ها</span></button>
      <button class="side-link" data-page="telegram"><span class="ic">🤖</span><span data-en="Telegram" data-fa="ربات">ربات</span></button>
      <button class="side-link" data-page="settings"><span class="ic">⚙️</span><span data-en="Settings" data-fa="تنظیمات">تنظیمات</span></button>
    </nav>
    <div class="sidebar-foot">
      <button class="btn btn-outline btn-sm" onclick="randomInbound()" style="width:100%;justify-content:center" data-en="+ Random" data-fa="+ تصادفی">+ تصادفی</button>
      <button class="btn btn-danger btn-sm" onclick="doLogout()" style="width:100%;justify-content:center" data-en="Logout" data-fa="خروج">خروج</button>
    </div>
  </aside>
  <div class="sidebar-overlay" id="sidebar-overlay"></div>

  <div class="app-content">
    <header class="topbar">
      <div class="topbar-left">
        <button class="hamburger icon-btn" id="hamburger-btn">☰</button>
        <button class="icon-btn" onclick="toggleTheme()" title="Theme">🌙</button>
        <span id="panel-clock" style="font-weight:700;color:var(--primary);font-size:0.85rem"></span>
      </div>
      <div class="topbar-right">
        <span class="status-pill"><span class="dot"></span><span data-en="Active" data-fa="فعال">فعال</span></span>
        <span class="page-title-top" id="topbar-page-title">داشبورد</span>
        <div class="lang-switch">
          <button class="lang-btn lang-fa active" onclick="setLang('fa')">FA</button>
          <button class="lang-btn lang-en" onclick="setLang('en')">EN</button>
        </div>
      </div>
    </header>

    <main class="main">
      <!-- DASHBOARD -->
      <section class="page active" id="page-dashboard">
        <div class="page-header">
          <div><div class="page-title" data-en="Dashboard" data-fa="داشبورد">داشبورد</div><div class="page-sub" id="last-up">—</div></div>
        </div>
        <div class="stats-grid">
          <div class="stat-card"><div class="stat-label" data-en="Requests" data-fa="درخواست‌ها">درخواست‌ها</div><div class="stat-val" id="sv-requests">—</div></div>
          <div class="stat-card"><div class="stat-label" data-en="Uptime" data-fa="آپتایم">آپتایم</div><div class="stat-val" id="sv-uptime" style="font-size:1.4rem">—</div></div>
          <div class="stat-card"><div class="stat-label" data-en="Active Connections" data-fa="اتصالات فعال">اتصالات فعال</div><div class="stat-val" id="sv-activeconn">—</div></div>
          <div class="stat-card"><div class="stat-label" data-en="Total Traffic" data-fa="ترافیک کل">ترافیک کل</div><div class="stat-val" id="sv-traffic">— <span class="stat-unit">MB</span></div></div>
        </div>
        <div class="stats-grid">
          <div class="stat-card"><div class="stat-label" data-en="Download" data-fa="دانلود">دانلود</div><div class="stat-val" id="sv-down-speed" style="font-size:1.15rem">—</div></div>
          <div class="stat-card"><div class="stat-label" data-en="Upload" data-fa="آپلود">آپلود</div><div class="stat-val" id="sv-up-speed" style="font-size:1.15rem">—</div></div>
          <div class="stat-card"><div class="stat-label" data-en="Monthly Usage" data-fa="مصرف ماهانه">مصرف ماهانه</div><div class="stat-val" id="sv-monthly" style="font-size:1.15rem">—</div></div>
          <div class="stat-card"><div class="stat-label" data-en="Disk Free" data-fa="فضای آزاد">فضای آزاد</div><div class="stat-val" id="sv-disk" style="font-size:1.15rem">— <span class="stat-unit">GB</span></div></div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
          <div class="card"><div class="card-header"><span class="card-title" data-en="CPU" data-fa="پردازنده">پردازنده</span><span id="cpu-v" style="font-weight:700;color:var(--primary)">—%</span></div><div class="sys-bar"><div class="sys-fill" id="cpu-b" style="background:var(--primary);width:0%"></div></div></div>
          <div class="card"><div class="card-header"><span class="card-title" data-en="Memory" data-fa="حافظه">حافظه</span><span id="mem-v" style="font-weight:700;color:var(--green)">—%</span></div><div class="sys-bar"><div class="sys-fill" id="mem-b" style="background:var(--green);width:0%"></div></div></div>
        </div>
        <div class="card"><div class="card-header"><span class="card-title" data-en="Hourly Traffic" data-fa="ترافیک ساعتی">ترافیک ساعتی</span></div><div class="chart-wrap"><canvas id="tc"></canvas></div></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
          <div class="card"><div class="card-header"><span class="card-title" data-en="Usage Distribution" data-fa="توزیع مصرف">توزیع مصرف</span></div><div class="chart-wrap"><canvas id="doughnut-chart"></canvas></div></div>
          <div class="card"><div class="card-header"><span class="card-title" data-en="Live Speed" data-fa="سرعت لحظه‌ای">سرعت لحظه‌ای</span></div><div class="chart-wrap"><canvas id="speed-chart"></canvas></div></div>
        </div>
        <div class="card"><div class="card-header"><span class="card-title" data-en="Recent Activity" data-fa="فعالیت اخیر">فعالیت اخیر</span></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th data-en="Time" data-fa="زمان">زمان</th><th data-en="IP / Agent" data-fa="آی‌پی / مرورگر">آی‌پی / مرورگر</th><th data-en="Status" data-fa="وضعیت">وضعیت</th></tr></thead><tbody id="login-logs-tbody"></tbody></table></div></div>
      </section>

      <!-- INBOUNDS -->
      <section class="page" id="page-inbounds">
        <div class="page-header">
          <div><div class="page-title" data-en="Inbounds" data-fa="اینباندها">اینباندها</div><div class="page-sub" data-en="Manage VLESS Configs" data-fa="مدیریت کانفیگ‌های VLESS">مدیریت کانفیگ‌های VLESS</div></div>
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            <button class="btn btn-primary" onclick="showAddMo()">+ <span data-en="Create" data-fa="جدید">جدید</span></button>
            <button class="btn btn-outline btn-sm" onclick="exportLinks()" data-en="Export" data-fa="خروجی">خروجی</button>
            <button class="btn btn-outline btn-sm" onclick="document.getElementById('import-file').click()" data-en="Import" data-fa="ورودی">ورودی</button>
            <input type="file" id="import-file" style="display:none" accept=".json" onchange="importLinks(this)">
          </div>
        </div>
        <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
          <input id="srch" placeholder="جستجو..." oninput="filterLinks()" class="fi" style="flex:1;min-width:120px">
          <div class="chip-group">
            <button class="chip active" data-filter="all" onclick="setFilter('all',this)" data-en="All" data-fa="همه">همه</button>
            <button class="chip" data-filter="active" onclick="setFilter('active',this)" data-en="Active" data-fa="فعال">فعال</button>
            <button class="chip" data-filter="off" onclick="setFilter('off',this)" data-en="Off" data-fa="غیرفعال">غیرفعال</button>
          </div>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
          <button class="btn btn-outline btn-sm" onclick="batchAction('activate')" data-en="Activate" data-fa="فعال‌سازی">فعال‌سازی</button>
          <button class="btn btn-outline btn-sm" onclick="batchAction('deactivate')" data-en="Deactivate" data-fa="غیرفعال‌سازی">غیرفعال‌سازی</button>
          <button class="btn btn-outline btn-sm" onclick="batchAction('reset_usage')" data-en="Reset Usage" data-fa="ریست مصرف">ریست مصرف</button>
          <button class="btn btn-danger btn-sm" onclick="batchAction('delete')" data-en="Delete" data-fa="حذف">حذف</button>
        </div>
        <div class="card" style="padding:0;overflow:hidden">
          <div class="card-header" style="padding:18px 20px 0;margin-bottom:0">
            <span class="card-title" data-en="Active Cards" data-fa="کارت‌های فعال">کارت‌های فعال</span>
          </div>
          <div class="tbl-wrap" style="margin-top:10px"><table class="tbl" id="inbound-table"><thead><tr><th><input type="checkbox" id="select-all" onchange="toggleSelectAll()"></th><th data-en="Name" data-fa="نام" onclick="sortLinks('label')">نام</th><th data-en="Type" data-fa="نوع">نوع</th><th data-en="Usage" data-fa="مصرف" onclick="sortLinks('used_bytes')">مصرف</th><th data-en="Conns" data-fa="اتصال">اتصال</th><th data-en="Expiry" data-fa="انقضا" onclick="sortLinks('expires_at')">انقضا</th><th data-en="Status" data-fa="وضعیت">وضعیت</th><th data-en="Actions" data-fa="عملیات">عملیات</th></tr></thead><tbody id="ltb"></tbody></table></div>
          <div class="empty" id="lempty" style="display:none" data-en="No inbounds found" data-fa="هیچ اینباندی یافت نشد">هیچ اینباندی یافت نشد</div>
        </div>
      </section>

      <!-- ADDRESSES -->
      <section class="page" id="page-addresses">
        <div class="page-header"><div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">آی‌پی تمیز</div></div>
        <div class="card">
          <div class="fg"><label class="fl" data-en="Add Addresses (one per line)" data-fa="افزودن آدرس (هر خط یک آدرس)">افزودن آدرس (هر خط یک آدرس)</label><textarea class="fi" id="batch-addrs" rows="4" placeholder="8.8.8.8&#10;example.com"></textarea></div>
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            <button class="btn btn-primary" onclick="addBatchAddrs()" data-en="Add All" data-fa="افزودن همه">افزودن همه</button>
            <button class="btn btn-danger btn-sm" onclick="deleteAllAddrs()" data-en="Delete All" data-fa="حذف همه">حذف همه</button>
            <button class="btn btn-danger btn-sm" onclick="bulkDeleteAddrs()" data-en="Delete Selected" data-fa="حذف انتخاب‌شده‌ها">حذف انتخاب‌شده‌ها</button>
          </div>
          <div class="addr-scroll" id="addr-list" style="margin-top:14px"></div>
        </div>
      </section>

      <!-- SCANNER -->
      <section class="page" id="page-ipscanner">
        <div class="page-header"><div class="page-title" data-en="IP Scanner" data-fa="اسکنر آی‌پی">اسکنر آی‌پی</div></div>
        <div style="background:rgba(251,191,36,0.08);border:1px solid rgba(251,191,36,0.2);border-radius:var(--radius-sm);padding:12px 16px;margin-bottom:14px;font-size:0.8rem;color:var(--yellow)">
          ⚠️ <span data-en="Safe Scan: Limited to 256 IPs at a time." data-fa="اسکن ایمن: حداکثر ۲۵۶ آی‌پی در هر بار.">اسکن ایمن: حداکثر ۲۵۶ آی‌پی در هر بار.</span>
          <div id="railway-note" style="display:none;margin-top:6px;color:#d8b4fe">ℹ️ <span data-en="For Railway, only Railway-related IPs will work." data-fa="برای Railway فقط آی‌پی‌های مرتبط با آن کار می‌کنند.">برای Railway فقط آی‌پی‌های مرتبط با آن کار می‌کنند.</span></div>
        </div>
        <div class="card">
          <div class="fg"><label class="fl" data-en="Provider" data-fa="ارائه‌دهنده">ارائه‌دهنده</label><div id="provider-btns" class="chip-group"></div></div>
          <div class="fg" id="range-section" style="display:none"><label class="fl" data-en="Ranges" data-fa="بازه‌ها">بازه‌ها</label><div id="range-btns" class="chip-group"></div></div>
          <div class="fg"><label class="fl" data-en="IPs / Domains / CIDR" data-fa="آی‌پی / دامنه / CIDR">آی‌پی / دامنه / CIDR</label><textarea class="fi" id="scan-ips" rows="5" placeholder="8.8.8.8&#10;example.com&#10;192.168.1.0/24"></textarea></div>
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            <button class="btn btn-primary" id="scan-start-btn" onclick="startIPScan()">🔍 <span data-en="Scan (port 443)" data-fa="اسکن (پورت ۴۴۳)">اسکن (پورت ۴۴۳)</span></button>
            <button class="btn btn-danger btn-sm" id="scan-stop-btn" onclick="stopScan()" style="display:none" data-en="Stop" data-fa="توقف">توقف</button>
          </div>
          <div style="display:flex;align-items:center;gap:10px;margin:10px 0"><div class="sys-bar" style="flex:1"><div id="scan-progress" class="sys-fill" style="width:0%;background:var(--primary)"></div></div><span id="progress-text" style="font-size:0.8rem;color:var(--text3)">0%</span></div>
          <div class="scan-scroll"><table class="tbl"><thead><tr><th data-en="Address" data-fa="آدرس">آدرس</th><th data-en="Status" data-fa="وضعیت">وضعیت</th><th data-en="Latency" data-fa="تأخیر">تأخیر</th></tr></thead><tbody id="scan-tbody"></tbody></table></div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px">
            <button class="btn btn-outline btn-sm" onclick="sortBestIPs()" data-en="Sort Best" data-fa="مرتب‌سازی بهترین">مرتب‌سازی بهترین</button>
            <button class="btn btn-outline btn-sm" onclick="copyReachableSorted()" data-en="Copy Reachable" data-fa="کپی موفق‌ها">کپی موفق‌ها</button>
          </div>
        </div>
      </section>

      <!-- LOGS -->
      <section class="page" id="page-logs">
        <div class="page-header"><div class="page-title" data-en="Logs" data-fa="لاگ‌ها">لاگ‌ها</div></div>
        <div style="display:flex;gap:8px;margin-bottom:14px">
          <input id="log-search" placeholder="جستجو در لاگ‌ها..." oninput="filterLogs()" class="fi" style="flex:1">
          <button class="btn btn-outline btn-sm" onclick="clearLogSearch()">✕</button>
        </div>
        <div class="card" style="padding:0;overflow:hidden">
          <div class="logs-scroll"><table class="tbl"><thead><tr><th>#</th><th data-en="Time (UTC)" data-fa="زمان (UTC)">زمان (UTC)</th><th data-en="Type" data-fa="نوع">نوع</th><th data-en="Event" data-fa="رویداد">رویداد</th></tr></thead><tbody id="logs-tbody"></tbody></table></div>
          <div class="empty" id="logs-empty" style="display:none" data-en="No events recorded" data-fa="رویدادی ثبت نشده">رویدادی ثبت نشده</div>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px">
          <button class="btn btn-outline btn-sm" onclick="fetchLogSize()" data-en="Log Size" data-fa="حجم لاگ">حجم لاگ</button>
          <button class="btn btn-danger btn-sm" onclick="clearLogs()" data-en="Clear Logs" data-fa="پاک‌سازی لاگ‌ها">پاک‌سازی لاگ‌ها</button>
        </div>
      </section>

      <!-- TELEGRAM -->
      <section class="page" id="page-telegram">
        <div class="page-header"><div class="page-title" data-en="Telegram Bot" data-fa="ربات تلگرام">ربات تلگرام</div></div>
        <div class="card">
          <div class="fg"><label class="fl">Bot Token</label><input class="fi" id="tg-token" placeholder="123456:ABC-def..."></div>
          <div class="fg"><label class="fl">Chat ID</label><input class="fi" id="tg-chat-id" placeholder="-100123456789"></div>
          <div class="fg"><label class="fl" data-en="Notify Events" data-fa="رویدادهای اطلاع‌رسانی">رویدادهای اطلاع‌رسانی</label><div style="display:flex;flex-wrap:wrap;gap:8px">
            <label><input type="checkbox" value="quota_90" class="tg-event"> Quota 90%</label>
            <label><input type="checkbox" value="login" class="tg-event"> Login</label>
            <label><input type="checkbox" value="expiry" class="tg-event"> Expiry</label>
            <label><input type="checkbox" value="error" class="tg-event"> Error</label>
          </div></div>
          <div class="fg"><label class="fl" data-en="Report Interval (hours)" data-fa="بازه گزارش (ساعت)">بازه گزارش (ساعت)</label><input class="fi" type="number" id="tg-interval" value="1" min="0.5" step="0.5"></div>
          <div class="fg"><label class="fl" data-en="Telegram Language" data-fa="زبان تلگرام">زبان تلگرام</label><div style="display:flex;align-items:center;gap:10px"><div class="toggle on" id="tg-lang-toggle" onpointerdown="toggleTgLang()"></div><span id="tg-lang-label">English</span><input type="hidden" id="tg-lang-hidden" value="en"></div></div>
          <div class="fg"><label class="fl" data-en="Custom Templates (EN)" data-fa="قالب‌های سفارشی (EN)">قالب‌های سفارشی (EN)</label><textarea class="fi" id="tg-templates-en" rows="4">{"quota_90":"⚠️ {label} ({uid}) used 90% of quota","login":"🔐 SulgX Panel login\n🌐 IP: {ip}\n🤖 UA: {ua}\n📅 {time}","expiry":"⏰ {label} expired","error":"❌ Error on {label}: check logs"}</textarea></div>
          <div class="fg"><label class="fl" data-en="Custom Templates (FA)" data-fa="قالب‌های سفارشی (FA)">قالب‌های سفارشی (FA)</label><textarea class="fi" id="tg-templates-fa" rows="4">{"quota_90":"⚠️ {label} ({uid}) ۹۰٪ کوتا","login":"🔐 ورود SulgX\n🌐 IP: {ip}\n🤖 UA: {ua}\n📅 {time}","expiry":"⏰ {label} منقضی شد","error":"❌ خطا در {label}: بررسی شود"}</textarea></div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin:8px 0">
            <button class="btn btn-outline btn-sm" onclick="previewTemplate()" data-en="Preview" data-fa="پیش‌نمایش">پیش‌نمایش</button>
            <div id="tg-preview" style="flex:1;padding:8px;background:var(--surface3);border-radius:var(--radius-sm);font-size:0.85rem;white-space:pre-wrap;min-height:40px"></div>
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            <button class="btn btn-primary" onclick="saveTelegramSettings()" data-en="Save" data-fa="ذخیره">ذخیره</button>
            <button class="btn btn-outline btn-sm" onclick="testTelegram()" data-en="Test" data-fa="تست">تست</button>
          </div>
        </div>
      </section>

      <!-- SETTINGS -->
      <section class="page" id="page-settings">
        <div class="page-header"><div class="page-title" data-en="Settings" data-fa="تنظیمات">تنظیمات</div></div>
        <div class="card">
          <div class="fg"><label class="fl" data-en="Login Text" data-fa="متن ورود">متن ورود</label><input class="fi" id="set-footer" placeholder="Custom login message"></div>
          <div class="fg"><label class="fl" data-en="Default Path" data-fa="مسیر پیش‌فرض">مسیر پیش‌فرض</label><input class="fi" id="set-default-path" placeholder="/ws/{uid}"></div>

          <div class="fg"><label class="fl" data-en="Timezone" data-fa="منطقه زمانی">منطقه زمانی</label>
            <div class="glass-btn-group" id="tz-glass-group">
              <button class="glass-btn active" id="btn-tz-utc" onclick="setPanelTZ(0,'UTC')">UTC (00:00)</button>
              <button class="glass-btn" id="btn-tz-tehran" onclick="setPanelTZ(3.5,'Tehran')">Tehran (+3:30)</button>
              <button class="glass-btn" id="btn-tz-custom" onclick="toggleCustomTZInput(true)" data-en="Custom" data-fa="سفارشی">سفارشی</button>
            </div>
            <div id="custom-tz-container" style="display:none;margin-top:8px"><input class="fi" id="custom-tz-value" placeholder="e.g. +3.5" oninput="applyCustomTZ(this.value)"></div>
          </div>

          <div class="fg"><label class="fl" data-en="Theme" data-fa="پوسته">پوسته</label>
            <div class="glass-btn-group" id="theme-glass-group">
              <button class="glass-btn active" id="btn-theme-dark" onclick="setPanelTheme('dark')">🌙 <span data-en="Dark" data-fa="تیره">تیره</span></button>
              <button class="glass-btn" id="btn-theme-light" onclick="setPanelTheme('light')">☀️ <span data-en="Light" data-fa="روشن">روشن</span></button>
              <button class="glass-btn" id="btn-theme-blue-dark" onclick="setPanelTheme('blue-dark')">🔵 <span data-en="Blue" data-fa="آبی">آبی</span></button>
            </div>
            <input type="hidden" id="set-theme-color" value="dark">
          </div>

          <div class="fg"><label class="fl" data-en="Keep Alive" data-fa="فعال‌نگه‌داشتن">فعال‌نگه‌داشتن</label>
            <div class="glass-btn-group" id="keepalive-mode-group">
              <button class="glass-btn active" id="btn-keepalive-simple" onclick="setKeepAliveMode('simple')" data-en="Simple" data-fa="ساده">ساده</button>
              <button class="glass-btn" id="btn-keepalive-advanced" onclick="setKeepAliveMode('advanced')" data-en="Advanced" data-fa="پیشرفته">پیشرفته</button>
            </div>
            <input type="hidden" id="set-keepalive-mode" value="simple">
            <div class="status-grid" style="margin-top:8px">
              <div class="status-card active" id="card-keepalive" onclick="toggleSettingCard('card-keepalive','set-keepalive-enabled')"><span class="icon">⚡</span><span data-en="Keep-Alive" data-fa="فعال‌نگه‌داشتن">فعال‌نگه‌داشتن</span><input type="hidden" id="set-keepalive-enabled" value="1"></div>
            </div>
            <div class="fg"><label class="fl" data-en="Interval (seconds)" data-fa="بازه (ثانیه)">بازه (ثانیه)</label><input class="fi" type="number" id="set-keep-alive-interval" placeholder="300" min="60"></div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
            <div class="fg"><label class="fl" data-en="Default Limit (GB)" data-fa="سقف پیش‌فرض (GB)">سقف پیش‌فرض (GB)</label><input class="fi" type="number" id="set-default-limit" placeholder="0 = Unlimited"></div>
            <div class="fg"><label class="fl" data-en="Default Expiry (Days)" data-fa="انقضای پیش‌فرض (روز)">انقضای پیش‌فرض (روز)</label><input class="fi" type="number" id="set-default-expiry" placeholder="0 = Unlimited"></div>
            <div class="fg"><label class="fl" data-en="Default Max Conns" data-fa="حداکثر اتصال پیش‌فرض">حداکثر اتصال پیش‌فرض</label><input class="fi" type="number" id="set-default-maxconn" placeholder="0 = Unlimited"></div>
            <div class="fg"><label class="fl" data-en="Scanner Timeout (s)" data-fa="تایم‌اوت اسکنر (ثانیه)">تایم‌اوت اسکنر (ثانیه)</label><input class="fi" type="number" id="set-scanner-timeout" placeholder="4"></div>
            <div class="fg"><label class="fl" data-en="Max Scan IPs" data-fa="حداکثر آی‌پی اسکن">حداکثر آی‌پی اسکن</label><input class="fi" type="number" id="set-max-scan-ips" placeholder="256"></div>
            <div class="fg"><label class="fl" data-en="Monthly Limit (GB)" data-fa="سقف ماهانه (GB)">سقف ماهانه (GB)</label><input class="fi" type="number" id="set-monthly-limit" placeholder="0 = Unlimited"></div>
          </div>

          <div class="fg"><label class="fl" data-en="System Toggles" data-fa="کلیدهای سیستم">کلیدهای سیستم</label>
            <div class="status-grid">
              <div class="status-card active" id="card-log" onclick="toggleSettingCard('card-log','set-log-toggle')"><span class="icon">📝</span><span data-en="Logs" data-fa="لاگ‌ها">لاگ‌ها</span><input type="hidden" id="set-log-toggle" value="1"></div>
              <div class="status-card active" id="card-auto" onclick="toggleSettingCard('card-auto','set-auto-disable')"><span class="icon">🚫</span><span data-en="Auto Disable" data-fa="غیرفعال‌سازی خودکار">غیرفعال خودکار</span><input type="hidden" id="set-auto-disable" value="1"></div>
              <div class="status-card active" id="card-tgrep" onclick="toggleSettingCard('card-tgrep','set-tg-report')"><span class="icon">📊</span><span data-en="TG Reports" data-fa="گزارش تلگرام">گزارش تلگرام</span><input type="hidden" id="set-tg-report" value="1"></div>
              <div class="status-card active" id="card-tgnot" onclick="toggleSettingCard('card-tgnot','set-tg-notify')"><span class="icon">🔔</span><span data-en="TG Alerts" data-fa="هشدار تلگرام">هشدار تلگرام</span><input type="hidden" id="set-tg-notify" value="1"></div>
            </div>
          </div>

          <hr style="border-color:var(--border);margin:16px 0">
          <div class="mo-title" style="margin-bottom:12px" data-en="Change Password" data-fa="تغییر رمز عبور">تغییر رمز عبور</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
            <div class="fg"><label class="fl" data-en="Current Password" data-fa="رمز فعلی">رمز فعلی</label><input class="fi" type="password" id="cpw"></div>
            <div class="fg"><label class="fl" data-en="New Password" data-fa="رمز جدید">رمز جدید</label><input class="fi" type="password" id="npw"></div>
          </div>
          <button class="btn btn-primary btn-sm" onclick="chgPw()" data-en="Update Password" data-fa="به‌روزرسانی رمز">به‌روزرسانی رمز</button>
          <div style="margin-top:16px"><button class="btn btn-primary" onclick="saveGeneralSettings()" style="width:100%;justify-content:center;padding:12px" data-en="Save All Settings" data-fa="ذخیره همه تنظیمات">ذخیره همه تنظیمات</button></div>
          <hr style="border-color:var(--border);margin:16px 0">
          <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
            <button class="btn btn-danger" onclick="resetAllSettings()" data-en="Reset to Defaults" data-fa="بازگشت به پیش‌فرض">بازگشت به پیش‌فرض</button>
            <span style="font-size:0.75rem;color:var(--text3)" data-en="Resets all settings except password." data-fa="همه تنظیمات به‌جز رمز عبور بازنشانی می‌شود.">همه تنظیمات به‌جز رمز عبور بازنشانی می‌شود.</span>
          </div>
        </div>
      </section>
    </main>

    <footer class="footer">
      <div class="footer-inner">
        <span id="footer-dedication"></span>
        <a href="https://t.me/SulgX" target="_blank">Telegram</a>
        <a href="https://github.com/SulgX" target="_blank">GitHub</a>
      </div>
    </footer>
  </div>
</div>

<!-- MODALS (unchanged structure/ids, restyled by CSS above) -->
<div class="mo" id="mo-add"><div class="mo-box"><button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('show')">✕</button>
<div class="mo-title" data-en="Create Inbound" data-fa="ساخت اینباند">ساخت اینباند</div>
<div class="fg"><label class="fl" data-en="Name" data-fa="نام">نام</label><input class="fi" id="nl" placeholder="This Server is Free" maxlength="60"></div>
<div class="fg"><label class="fl" data-en="Flag / Country" data-fa="پرچم / کشور">پرچم / کشور</label>
  <select class="fs" id="flag-select-create" onchange="applyFlagCreate()">
    <option value="">None</option><option value="cn">🇨🇳 China</option><option value="nl">🇳🇱 Netherlands</option>
    <option value="ru">🇷🇺 Russia</option><option value="us">🇺🇸 United States</option><option value="ca">🇨🇦 Canada</option>
    <option value="ir">🇮🇷 Iran</option><option value="de">🇩🇪 Germany</option><option value="gb">🇬🇧 UK</option>
    <option value="it">🇮🇹 Italy</option><option value="fr">🇫🇷 France</option><option value="tr">🇹🇷 Turkey</option>
    <option value="ae">🇦🇪 UAE</option><option value="custom">Custom (2-letter)</option>
  </select>
  <input class="fi" id="flag-custom-create" placeholder="e.g. jp" style="display:none;margin-top:4px" maxlength="2">
  <input type="hidden" id="flag-code-create" value="">
</div>
<div class="fg"><label class="fl">UUID</label><div style="display:flex;gap:6px"><input class="fi" id="auuid" placeholder="Auto-generate" style="flex:1"><button class="btn btn-outline btn-sm" onclick="generateUUID('auuid')">🎲</button></div></div>
<div class="fg"><button class="btn btn-outline btn-sm" onclick="toggleAdv('adv-create')" style="width:100%;justify-content:center" data-en="Advanced Options" data-fa="گزینه‌های پیشرفته">▼ گزینه‌های پیشرفته</button>
  <div id="adv-create" class="adv-section" style="display:none;margin-top:8px">
    <div class="fg"><label class="fl" data-en="Profile" data-fa="پروفایل">پروفایل</label><select class="fs" id="ares-profile" onchange="applyProfileCreate()"><option value="">Custom</option><option value="default">Default</option><option value="youtube">YouTube</option><option value="instagram">Instagram</option><option value="twitter">Twitter</option><option value="tiktok">TikTok</option><option value="whatsapp">WhatsApp</option><option value="telegram">Telegram</option><option value="netflix">Netflix</option><option value="spotify">Spotify</option><option value="google">Google</option></select></div>
    <div class="fg"><label class="fl">Path</label><input class="fi" id="ap" placeholder="/ws/{uid}"></div>
    <div class="fg"><label class="fl">SNI</label><input class="fi" id="asni" placeholder="example.com"></div>
    <div class="fg"><label class="fl">Host</label><input class="fi" id="ahost" placeholder="example.com"></div>
    <div class="fg"><label class="fl" data-en="Fingerprint" data-fa="فینگرپرینت">فینگرپرینت</label><input class="fi" id="afp" placeholder="chrome"></div>
    <div class="fg"><label class="fl" data-en="Fragment" data-fa="فرگمنت">فرگمنت</label><input class="fi" id="afrag" placeholder="e.g. 1000-2000"></div>
  </div>
</div>
<div class="fg"><label class="fl" data-en="Traffic Limit (GB)" data-fa="سقف ترافیک (GB)">سقف ترافیک (GB)</label><input class="fi" type="number" id="nv" min="0" step="0.1" value="0" placeholder="0 = Unlimited"></div>
<div class="fg"><label class="fl" data-en="Max Connections" data-fa="حداکثر اتصال">حداکثر اتصال</label><input class="fi" type="number" id="nc" min="0" value="0" placeholder="0 = Unlimited"></div>
<div class="fg"><label class="fl" data-en="Validity (Days)" data-fa="اعتبار (روز)">اعتبار (روز)</label><input class="fi" type="number" id="nd" min="0" value="0" placeholder="0 = Unlimited"></div>
<div class="fg"><label class="fl" data-en="Color" data-fa="رنگ">رنگ</label><input type="color" id="alink-color" value="#22c55e"></div>
<div style="display:flex;gap:6px;margin-top:12px"><button class="btn btn-primary" onclick="createLink()" style="flex:1" data-en="Create" data-fa="ایجاد">✅ ایجاد</button><button class="btn btn-outline" onclick="document.getElementById('mo-add').classList.remove('show')" data-en="Cancel" data-fa="انصراف">انصراف</button></div>
</div></div>

<div class="mo" id="mo-edit"><div class="mo-box"><button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">✕</button>
<div class="mo-title" id="et" data-en="Edit Inbound" data-fa="ویرایش اینباند">✏️ ویرایش اینباند</div><input type="hidden" id="eu">
<div class="fg"><label class="fl">UUID</label><input class="fi" id="euuid" readonly></div>
<div class="fg"><label class="fl" data-en="Name" data-fa="نام">نام</label><input class="fi" id="en2" maxlength="60"></div>
<div class="fg"><label class="fl" data-en="Flag / Country" data-fa="پرچم / کشور">پرچم / کشور</label>
  <select class="fs" id="flag-select-edit" onchange="applyFlagEdit()">
    <option value="">None</option><option value="cn">🇨🇳 China</option><option value="nl">🇳🇱 Netherlands</option>
    <option value="ru">🇷🇺 Russia</option><option value="us">🇺🇸 United States</option><option value="ca">🇨🇦 Canada</option>
    <option value="ir">🇮🇷 Iran</option><option value="de">🇩🇪 Germany</option><option value="gb">🇬🇧 UK</option>
    <option value="it">🇮🇹 Italy</option><option value="fr">🇫🇷 France</option><option value="tr">🇹🇷 Turkey</option>
    <option value="ae">🇦🇪 UAE</option><option value="custom">Custom (2-letter)</option>
  </select>
  <input class="fi" id="flag-custom-edit" placeholder="e.g. jp" style="display:none;margin-top:4px" maxlength="2">
  <input type="hidden" id="flag-code-edit" value="">
</div>
<div class="fg"><button class="btn btn-outline btn-sm" onclick="toggleAdv('adv-edit')" style="width:100%;justify-content:center" data-en="Advanced Options" data-fa="گزینه‌های پیشرفته">▼ گزینه‌های پیشرفته</button>
  <div id="adv-edit" class="adv-section" style="display:none;margin-top:8px">
    <div class="fg"><label class="fl" data-en="Profile" data-fa="پروفایل">پروفایل</label><select class="fs" id="eres-profile" onchange="applyProfile()"><option value="">Custom</option><option value="default">Default</option><option value="youtube">YouTube</option><option value="instagram">Instagram</option><option value="twitter">Twitter</option><option value="tiktok">TikTok</option><option value="whatsapp">WhatsApp</option><option value="telegram">Telegram</option><option value="netflix">Netflix</option><option value="spotify">Spotify</option><option value="google">Google</option></select></div>
    <div class="fg"><label class="fl">Path</label><input class="fi" id="ep"></div>
    <div class="fg"><label class="fl">SNI</label><input class="fi" id="esni"></div>
    <div class="fg"><label class="fl">Host</label><input class="fi" id="ehost"></div>
    <div class="fg"><label class="fl" data-en="Fingerprint" data-fa="فینگرپرینت">فینگرپرینت</label><input class="fi" id="efp"></div>
    <div class="fg"><label class="fl" data-en="Fragment" data-fa="فرگمنت">فرگمنت</label><input class="fi" id="efrag"></div>
  </div>
</div>
<div class="fg"><label class="fl" data-en="Traffic Limit (GB)" data-fa="سقف ترافیک (GB)">سقف ترافیک (GB)</label><input class="fi" type="number" id="el" min="0" step="0.1" placeholder="0 = Unlimited"></div>
<div class="fg"><label class="fl" data-en="Max Connections" data-fa="حداکثر اتصال">حداکثر اتصال</label><input class="fi" type="number" id="ec" min="0" placeholder="0 = Unlimited"></div>
<div class="fg"><label class="fl" data-en="Validity (Days)" data-fa="اعتبار (روز)">اعتبار (روز)</label><input class="fi" type="number" id="ed" min="0" placeholder="0 = Unlimited"></div>
<div class="fg"><label class="fl" data-en="Color" data-fa="رنگ">رنگ</label><input type="color" id="e-color" value="#22c55e"></div>
<div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:12px">
  <button class="btn btn-primary" onclick="saveEdit()" style="flex:1" data-en="Save" data-fa="ذخیره">💾 ذخیره</button>
  <button class="btn btn-outline btn-sm" onclick="resetTraf()" data-en="Reset Traffic" data-fa="ریست ترافیک">ریست ترافیک</button>
  <button class="btn btn-outline" onclick="document.getElementById('mo-edit').classList.remove('show')" data-en="Cancel" data-fa="انصراف">انصراف</button>
</div>
</div></div>

<div class="mo" id="mo-qr"><div class="mo-box" style="max-width:340px"><button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">✕</button>
<div class="mo-title" data-en="QR Code" data-fa="کد QR">کد QR</div><div style="text-align:center;padding:16px;background:var(--surface3);border-radius:var(--radius-sm)"><img id="qr-img" src="" alt="QR" style="max-width:200px;border-radius:8px"></div>
<button class="btn btn-primary" onclick="dlQR()" style="width:100%;justify-content:center;margin-top:10px" data-en="Download" data-fa="دانلود">⬇️ دانلود</button>
</div></div>

<div class="mo" id="mo-addr-edit"><div class="mo-box"><button class="mo-close" onclick="document.getElementById('mo-addr-edit').classList.remove('show')">✕</button>
<div class="mo-title" data-en="Edit Address" data-fa="ویرایش آدرس">ویرایش آدرس</div>
<div class="fg"><label class="fl" data-en="New Address" data-fa="آدرس جدید">آدرس جدید</label><input class="fi" id="edit-addr-input"></div>
<button class="btn btn-primary" onclick="saveAddrEdit()" style="width:100%;justify-content:center;margin-top:8px" data-en="Save" data-fa="ذخیره">💾 ذخیره</button>
</div></div>

<script>
const $=s=>document.querySelector(s),$m=id=>document.getElementById(id);
function esc(s){return String(s).replace(/&/g,'&').replace(/</g,'<').replace(/>/g,'>').replace(/"/g,'"').replace(/'/g,'&#39;')}
let lang=localStorage.getItem('ll')||'fa',theme=localStorage.getItem('theme')||'dark';
let allLinks=[],cf='all',sData={},tChart=null,allAddrs=[],isAuthenticated=false;
let prevUploadBytes=null,prevDownloadBytes=null,prevStatsTime=null;
let timezoneOffset=0,editingAddrIndex=-1,selectedUids=new Set(),selectedAddrIndices=new Set();
let uploadSpeedAvg=0,downloadSpeedAvg=0;
const footerTexts={en:'Dedicated to the people of my homeland Iran from <a href="https://github.com/SulgX" target="_blank">SulgX</a>',fa:'تقدیم به مردم سرزمینم ایران از طرف <a href="https://github.com/SulgX" target="_blank">SulgX</a>'};
const pageTitleWords={dashboard:{en:'Dashboard',fa:'داشبورد'},inbounds:{en:'Inbounds',fa:'اینباندها'},addresses:{en:'Clean IP',fa:'آی‌پی تمیز'},ipscanner:{en:'Scanner',fa:'اسکنر'},logs:{en:'Logs',fa:'لاگ‌ها'},telegram:{en:'Telegram',fa:'ربات'},settings:{en:'Settings',fa:'تنظیمات'}};

function setLang(l){lang=l;document.querySelectorAll('.lang-en,.lang-fa').forEach(e=>e.classList.remove('active'));document.querySelectorAll(`.lang-${l}`).forEach(e=>e.classList.add('active'));document.body.dir=l==='fa'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l)||el.getAttribute('data-en');if(v)el.textContent=v;});localStorage.setItem('ll',l);const footer=$m('footer-dedication');if(footer)footer.innerHTML=footerTexts[l]||footerTexts['en'];const activePage=document.querySelector('.side-link.active')?.dataset.page||'dashboard';const tt=$m('topbar-page-title');if(tt&&pageTitleWords[activePage])tt.textContent=pageTitleWords[activePage][l];if(isAuthenticated){loadLoginLogs();loadLogs();renderAddrs();filterLinks();}}
function setTheme(t){theme=t;document.body.classList.toggle('light-mode',t==='light');document.body.classList.toggle('blue-mode',t==='blue-dark');localStorage.setItem('theme',t);if(tChart)updChartColors();syncGlassThemeButtons();}
function toggleTheme(){const themes=['dark','light','blue-dark'];const idx=themes.indexOf(theme);setTheme(themes[(idx+1)%themes.length]);}
function syncGlassThemeButtons(){document.querySelectorAll('#theme-glass-group .glass-btn').forEach(b=>b.classList.remove('active'));const btn=$m(`btn-theme-${theme}`);if(btn)btn.classList.add('active');}
function setPanelTheme(th){document.querySelectorAll('#theme-glass-group .glass-btn').forEach(b=>b.classList.remove('active'));const btn=$m(`btn-theme-${th}`);if(btn)btn.classList.add('active');const hidden=$m('set-theme-color');if(hidden)hidden.value=th;setTheme(th);localStorage.setItem('theme',th);}
function setPanelTZ(offset,name){document.querySelectorAll('#tz-glass-group .glass-btn').forEach(b=>b.classList.remove('active'));if(name==='Tehran')$m('btn-tz-tehran').classList.add('active');else if(name==='UTC')$m('btn-tz-utc').classList.add('active');else if(name==='Custom')$m('btn-tz-custom').classList.add('active');toggleCustomTZInput(false);timezoneOffset=offset;localStorage.setItem('timezone_offset',offset);saveSingleSetting('timezone_offset',offset);}
function toggleCustomTZInput(show){const container=$m('custom-tz-container');const customBtn=$m('btn-tz-custom');if(show){document.querySelectorAll('#tz-glass-group .glass-btn').forEach(b=>b.classList.remove('active'));customBtn.classList.add('active');container.style.display='block';}else{container.style.display='none';}}
function applyCustomTZ(val){let parsed=parseFloat(val);if(!isNaN(parsed)){timezoneOffset=parsed;localStorage.setItem('timezone_offset',parsed);saveSingleSetting('timezone_offset',parsed);}}
function saveSingleSetting(key,value){fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({[key]:value})});}
function setKeepAliveMode(mode){document.querySelectorAll('#keepalive-mode-group .glass-btn').forEach(b=>b.classList.remove('active'));$m(`btn-keepalive-${mode}`).classList.add('active');var el=$m('set-keepalive-mode');if(el)el.value=mode;}
function toggleSettingCard(cardId,inputId){const card=$m(cardId);const input=$m(inputId);if(card.classList.contains('active')){card.classList.remove('active');card.classList.add('inactive');input.value='0';}else{card.classList.remove('inactive');card.classList.add('active');input.value='1';}}
function updateSettingsStatus(settings){if(!settings)return;const setCard=(cardId,enabled)=>{const card=$m(cardId);if(card){card.classList.toggle('active',enabled);card.classList.toggle('inactive',!enabled);}};setCard('card-log',settings.log_enabled==='1');setCard('card-auto',settings.auto_disable_enabled==='1');setCard('card-tgrep',settings.telegram_report_enabled==='1');setCard('card-tgnot',settings.telegram_notify_enabled==='1');$m('set-log-toggle').value=settings.log_enabled==='1'?'1':'0';$m('set-auto-disable').value=settings.auto_disable_enabled==='1'?'1':'0';$m('set-tg-report').value=settings.telegram_report_enabled==='1'?'1':'0';$m('set-tg-notify').value=settings.telegram_notify_enabled==='1'?'1':'0';setCard('card-keepalive',settings.keep_alive_enabled==='1');$m('set-keepalive-enabled').value=settings.keep_alive_enabled==='1'?'1':'0';}
function toast(msg,err=false){const t=$m('toast');t.textContent=msg;t.className='toast'+(err?' err':'')+' show';clearTimeout(t._hide);t._hide=setTimeout(()=>t.classList.remove('show'),3000);}
function fmtB(b){if(!b||b===0)return'0 B';return b>=1073741824?(b/1073741824).toFixed(2)+' GB':b>=1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB';}
function fmtLim(b){if(!b||b===0)return'∞';const g=b/1073741824;return(g%1===0?g.toFixed(0):g.toFixed(1))+' GB';}
function fmtExp(ea){if(!ea||ea===0)return'∞';const d=new Date(ea)-new Date();if(d<=0)return'Expired';const days=Math.floor(d/86400000);if(days>0)return days+'d';const hours=Math.floor(d/3600000);if(hours>0)return hours+'h';return Math.floor(d/60000)+'m';}
function codeToFlag(code){if(!code||code.length!==2)return'';code=code.toUpperCase();return String.fromCodePoint(0x1F1E6+code.charCodeAt(0)-65)+String.fromCodePoint(0x1F1E6+code.charCodeAt(1)-65);}
function getLocalTimeString(){const d=new Date();d.setMinutes(d.getMinutes()+d.getTimezoneOffset()+timezoneOffset*60);return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;}
function formatSpeed(bps){if(bps<1024)return bps.toFixed(1)+' B/s';const kbps=bps/1024;if(kbps<1024)return kbps.toFixed(1)+' KB/s';const mbps=kbps/1024;return mbps.toFixed(2)+' MB/s';}
function safeSetText(id,text){const el=$m(id);if(el)el.textContent=text;}
function safeSetHTML(id,html){const el=$m(id);if(el)el.innerHTML=html;}

async function checkAuth(){try{const r=await fetch('/api/me');if((await r.json()).authenticated){await showDashboard();}else{showLogin();}}catch{showLogin();}}
function showLogin(){isAuthenticated=false;$m('login-page').style.display='flex';$m('dashboard-page').style.display='none';fetch('/api/public-settings').then(r=>r.json()).then(d=>{if(d.footer_text)$m('login-custom-message').textContent=d.footer_text;}).catch(()=>{});}
async function showDashboard(){isAuthenticated=true;$m('login-page').style.display='none';$m('dashboard-page').style.display='flex';await loadGeneralSettings();initChart();initDoughnutChart();initSpeedChart();loadStats();loadLinks();loadAddrs();loadLogs();loadLoginLogs();buildProviderPills();loadTelegramSettings();setLang(lang);startPanelClock();syncGlassThemeButtons();}
function startPanelClock(){setInterval(()=>{const d=new Date();d.setMinutes(d.getMinutes()+d.getTimezoneOffset()+timezoneOffset*60);$m('panel-clock').textContent=d.toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit'});},1000);}
async function doLogin(){const pw=$m('login-pw').value;$m('login-err').style.display='none';try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});if(r.ok){$m('login-pw').value='';showDashboard();}else $m('login-err').style.display='block';}catch{$m('login-err').style.display='block';}}
async function doLogout(){await fetch('/api/logout',{method:'POST'});showLogin();}
function switchPage(id){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));$m('page-'+id).classList.add('active');document.querySelectorAll('.side-link').forEach(n=>n.classList.toggle('active',n.dataset.page===id));const tt=$m('topbar-page-title');if(tt&&pageTitleWords[id])tt.textContent=pageTitleWords[id][lang];closeSidebar();}
function openSidebar(){$m('sidebar').classList.add('open');}
function closeSidebar(){$m('sidebar').classList.remove('open');}
document.getElementById('hamburger-btn')?.addEventListener('click',openSidebar);
document.getElementById('sidebar-close-btn')?.addEventListener('click',closeSidebar);
document.getElementById('sidebar-overlay')?.addEventListener('click',closeSidebar);
document.getElementById('mainNav')?.addEventListener('click',e=>{const b=e.target.closest('.side-link');if(b)switchPage(b.dataset.page);});

async function loadStats(){try{const r=await fetch('/stats');if(r.status===401){showLogin();return;}if(!r.ok)return;sData=await r.json();const now=Date.now();if(prevUploadBytes===null||prevDownloadBytes===null){prevUploadBytes=sData.upload_bytes;prevDownloadBytes=sData.download_bytes;prevStatsTime=now;safeSetHTML('sv-down-speed','0 B/s');safeSetHTML('sv-up-speed','0 B/s');}else{const intervalSec=(now-prevStatsTime)/1000;if(intervalSec>0){let rawUpload=(sData.upload_bytes-prevUploadBytes)/intervalSec;let rawDownload=(sData.download_bytes-prevDownloadBytes)/intervalSec;if(sData.active_connections===0){rawUpload=0;rawDownload=0;uploadSpeedAvg=0;downloadSpeedAvg=0;}else{uploadSpeedAvg=rawUpload*0.3+uploadSpeedAvg*0.7;downloadSpeedAvg=rawDownload*0.3+downloadSpeedAvg*0.7;}safeSetHTML('sv-down-speed',formatSpeed(downloadSpeedAvg));safeSetHTML('sv-up-speed',formatSpeed(uploadSpeedAvg));updSpeedChart(uploadSpeedAvg,downloadSpeedAvg);}prevUploadBytes=sData.upload_bytes;prevDownloadBytes=sData.download_bytes;prevStatsTime=now;}safeSetHTML('sv-traffic',(sData.total_traffic_mb||0)+' <span class="stat-unit">MB</span>');safeSetText('sv-requests',sData.total_requests);safeSetText('sv-uptime',sData.uptime);safeSetText('sv-activeconn',sData.active_connections);safeSetHTML('sv-disk',(sData.disk_free_gb||0)+' <span class="stat-unit">GB</span>');safeSetText('last-up',(lang==='fa'?'به‌روزرسانی: ':'Updated ')+getLocalTimeString());if(sData.cpu_percent!==undefined&&sData.cpu_percent!==null){const c=sData.cpu_percent;safeSetText('cpu-v',c.toFixed(1)+'%');const bar=$m('cpu-b');if(bar)bar.style.width=c+'%';}else{safeSetText('cpu-v','N/A');const bar=$m('cpu-b');if(bar)bar.style.width='0%';}if(sData.memory_percent!==undefined){const m=sData.memory_percent;safeSetText('mem-v',m.toFixed(1)+'%');const bar=$m('mem-b');if(bar)bar.style.width=m+'%';}const monthlyUsageGB=sData.monthly_usage_bytes?sData.monthly_usage_bytes/1e9:0;const monthlyLimitGB=sData.monthly_limit_bytes?sData.monthly_limit_bytes/1e9:0;safeSetHTML('sv-monthly',monthlyUsageGB.toFixed(1)+' GB'+(monthlyLimitGB>0?' / '+monthlyLimitGB.toFixed(1)+' GB':''));updChart();updDoughnutChart();}catch(err){console.error('loadStats error:',err);}}
async function loadLinks(){try{const r=await fetch('/api/links');if(r.status===401){showLogin();return;}if(!r.ok)return;const d=await r.json();allLinks=d.links||[];filterLinks();}catch(e){console.error('loadLinks error:',e);}}
function setFilter(f,el){cf=f;document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));el.classList.add('active');filterLinks();}
function filterLinks(){const q=($m('srch')?.value||'').toLowerCase();let r=allLinks;if(cf==='active')r=r.filter(l=>l.active);else if(cf==='off')r=r.filter(l=>!l.active);if(q)r=r.filter(l=>l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));renderLinks(r);}
function renderLinks(links){const tb=$m('ltb'),em=$m('lempty');if(!links||!links.length){tb.innerHTML='';em.style.display='block';return;}em.style.display='none';const onW=lang==='fa'?'فعال':'On',offW=lang==='fa'?'غیرفعال':'Off',copyW=lang==='fa'?'کپی':'Copy',subW=lang==='fa'?'اشتراک':'Sub',delW=lang==='fa'?'حذف':'Del';tb.innerHTML=links.map(l=>{const u=l.used_bytes||0,lim=l.limit_bytes||0,pct=lim>0?Math.min(100,(u/lim)*100):0,col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';const ex=fmtExp(l.expires_at),ec=ex==='Expired'?'var(--red)':ex==='∞'?'var(--text3)':'var(--text2)';const cc=l.current_connections||0,mc2=l.max_connections||0,check=selectedUids.has(l.uuid)?'checked':'';const flagEmoji=l.flag?codeToFlag(l.flag):'';const labelDisplay=(flagEmoji?flagEmoji+' ':'')+esc(l.label);return`<tr><td><input type="checkbox" value="${l.uuid}" ${check} onchange="toggleSelectUid('${l.uuid}')"></td><td style="font-weight:700">${labelDisplay}</td><td style="color:var(--text3);font-size:0.78rem">VLESS</td><td><div class="pill"><span class="pill-used">${fmtB(u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${pct}%;background:${col}"></div></div><span class="pill-lim">${fmtLim(lim)}</span></div></td><td>${cc}/${mc2||'∞'}</td><td style="color:${ec}">${ex}</td><td><span class="status-text ${l.active?'on':'off'}">${l.active?onW:offW}</span></td><td><div style="display:flex;flex-direction:column;gap:6px;align-items:flex-start"><button class="toggle ${l.active?'on':''}" data-uid="${l.uuid}" onclick="togLink(this)"></button><div class="act-group">${l.label==='This Server is Free'?`<button class="pbtn copy" onclick="cpLink('${esc(l.vless_link)}')">${copyW}</button><button class="pbtn sub" onclick="cpSub('${l.uuid}')">🔗</button><button class="pbtn qr" onclick="showQR('${esc(l.vless_link)}')">QR</button>`:`<button class="pbtn edit" onclick="showEditMo('${l.uuid}')">✏️</button><button class="pbtn copy" onclick="cpLink('${esc(l.vless_link)}')">${copyW}</button><button class="pbtn sub" onclick="cpSub('${l.uuid}')">🔗</button><button class="pbtn qr" onclick="showQR('${esc(l.vless_link)}')">QR</button><button class="pbtn del" onclick="delLink('${l.uuid}')">${delW}</button><button class="pbtn edit" onclick="regenerateUUID('${l.uuid}')">🔄</button><button class="pbtn del" onclick="disconnectLink('${l.uuid}')">🔌</button>`}</div></div></td></tr>`;}).join('');}
function toggleSelectUid(uid){selectedUids.has(uid)?selectedUids.delete(uid):selectedUids.add(uid);}
function toggleSelectAll(){const all=$m('select-all');const boxes=document.querySelectorAll('#ltb input[type=checkbox]');if(all.checked){boxes.forEach(c=>{c.checked=true;selectedUids.add(c.value);});}else{boxes.forEach(c=>{c.checked=false;selectedUids.clear();});}}
async function batchAction(action){if(selectedUids.size===0)return toast('No items selected',true);if(action==='delete'&&!confirm('Delete selected?'))return;try{const r=await fetch('/api/links/batch',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({uids:Array.from(selectedUids),action})});if(!r.ok){const d=await r.json();toast(d.detail||'Error',true);}else{selectedUids.clear();loadLinks();loadStats();}}catch{toast('Error',true);}}
async function regenerateUUID(uid){const r=await fetch('/api/links/'+uid+'/new-uuid',{method:'POST'});if(r.ok){loadLinks();toast('UUID regenerated');}}
async function disconnectLink(uid){await fetch('/api/links/'+uid+'/disconnect',{method:'POST'});toast('Disconnected');loadLinks();}
let sortCol='created_at',sortDir='desc';
function sortLinks(col){if(sortCol===col)sortDir=sortDir==='asc'?'desc':'asc';else{sortCol=col;sortDir='desc';}allLinks.sort((a,b)=>{let va=a[sortCol]??'',vb=b[sortCol]??'';if(sortCol==='used_bytes'){va=Number(va);vb=Number(vb);}else if(sortCol==='expires_at'){va=va||'';vb=vb||'';}if(va<vb)return sortDir==='asc'?-1:1;if(va>vb)return sortDir==='asc'?1:-1;return 0;});filterLinks();}
async function togLink(el){const uid=el.dataset.uid,l=allLinks.find(x=>x.uuid===uid);if(!l)return;const na=!l.active;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:na})});l.active=na;filterLinks();loadStats();}catch{toast('Failed',true);}}
async function randomInbound(){const names=['User','Client','Node','Peer'];const n=names[Math.floor(Math.random()*names.length)]+'-'+Math.floor(Math.random()*1000);try{await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:n,limit_value:0})});toast('Created '+n);loadLinks();loadStats();}catch{toast('Error',true);}}
function showAddMo(){$m('mo-add').classList.add('show');}
async function createLink(){const label=$m('nl').value.trim()||'This Server is Free';const uuid=$m('auuid').value.trim();const v=parseFloat($m('nv').value)||0,mc=parseInt($m('nc').value)||0,days=parseInt($m('nd').value)||0;const flagCode=$m('flag-code-create').value||'';const fragment=$m('afrag')?.value?.trim()||'';const body={label,uuid,limit_value:v,limit_unit:'GB',max_connections:mc,days_valid:days,custom_path:$m('ap').value.trim(),custom_sni:$m('asni').value.trim(),custom_host:$m('ahost').value.trim(),custom_fp:$m('afp').value.trim(),color:$m('alink-color')?.value||'#22c55e',flag:flagCode,fragment:fragment};try{await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast('Created');$m('mo-add').classList.remove('show');loadLinks();loadStats();}catch{toast('Error',true);}}
function showEditMo(uid){const l=allLinks.find(x=>x.uuid===uid);if(!l)return;$m('eu').value=uid;$m('euuid').value=l.uuid;$m('en2').value=l.label;$m('el').value=l.limit_bytes>0?(l.limit_bytes/1073741824):'';$m('ec').value=l.max_connections||'';$m('ed').value='';$m('ep').value=l.custom_path||'';$m('esni').value=l.custom_sni||'';$m('ehost').value=l.custom_host||'';$m('efp').value=l.custom_fp||'chrome';$m('efrag').value=l.fragment||'';$m('e-color').value=l.color||'#22c55e';const flag=l.flag||'';$m('flag-code-edit').value=flag;const sel=$m('flag-select-edit');if(flag&&['cn','nl','ru','us','ca','ir','de','gb','it','fr','tr','ae'].includes(flag)){sel.value=flag;$m('flag-custom-edit').style.display='none';}else if(flag){sel.value='custom';$m('flag-custom-edit').style.display='block';$m('flag-custom-edit').value=flag;}else{sel.value='';$m('flag-custom-edit').style.display='none';}$m('et').textContent=(lang==='fa'?'✏️ ویرایش: ':'✏️ Edit: ')+l.label;$m('mo-edit').classList.add('show');}
async function saveEdit(){const uid=$m('eu').value,v=parseFloat($m('el').value)||0,mc=parseInt($m('ec').value)||0,days=parseInt($m('ed').value)||0;const flagCode=$m('flag-code-edit').value||'';const fragment=$m('efrag').value.trim()||'';const body={limit_value:v,limit_unit:'GB',max_connections:mc,label:$m('en2').value.trim(),custom_path:$m('ep').value.trim(),custom_sni:$m('esni').value.trim(),custom_host:$m('ehost').value.trim(),custom_fp:$m('efp').value.trim(),color:$m('e-color').value,flag:flagCode,fragment:fragment};if(days)body.days_valid=days;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast('Updated');$m('mo-edit').classList.remove('show');loadLinks();}catch{toast('Error',true);}}
async function resetTraf(){const uid=$m('eu').value;if(!confirm('Reset?'))return;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('Reset');loadLinks();}catch{toast('Error',true);}}
async function delLink(uid){if(!confirm('Delete?'))return;try{const r=await fetch('/api/links/'+uid,{method:'DELETE'});if(!r.ok){const d=await r.json();toast(d.detail||'Error',true);}else{toast('Deleted');loadLinks();loadStats();}}catch{toast('Error',true);}}
function cpLink(txt){navigator.clipboard.writeText(txt).then(()=>toast('Copied!')).catch(()=>toast('Failed',true));}
async function cpSub(uid){await navigator.clipboard.writeText('https://'+location.host+'/user/'+uid);toast('User Dashboard URL copied!');}
function showQR(txt){if(txt.length>2000){toast('Link too long for QR',true);return;}const img=$m('qr-img');img.src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(txt);$m('mo-qr').classList.add('show');}
function dlQR(){const a=document.createElement('a');a.href=$m('qr-img').src;a.download='sulgx-qr.png';a.click();}

function initChart(){const ctx=$m('tc');if(!ctx||tChart)return;tChart=new Chart(ctx,{type:'bar',data:{labels:[],datasets:[{label:'MB',data:[],backgroundColor:'rgba(34,197,94,0.45)',borderColor:'#22c55e',borderWidth:2,borderRadius:4,barPercentage:0.7}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'var(--text3)'},grid:{display:false}},y:{ticks:{color:'var(--text3)'},grid:{color:'var(--border)'},beginAtZero:true}}}});updChartColors();}
function updChartColors(){if(!tChart)return;const col='var(--text3)';tChart.options.scales.x.ticks.color=col;tChart.options.scales.y.ticks.color=col;tChart.update();}
function updChart(){if(!tChart||!sData.hourly_traffic)return;const labels=[],data=[];for(let h=0;h<24;h++){const key=`${h.toString().padStart(2,'0')}:00`;labels.push(key);data.push(Math.round((sData.hourly_traffic[key]||0)/1048576));}tChart.data.labels=labels;tChart.data.datasets[0].data=data;tChart.update();}
let doughnutChart=null;
function initDoughnutChart(){const ctx=$m('doughnut-chart');if(!ctx||doughnutChart)return;doughnutChart=new Chart(ctx,{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:[]}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'var(--text2)'}}},cutout:'65%'}});}
function updDoughnutChart(){if(!doughnutChart)return;const labels=[],data=[],colors=[];allLinks.filter(l=>l.used_bytes>0).forEach(l=>{labels.push(l.label);data.push(l.used_bytes);colors.push(l.color||'#22c55e');});doughnutChart.data.labels=labels;doughnutChart.data.datasets[0].data=data;doughnutChart.data.datasets[0].backgroundColor=colors;doughnutChart.update();}
let speedChart=null,speedHistory=[];
function initSpeedChart(){const ctx=$m('speed-chart');if(!ctx||speedChart)return;speedChart=new Chart(ctx,{type:'line',data:{labels:[],datasets:[{label:'DL',borderColor:'#22c55e',data:[],tension:0.3,pointRadius:0},{label:'UL',borderColor:'#f87171',data:[],tension:0.3,pointRadius:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'var(--text2)'}},tooltip:{callbacks:{label:ctx=>ctx.dataset.label+': '+formatSpeed(ctx.raw)}}},scales:{x:{ticks:{color:'var(--text3)',maxTicksLimit:10},grid:{display:false}},y:{ticks:{color:'var(--text3)',callback:v=>formatSpeed(v)},grid:{color:'var(--border)'},beginAtZero:true}}}});}
function updSpeedChart(up,down){if(!speedChart)return;const t=getLocalTimeString();speedHistory.push({t,up,down});if(speedHistory.length>60)speedHistory.shift();const maxVal=Math.max(...speedHistory.map(s=>Math.max(s.up,s.down)),1);speedChart.options.scales.y.max=maxVal*1.2;speedChart.data.labels=speedHistory.map(s=>s.t);speedChart.data.datasets[0].data=speedHistory.map(s=>s.down);speedChart.data.datasets[1].data=speedHistory.map(s=>s.up);speedChart.update();}

async function loadAddrs(){try{const r=await fetch('/api/addresses');if(r.status===401){showLogin();return;}if(!r.ok)return;allAddrs=(await r.json()).addresses||[];renderAddrs();}catch(e){console.error('loadAddrs error:',e);}}
function renderAddrs(){const el=$m('addr-list');if(!el)return;if(!allAddrs.length){el.innerHTML='<div class="empty">'+(lang==='fa'?'آدرسی افزوده نشده':'No addresses added')+'</div>';return;}el.innerHTML=allAddrs.map((a,i)=>`<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:var(--surface3);border-radius:var(--radius-sm);margin-bottom:6px"><div style="display:flex;align-items:center;gap:8px"><input type="checkbox" class="addr-checkbox" data-index="${i}" ${selectedAddrIndices.has(i)?'checked':''} onchange="toggleSelectAddr(${i})"><span style="font-weight:600">${esc(a)}</span></div><div style="display:flex;gap:4px"><button class="pbtn edit" onclick="showEditAddr(${i})">✏️</button><button class="pbtn del" onclick="delAddr(${i})">🗑️</button></div></div>`).join('');}
function toggleSelectAddr(i){selectedAddrIndices.has(i)?selectedAddrIndices.delete(i):selectedAddrIndices.add(i);}
async function bulkDeleteAddrs(){if(selectedAddrIndices.size===0)return toast('No addresses selected',true);if(!confirm('Delete selected?'))return;const indices=Array.from(selectedAddrIndices);try{const r=await fetch('/api/addresses/bulk-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indices})});if(r.ok){selectedAddrIndices.clear();await loadAddrs();toast('Deleted selected');}}catch{toast('Error',true);}}
function showEditAddr(i){editingAddrIndex=i;$m('edit-addr-input').value=allAddrs[i];$m('mo-addr-edit').classList.add('show');}
async function saveAddrEdit(){const newAddr=$m('edit-addr-input').value.trim();if(!newAddr)return toast('Invalid address',true);try{const r=await fetch('/api/addresses/'+editingAddrIndex,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:newAddr})});if(r.ok){toast('Address updated');$m('mo-addr-edit').classList.remove('show');await loadAddrs();}else{const d=await r.json();toast(d.detail||'Error updating',true);}}catch{toast('Error',true);}}
async function addBatchAddrs(){const raw=$m('batch-addrs').value;const lines=raw.split('\n').map(l=>l.trim()).filter(l=>l);if(!lines.length)return;try{const r=await fetch('/api/addresses/batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({addresses:lines})});if(r.status===401){showLogin();return;}const d=await r.json();toast(`Added ${d.added} addresses`+(d.errors?` (${d.errors} errors)`:''));$m('batch-addrs').value='';await loadAddrs();}catch{toast('Batch add failed',true);}}
async function deleteAllAddrs(){if(!confirm('Delete all addresses?'))return;try{await fetch('/api/addresses',{method:'DELETE'});toast('All deleted');await loadAddrs();}catch{toast('Error',true);}}
async function delAddr(i){if(!confirm('Delete?'))return;try{await fetch('/api/addresses/'+i,{method:'DELETE'});toast('Deleted');await loadAddrs();}catch{toast('Error',true);}}
async function exportLinks(){try{const r=await fetch('/api/export-links');const data=await r.json();const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='sulgx-links.json';a.click();}catch{toast('Export failed',true);}}
async function importLinks(input){const file=input.files[0];if(!file)return;try{const text=await file.text();const data=JSON.parse(text);const r=await fetch('/api/import-links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const res=await r.json();toast(`Imported ${res.imported} links`);loadLinks();loadStats();}catch{toast('Import failed',true);}input.value='';}

let currentProvider=null;
const dnsRanges=new Set(['1.1.1.1','1.0.0.1','9.9.9.9','149.112.112.112','208.67.222.222','208.67.220.220']);
const providerIPs={"arvancloud":{"ipv4":["185.143.232.0/22","188.229.116.16/30","94.101.182.0/27","2.144.3.128/28","37.32.16.0/27","37.32.17.0/27","37.32.18.0/27","37.32.19.0/27","185.215.232.0/22","178.131.120.48/28","185.143.235.0/24"]},"cloudflare":{"ipv4":["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"]},"fastly":{"ipv4":["23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23","103.245.224.0/24","104.156.80.0/20","140.248.64.0/18","140.248.128.0/17","146.75.0.0/17","151.101.0.0/16","157.52.64.0/18","167.82.0.0/17","167.82.128.0/20","167.82.160.0/20","167.82.224.0/20","172.111.64.0/18","185.31.16.0/22","199.27.72.0/21","199.232.0.0/16"]},"Google":{"ipv4":["34.0.0.0/15","34.2.0.0/16","34.64.0.0/10","34.128.0.0/10","35.216.0.0/14","104.132.0.0/14"]},"Railway":{"ipv4":["69.46.46.0/24","208.77.244.0/24","208.77.245.0/24","208.77.246.0/24","208.77.247.0/24","208.77.248.0/24"]},"GitHub":{"ipv4":["140.82.112.0/20","143.55.64.0/20","192.30.252.0/22"]},"Netflix":{"ipv4":["23.246.0.0/18","37.77.184.0/21","45.57.0.0/17","64.120.128.0/17","66.197.128.0/17","69.53.224.0/19","198.45.48.0/20"]},"Spotify":{"ipv4":["23.92.96.0/20","78.31.8.0/22","193.182.8.0/21","193.235.232.0/24"]}};
function buildProviderPills(){const container=$m('provider-btns');if(!container)return;container.innerHTML='';Object.keys(providerIPs).forEach(prov=>{const btn=document.createElement('button');btn.className='chip';btn.textContent=prov;btn.onclick=()=>selectProvider(prov,btn);if(prov==='Railway')btn.classList.add('railway-hl');container.appendChild(btn);});const customBtn=document.createElement('button');customBtn.className='chip';customBtn.textContent='Custom';customBtn.onclick=()=>selectProvider('Custom',customBtn);container.appendChild(customBtn);}
function selectProvider(prov,btn){document.querySelectorAll('#provider-btns .chip').forEach(b=>b.classList.remove('active'));btn.classList.add('active');currentProvider=prov;const rangeSection=$m('range-section'),railNote=$m('railway-note');if(prov==='Custom'){rangeSection.style.display='none';railNote.style.display='none';$m('scan-ips').value='';return;}rangeSection.style.display='flex';railNote.style.display=(prov==='Railway')?'block':'none';const rangeBtns=$m('range-btns');rangeBtns.innerHTML='';const ranges=providerIPs[prov]?.ipv4||[];ranges.forEach(r=>{const b=document.createElement('button');b.className='chip';b.textContent=r;b.onclick=()=>{loadRangeIPs(r,b);};rangeBtns.appendChild(b);});const allIPs=[];ranges.forEach(r=>{allIPs.push(...expandCIDR(r));});$m('scan-ips').value=allIPs.join('\n');}
function loadRangeIPs(range,btn){document.querySelectorAll('#range-btns .chip').forEach(b=>b.classList.remove('active'));if(btn)btn.classList.add('active');$m('scan-ips').value=expandCIDR(range).join('\n');}
function expandCIDR(cidr){const parts=cidr.split('/');if(parts.length!==2)return[cidr];const ip=parts[0].trim(),mask=parseInt(parts[1]);if(isNaN(mask)||mask<16||mask>32)return[cidr];const ipParts=ip.split('.').map(Number);if(ipParts.length!==4||ipParts.some(p=>isNaN(p)||p>255))return[cidr];const count=Math.pow(2,32-mask);const limit=Math.min(count,256);if(count>limit)toast('Large range: only first 256 IPs extracted.');const start=(ipParts[0]<<24)+(ipParts[1]<<16)+(ipParts[2]<<8)+ipParts[3];const base=start&(~((1<<(32-mask))-1));const result=[];for(let i=0;i<limit;i++){const addr=base+i;const ipStr=`${(addr>>>24)&255}.${(addr>>>16)&255}.${(addr>>>8)&255}.${addr&255}`;if(dnsRanges.has(ipStr))continue;result.push(ipStr);}return result;}
let totalScanCount=0,scannedCount=0,wsScanner=null;
function stopScan(){if(wsScanner){wsScanner.close();wsScanner=null;}$m('scan-start-btn').style.display='inline-flex';$m('scan-stop-btn').style.display='none';}
async function startIPScan(){const raw=$m('scan-ips').value;const lines=raw.split('\n').map(l=>l.trim()).filter(l=>l);if(!lines.length)return;const items=[];lines.forEach(l=>{if(l.includes('/'))items.push(...expandCIDR(l));else if(!dnsRanges.has(l.trim()))items.push(l.trim());});const unique=[...new Set(items)];const MAX_IPS=256;if(unique.length>MAX_IPS){toast(`Max ${MAX_IPS} IPs allowed. You entered ${unique.length}.`,true);return;}totalScanCount=unique.length;scannedCount=0;$m('scan-tbody').innerHTML='';$m('scan-progress').style.width='0%';$m('progress-text').textContent='0%';$m('scan-start-btn').style.display='none';$m('scan-stop-btn').style.display='inline-flex';if(wsScanner)wsScanner.close();const proto=location.protocol==='https:'?'wss:':'ws:';wsScanner=new WebSocket(`${proto}//${location.host}/ws/scanner`);wsScanner.onopen=()=>wsScanner.send(JSON.stringify({ips:unique}));wsScanner.onmessage=(e)=>{const d=JSON.parse(e.data);if(d.done){wsScanner.close();$m('scan-start-btn').style.display='inline-flex';$m('scan-stop-btn').style.display='none';toast('Scan finished.');return;}scannedCount++;const pct=Math.round((scannedCount/totalScanCount)*100);$m('scan-progress').style.width=pct+'%';$m('progress-text').textContent=pct+'%';const row=`<tr><td>${esc(d.ip)}</td><td style="color:${d.ok?'var(--green)':'var(--red)'}">${d.ok?'✅':'❌'}</td><td>${d.latency?d.latency+' ms':'–'}</td></tr>`;$m('scan-tbody').insertAdjacentHTML('beforeend',row);};wsScanner.onerror=()=>{toast('Scanner error (timeout?)',true);$m('scan-start-btn').style.display='inline-flex';$m('scan-stop-btn').style.display='none';};wsScanner.onclose=()=>{$m('scan-start-btn').style.display='inline-flex';$m('scan-stop-btn').style.display='none';};}
function sortBestIPs(){const rows=Array.from($m('scan-tbody').querySelectorAll('tr'));const items=[];rows.forEach(r=>{const cells=r.querySelectorAll('td');const ip=cells[0].textContent.trim();const ok=cells[1].textContent.includes('✅');const lat=parseFloat(cells[2].textContent);if(ok&&!isNaN(lat))items.push({ip,lat});});if(items.length===0){toast('No reachable IPs',true);return;}items.sort((a,b)=>a.lat-b.lat);$m('scan-tbody').innerHTML=items.map(i=>`<tr><td>${esc(i.ip)}</td><td style="color:var(--green)">✅</td><td>${i.lat} ms</td></tr>`).join('');}
function copyReachableSorted(){const rows=Array.from($m('scan-tbody').querySelectorAll('tr'));const reachable=[];rows.forEach(r=>{const cells=r.querySelectorAll('td');const ip=cells[0].textContent.trim();const ok=cells[1].textContent.includes('✅');const lat=parseFloat(cells[2].textContent);if(ok&&!isNaN(lat))reachable.push({ip,lat});});if(reachable.length===0){toast('No reachable IPs found',true);return;}reachable.sort((a,b)=>a.lat-b.lat);navigator.clipboard.writeText(reachable.map(item=>item.ip).join('\n')).then(()=>toast(`Copied ${reachable.length} IPs sorted by latency`)).catch(()=>toast('Failed to copy',true));}

async function loadLogs(){try{const r=await fetch('/api/logs');if(r.status===401){showLogin();return;}const d=await r.json();const logs=d.logs||[];const tbody=$m('logs-tbody'),empty=$m('logs-empty');if(!tbody)return;if(!logs.length){tbody.innerHTML='';empty.style.display='block';return;}empty.style.display='none';tbody.innerHTML=logs.map((l,i)=>{const local=new Date(l.time);local.setMinutes(local.getMinutes()+local.getTimezoneOffset()+timezoneOffset*60);return`<tr><td>${i+1}</td><td>${local.toISOString().replace('T',' ').split('.')[0]}</td><td>${esc(l.type||'Event')}</td><td>${esc(l.error||'')}</td></tr>`;}).join('');}catch(err){console.error('loadLogs error:',err);}}
async function loadLoginLogs(){try{const r=await fetch('/api/login-logs');if(!r.ok)return;const d=await r.json();const tbody=$m('login-logs-tbody');if(!tbody)return;const okW=lang==='fa'?'✅ موفق':'✅ Success',failW=lang==='fa'?'❌ ناموفق':'❌ Failed';tbody.innerHTML=d.logs.map(l=>`<tr><td>${timeAgo(l.timestamp)}</td><td><div style="font-weight:600">${esc(l.ip)}</div><div style="font-size:0.7rem;color:var(--text3);max-width:140px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(l.user_agent)}">${esc(l.user_agent)}</div></td><td style="color:${l.success?'var(--green)':'var(--red)'}">${l.success?okW:failW}</td></tr>`).join('');}catch(e){}}
function timeAgo(ts){const then=new Date(ts),now=new Date(),diff=Math.floor((now-then)/1000);if(diff<60)return'Just now';if(diff<3600)return Math.floor(diff/60)+'m ago';if(diff<86400)return Math.floor(diff/3600)+'h ago';return new Date(ts).toLocaleDateString();}
async function loadTelegramSettings(){try{const r=await fetch('/api/settings');if(r.status===401){showLogin();return;}const d=await r.json();$m('tg-token').value=d.tg_bot_token||'';$m('tg-chat-id').value=d.tg_chat_id||'';$m('tg-interval').value=d.telegram_interval||'1';const events=(d.telegram_events||'').split(',');document.querySelectorAll('.tg-event').forEach(cb=>cb.checked=events.includes(cb.value));$m('tg-templates-en').value=d.telegram_templates_en||'{"quota_90":"⚠️ {label} ({uid}) used 90% of quota","login":"🔐 SulgX Panel login\\n🌐 IP: {ip}\\n🤖 UA: {ua}\\n📅 {time}","expiry":"⏰ {label} expired","error":"❌ Error on {label}: check logs"}';$m('tg-templates-fa').value=d.telegram_templates_fa||'{"quota_90":"⚠️ {label} ({uid}) ۹۰٪ کوتا","login":"🔐 ورود SulgX\\n🌐 IP: {ip}\\n🤖 UA: {ua}\\n📅 {time}","expiry":"⏰ {label} منقضی شد","error":"❌ خطا در {label}: بررسی شود"}';const tgLang=d.telegram_lang||'en';const toggle=$m('tg-lang-toggle');if(tgLang==='fa'){toggle.classList.remove('on');$m('tg-lang-label').textContent='فارسی';$m('tg-lang-hidden').value='fa';}else{toggle.classList.add('on');$m('tg-lang-label').textContent='English';$m('tg-lang-hidden').value='en';}}catch(err){console.error('loadTelegram error:',err);}}
async function saveTelegramSettings(){const token=$m('tg-token').value.trim(),chat=$m('tg-chat-id').value.trim();const interval=$m('tg-interval').value.trim();const events=Array.from(document.querySelectorAll('.tg-event:checked')).map(cb=>cb.value).join(',');const templates_en=$m('tg-templates-en').value.trim();const templates_fa=$m('tg-templates-fa').value.trim();const tglang=$m('tg-lang-hidden').value;try{await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tg_bot_token:token,tg_chat_id:chat,telegram_interval:interval,telegram_events:events,telegram_templates_en:templates_en,telegram_templates_fa:templates_fa,telegram_lang:tglang})});toast('Saved');}catch{toast('Error',true);}}
async function testTelegram(){const token=$m('tg-token').value.trim(),chat=$m('tg-chat-id').value.trim();if(!token||!chat){toast('Fill token and chat ID',true);return;}const tglang=$m('tg-lang-hidden').value;const msg=tglang==='fa'?'✅ SulgX متصل شد':'✅ SulgX is connected';try{const res=await fetch(`https://api.telegram.org/bot${token}/sendMessage`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:chat,text:msg})});if(res.ok)toast('Test message sent!');else toast('Failed to send',true);}catch{toast('Error',true);}}
function toggleTgLang(){const toggle=$m('tg-lang-toggle');toggle.classList.toggle('on');const isEn=toggle.classList.contains('on');$m('tg-lang-label').textContent=isEn?'English':'فارسی';$m('tg-lang-hidden').value=isEn?'en':'fa';}
function previewTemplate(){const isEn=$m('tg-lang-toggle').classList.contains('on');const targetId=isEn?'tg-templates-en':'tg-templates-fa';const textarea=$m(targetId);const previewDiv=$m('tg-preview');if(!textarea||!previewDiv)return;try{const sanitized=textarea.value.replace(/[\u0000-\u001f]/g,function(ch){if(ch==='\n')return'\\n';if(ch==='\r')return'\\r';if(ch==='\t')return'\\t';return'';});const templates=JSON.parse(sanitized);const mockData={label:"SulgX_User",uid:"sulgx-7b8c-49ed-b45a",ip:"85.201.32.44",ua:"Mozilla/5.0 (iPhone; iOS 18)",time:new Date().toISOString().replace('T',' ').substring(0,19)};let html="";for(const[key,templateText]of Object.entries(templates)){let text=templateText;text=text.replace(/{label}/g,mockData.label).replace(/{uid}/g,mockData.uid).replace(/{ip}/g,mockData.ip).replace(/{ua}/g,mockData.ua).replace(/{time}/g,mockData.time);html+=`<div style="margin-bottom:6px;border-bottom:1px solid var(--border);padding-bottom:4px"><span style="color:var(--primary);font-weight:700;font-size:0.75rem">[${key}]:</span><br>${text}</div>`;}const domain=window.location.host||'your-domain.com';html+=`<div style="margin-top:6px;padding-top:4px;color:var(--green)">⚠️ <i>Auto appended:</i><br>🔗 https://${domain}/panel</div>`;previewDiv.innerHTML=html;previewDiv.style.border='1px solid var(--primary)';}catch(e){previewDiv.innerHTML=`<span style="color:var(--red)">❌ Invalid JSON: ${e.message}</span>`;previewDiv.style.border='1px solid var(--red)';}}

async function loadGeneralSettings(){try{const r=await fetch('/api/settings');if(!r.ok)return;const d=await r.json();$m('set-footer').value=d.footer_text||'';$m('set-default-path').value=d.default_path||'';timezoneOffset=parseFloat(d.timezone_offset)||0;$m('set-default-limit').value=d.default_limit_bytes?(parseInt(d.default_limit_bytes)/1073741824).toFixed(1):'';$m('set-default-expiry').value=d.default_expiry_days||'';$m('set-default-maxconn').value=d.default_max_connections||'';$m('set-scanner-timeout').value=d.scanner_timeout||'4';$m('set-monthly-limit').value=d.monthly_limit_gb||'';$m('set-max-scan-ips').value=d.max_scan_ips||'256';$m('set-keep-alive-interval').value=d.keep_alive_interval||'300';updateSettingsStatus(d);if(d.keep_alive_mode){setKeepAliveMode(d.keep_alive_mode);$m('set-keepalive-enabled').value=d.keep_alive_enabled==='1'?'1':'0';const card=$m('card-keepalive');if(d.keep_alive_enabled==='1'){card.classList.add('active');card.classList.remove('inactive');}else{card.classList.add('inactive');card.classList.remove('active');}}if(timezoneOffset===3.5)setPanelTZ(3.5,'Tehran');else if(timezoneOffset===0)setPanelTZ(0,'UTC');else{toggleCustomTZInput(true);$m('custom-tz-value').value=timezoneOffset;}const savedTheme=d.theme_color||'dark';setPanelTheme(savedTheme);}catch(e){}}
async function saveGeneralSettings(){const footer=$m('set-footer').value.trim();const defPath=$m('set-default-path').value.trim();const logEnabled=$m('set-log-toggle').value;const themeColor=$m('set-theme-color')?.value||theme;const defLimit=parseFloat($m('set-default-limit').value)*1073741824;const defExpiry=$m('set-default-expiry').value.trim();const defMaxConn=$m('set-default-maxconn').value.trim();const scannerTimeout=$m('set-scanner-timeout').value.trim();const monthlyLimit=$m('set-monthly-limit').value.trim();const maxScanIps=$m('set-max-scan-ips').value.trim();const keepAliveInterval=$m('set-keep-alive-interval').value.trim();const keepAliveEnabled=$m('set-keepalive-enabled').value;var keepAliveModeEl=$m('set-keepalive-mode');var keepAliveMode=keepAliveModeEl?keepAliveModeEl.value:'simple';const autoDisable=$m('set-auto-disable').value;const tgReport=$m('set-tg-report').value;const tgNotify=$m('set-tg-notify').value;try{await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({footer_text:footer,default_path:defPath,timezone_offset:timezoneOffset,log_enabled:logEnabled,theme_color:themeColor,default_lang:lang,default_limit_bytes:isNaN(defLimit)?'':String(Math.round(defLimit)),default_expiry_days:defExpiry,default_max_connections:defMaxConn,scanner_timeout:scannerTimeout,monthly_limit_gb:monthlyLimit,max_scan_ips:maxScanIps,keep_alive_interval:keepAliveInterval,keep_alive_enabled:keepAliveEnabled,keep_alive_mode:keepAliveMode,auto_disable_enabled:autoDisable,telegram_report_enabled:tgReport,telegram_notify_enabled:tgNotify})});toast('Saved');loadGeneralSettings();}catch{toast('Error',true);}}
function generateUUID(id){const uuid=crypto.randomUUID?crypto.randomUUID():'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,c=>{const r=Math.random()*16|0;return(c=='x'?r:(r&0x3|0x8)).toString(16);});$m(id).value=uuid;}
function toggleAdv(id){const el=$m(id);el.style.display=el.style.display==='none'?'block':'none';}
function filterLogs(){const q=($m('log-search').value||'').toLowerCase();document.querySelectorAll('#logs-tbody tr').forEach(row=>{if(!q){row.style.display='';return;}row.style.display=row.innerText.toLowerCase().includes(q)?'':'none';});}
function clearLogSearch(){$m('log-search').value='';filterLogs();}
async function clearLogs(){if(!confirm('Clear all logs?'))return;await fetch('/api/logs/clear',{method:'DELETE'});loadLogs();}
async function fetchLogSize(){const r=await fetch('/api/logs/size');const d=await r.json();toast(`Log entries: ${d.count}, Size: ${d.size_kb} KB`);}
async function resetAllSettings(){if(!confirm('Are you sure? All settings (except password) will reset to defaults.'))return;try{const r=await fetch('/api/settings/reset',{method:'POST'});if(!r.ok)throw new Error((await r.json()).detail);toast('Settings reset. Reloading...');setTimeout(()=>location.reload(),1500);}catch(e){toast(e.message,true);}}
async function chgPw(){const cur=$m('cpw').value,nw=$m('npw').value;if(!cur||!nw){toast('Fill fields',true);return;}if(nw.length<8){toast('Password must be at least 8 characters',true);return;}if(!/[A-Z]/.test(nw)||!/[a-z]/.test(nw)||!/[0-9]/.test(nw)){toast('Password must contain uppercase, lowercase, and digit',true);return;}try{const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});if(!r.ok)throw new Error((await r.json()).detail||'Error');toast('Password updated');}catch(e){toast(e.message,true);}}

function applyProfile(){const p=$m('eres-profile').value;if(!p)return;const pr={default:{path:'',sni:'',host:'',fp:'chrome'},youtube:{path:'/youtubei/v1/image',sni:'www.youtube.com',host:'www.youtube.com',fp:'chrome'},instagram:{path:'/graphql',sni:'www.instagram.com',host:'www.instagram.com',fp:'chrome'},twitter:{path:'/ws',sni:'twitter.com',host:'twitter.com',fp:'chrome'},tiktok:{path:'/ws',sni:'www.tiktok.com',host:'www.tiktok.com',fp:'chrome'},whatsapp:{path:'/ws/chat/v4',sni:'web.whatsapp.com',host:'web.whatsapp.com',fp:'safari'},telegram:{path:'/ws',sni:'telegram.org',host:'telegram.org',fp:'chrome'},netflix:{path:'/ws',sni:'www.netflix.com',host:'www.netflix.com',fp:'chrome'},spotify:{path:'/ws',sni:'www.spotify.com',host:'www.spotify.com',fp:'chrome'},google:{path:'/ws',sni:'www.google.com',host:'www.google.com',fp:'chrome'}};if(pr[p]){$m('ep').value=pr[p].path||'';$m('esni').value=pr[p].sni||'';$m('ehost').value=pr[p].host||'';$m('efp').value=pr[p].fp||'chrome';}}
function applyProfileCreate(){const p=$m('ares-profile').value;if(!p)return;const pr={default:{path:'',sni:'',host:'',fp:'chrome'},youtube:{path:'/youtubei/v1/image',sni:'www.youtube.com',host:'www.youtube.com',fp:'chrome'},instagram:{path:'/graphql',sni:'www.instagram.com',host:'www.instagram.com',fp:'chrome'},twitter:{path:'/ws',sni:'twitter.com',host:'twitter.com',fp:'chrome'},tiktok:{path:'/ws',sni:'www.tiktok.com',host:'www.tiktok.com',fp:'chrome'},whatsapp:{path:'/ws/chat/v4',sni:'web.whatsapp.com',host:'web.whatsapp.com',fp:'safari'},telegram:{path:'/ws',sni:'telegram.org',host:'telegram.org',fp:'chrome'},netflix:{path:'/ws',sni:'www.netflix.com',host:'www.netflix.com',fp:'chrome'},spotify:{path:'/ws',sni:'www.spotify.com',host:'www.spotify.com',fp:'chrome'},google:{path:'/ws',sni:'www.google.com',host:'www.google.com',fp:'chrome'}};if(pr[p]){$m('ap').value=pr[p].path||'';$m('asni').value=pr[p].sni||'';$m('ahost').value=pr[p].host||'';$m('afp').value=pr[p].fp||'chrome';}}
function applyFlagCreate(){const sel=$m('flag-select-create').value;const customInput=$m('flag-custom-create');const hidden=$m('flag-code-create');if(sel==='custom'){customInput.style.display='block';hidden.value=customInput.value.trim().toLowerCase();}else{customInput.style.display='none';hidden.value=sel;}}
function applyFlagEdit(){const sel=$m('flag-select-edit').value;const customInput=$m('flag-custom-edit');const hidden=$m('flag-code-edit');if(sel==='custom'){customInput.style.display='block';hidden.value=customInput.value.trim().toLowerCase();}else{customInput.style.display='none';hidden.value=sel;}}

document.addEventListener('keydown',e=>{if(e.ctrlKey||e.metaKey){const pages=['dashboard','inbounds','addresses','ipscanner','logs','telegram','settings'];const num=parseInt(e.key);if(num>=1&&num<=pages.length)switchPage(pages[num-1]);}});
if(window.matchMedia('(prefers-color-scheme: dark)').matches&&!localStorage.getItem('theme'))setTheme('dark');
setTheme(theme);setLang(lang);checkAuth();
setInterval(()=>{if(isAuthenticated){loadStats();loadLinks();}},12000);
</script>
</body>
</html>

<script>
// ===== SWITCH PAGE =====
function switchPage(id){
  // Hide all pages
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  // Show target page
  const target = document.getElementById('page-' + id);
  if (target) target.classList.add('active');
  
  // Update nav links (header)
  document.querySelectorAll('.nav-link').forEach(n => {
    n.classList.toggle('active', n.dataset.page === id);
  });
  
  // Update mobile nav items
  document.querySelectorAll('.mobile-nav .item').forEach(n => {
    n.classList.toggle('active', n.dataset.page === id);
  });
}

// ===== REST OF SCRIPT (same as before) =====
const $=s=>document.querySelector(s),$m=id=>document.getElementById(id);
function esc(s){return String(s).replace(/&/g,'&').replace(/</g,'<').replace(/>/g,'>').replace(/"/g,'"').replace(/'/g,'&#39;')}
let lang=localStorage.getItem('ll')||'en',theme=localStorage.getItem('theme')||'dark';
let allLinks=[],cf='all',sData={},tChart=null,allAddrs=[],isAuthenticated=false;
let prevUploadBytes=null,prevDownloadBytes=null,prevStatsTime=null;
let timezoneOffset=0,editingAddrIndex=-1,selectedUids=new Set(),selectedAddrIndices=new Set();
let uploadSpeedAvg=0,downloadSpeedAvg=0;
const footerTexts={en:'Dedicated to the people of my homeland Iran from <a href=\"https://github.com/SulgX\" target=\"_blank\">SulgX</a>',fa:'تقدیم به مردم سرزمینم ایران از طرف <a href=\"https://github.com/SulgX\" target=\"_blank\">SulgX</a>'};

function setLang(l){lang=l;document.querySelectorAll('.lang-en,.lang-fa').forEach(e=>e.classList.remove('active'));document.querySelectorAll(`.lang-${l}`).forEach(e=>e.classList.add('active'));document.body.dir=l==='fa'?'rtl':'ltr';localStorage.setItem('ll',l);const footer=$m('footer-dedication');if(footer)footer.innerHTML=footerTexts[l]||footerTexts['en'];if(isAuthenticated){loadLoginLogs();loadLogs();renderAddrs();filterLinks();}}
function setTheme(t){theme=t;document.body.classList.toggle('light-mode',t==='light');document.body.classList.toggle('blue-mode',t==='blue-dark');localStorage.setItem('theme',t);if(tChart)updChartColors();syncGlassThemeButtons();}
function toggleTheme(){const themes=['dark','light','blue-dark'];const idx=themes.indexOf(theme);setTheme(themes[(idx+1)%themes.length]);}
function syncGlassThemeButtons(){document.querySelectorAll('#theme-glass-group .glass-btn').forEach(b=>b.classList.remove('active'));const btn=$m(`btn-theme-${theme}`);if(btn)btn.classList.add('active');}
function setPanelTheme(th){document.querySelectorAll('#theme-glass-group .glass-btn').forEach(b=>b.classList.remove('active'));const btn=$m(`btn-theme-${th}`);if(btn)btn.classList.add('active');const hidden=$m('set-theme-color');if(hidden)hidden.value=th;setTheme(th);localStorage.setItem('theme',th);}
function setPanelTZ(offset,name){document.querySelectorAll('#tz-glass-group .glass-btn').forEach(b=>b.classList.remove('active'));if(name==='Tehran')$m('btn-tz-tehran').classList.add('active');else if(name==='UTC')$m('btn-tz-utc').classList.add('active');else if(name==='Custom')$m('btn-tz-custom').classList.add('active');toggleCustomTZInput(false);timezoneOffset=offset;localStorage.setItem('timezone_offset',offset);saveSingleSetting('timezone_offset',offset);}
function toggleCustomTZInput(show){const container=$m('custom-tz-container');const customBtn=$m('btn-tz-custom');if(show){document.querySelectorAll('#tz-glass-group .glass-btn').forEach(b=>b.classList.remove('active'));customBtn.classList.add('active');container.style.display='block';}else{container.style.display='none';}}
function applyCustomTZ(val){let parsed=parseFloat(val);if(!isNaN(parsed)){timezoneOffset=parsed;localStorage.setItem('timezone_offset',parsed);saveSingleSetting('timezone_offset',parsed);}}
function saveSingleSetting(key,value){fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({[key]:value})});}
function setKeepAliveMode(mode){document.querySelectorAll('#keepalive-mode-group .glass-btn').forEach(b=>b.classList.remove('active'));$m(`btn-keepalive-${mode}`).classList.add('active');var el=$m('set-keepalive-mode');if(el)el.value=mode;}
function toggleSettingCard(cardId,inputId){const card=$m(cardId);const input=$m(inputId);if(card.classList.contains('active')){card.classList.remove('active');card.classList.add('inactive');input.value='0';}else{card.classList.remove('inactive');card.classList.add('active');input.value='1';}}
function updateSettingsStatus(settings){if(!settings)return;const setCard=(cardId,enabled)=>{const card=$m(cardId);if(card){card.classList.toggle('active',enabled);card.classList.toggle('inactive',!enabled);}};setCard('card-log',settings.log_enabled==='1');setCard('card-auto',settings.auto_disable_enabled==='1');setCard('card-tgrep',settings.telegram_report_enabled==='1');setCard('card-tgnot',settings.telegram_notify_enabled==='1');$m('set-log-toggle').value=settings.log_enabled==='1'?'1':'0';$m('set-auto-disable').value=settings.auto_disable_enabled==='1'?'1':'0';$m('set-tg-report').value=settings.telegram_report_enabled==='1'?'1':'0';$m('set-tg-notify').value=settings.telegram_notify_enabled==='1'?'1':'0';setCard('card-keepalive',settings.keep_alive_enabled==='1');$m('set-keepalive-enabled').value=settings.keep_alive_enabled==='1'?'1':'0';}
function updateDashboardStatusCards(settings){if(!settings)return;const statusEl=$m('settings-status');if(!statusEl)return;const items=[{id:'st-log',label:'Logs',enabled:settings.log_enabled==='1'},{id:'st-auto',label:'Auto Disable',enabled:settings.auto_disable_enabled==='1'},{id:'st-tgrep',label:'TG Reports',enabled:settings.telegram_report_enabled==='1'},{id:'st-tgnot',label:'TG Alerts',enabled:settings.telegram_notify_enabled==='1'},{id:'st-bot',label:'Bot',enabled:!!(settings.tg_bot_token&&settings.tg_chat_id)}];statusEl.innerHTML=items.map(item=>`<div class="status-card ${item.enabled?'active':'inactive'}"><span class="icon">${item.enabled?'✅':'❌'}</span>${item.label}</div>`).join('');}
function toast(msg,err=false){const t=$m('toast');t.textContent=msg;t.className='toast'+(err?' err':'')+' show';clearTimeout(t._hide);t._hide=setTimeout(()=>t.classList.remove('show'),3000);}
function fmtB(b){if(!b||b===0)return'0 B';return b>=1073741824?(b/1073741824).toFixed(2)+' GB':b>=1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB';}
function fmtLim(b){if(!b||b===0)return'∞';const g=b/1073741824;return(g%1===0?g.toFixed(0):g.toFixed(1))+' GB';}
function fmtExp(ea){if(!ea||ea===0)return'∞';const d=new Date(ea)-new Date();if(d<=0)return'Expired';const days=Math.floor(d/86400000);if(days>0)return days+'d';const hours=Math.floor(d/3600000);if(hours>0)return hours+'h';return Math.floor(d/60000)+'m';}
function codeToFlag(code){if(!code||code.length!==2)return'';code=code.toUpperCase();return String.fromCodePoint(0x1F1E6+code.charCodeAt(0)-65)+String.fromCodePoint(0x1F1E6+code.charCodeAt(1)-65);}
function getLocalTimeString(){const d=new Date();d.setMinutes(d.getMinutes()+d.getTimezoneOffset()+timezoneOffset*60);return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;}
function formatSpeed(bps){if(bps<1024)return bps.toFixed(1)+' B/s';const kbps=bps/1024;if(kbps<1024)return kbps.toFixed(1)+' KB/s';const mbps=kbps/1024;return mbps.toFixed(2)+' MB/s';}
function safeSetText(id,text){const el=$m(id);if(el)el.textContent=text;}
function safeSetHTML(id,html){const el=$m(id);if(el)el.innerHTML=html;}

async function checkAuth(){try{const r=await fetch('/api/me');if((await r.json()).authenticated){await showDashboard();}else{showLogin();}}catch{showLogin();}}
function showLogin(){isAuthenticated=false;$m('login-page').style.display='flex';$m('dashboard-page').style.display='none';fetch('/api/public-settings').then(r=>r.json()).then(d=>{if(d.footer_text)$m('login-custom-message').textContent=d.footer_text;}).catch(()=>{});}
async function showDashboard(){isAuthenticated=true;$m('login-page').style.display='none';$m('dashboard-page').style.display='';await loadGeneralSettings();initChart();initDoughnutChart();initSpeedChart();loadStats();loadLinks();loadAddrs();loadLogs();loadLoginLogs();buildProviderPills();loadTelegramSettings();setLang(lang);startPanelClock();syncGlassThemeButtons();}
function startPanelClock(){setInterval(()=>{const d=new Date();d.setMinutes(d.getMinutes()+d.getTimezoneOffset()+timezoneOffset*60);$m('panel-clock').textContent=d.toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit'});},1000);}
async function doLogin(){const pw=$m('login-pw').value;$m('login-err').style.display='none';try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});if(r.ok){$m('login-pw').value='';showDashboard();}else $m('login-err').style.display='block';}catch{$m('login-err').style.display='block';}}
async function doLogout(){await fetch('/api/logout',{method:'POST'});showLogin();}
document.getElementById('hamburger-btn')?.addEventListener('click',function(e){e.stopPropagation();document.getElementById('mainNav').classList.toggle('open');});

async function loadStats(){try{const r=await fetch('/stats');if(r.status===401){showLogin();return;}if(!r.ok)return;sData=await r.json();const now=Date.now();if(prevUploadBytes===null||prevDownloadBytes===null){prevUploadBytes=sData.upload_bytes;prevDownloadBytes=sData.download_bytes;prevStatsTime=now;safeSetHTML('sv-down-speed','0 B/s');safeSetHTML('sv-up-speed','0 B/s');}else{const intervalSec=(now-prevStatsTime)/1000;if(intervalSec>0){let rawUpload=(sData.upload_bytes-prevUploadBytes)/intervalSec;let rawDownload=(sData.download_bytes-prevDownloadBytes)/intervalSec;if(sData.active_connections===0){rawUpload=0;rawDownload=0;uploadSpeedAvg=0;downloadSpeedAvg=0;}else{uploadSpeedAvg=rawUpload*0.3+uploadSpeedAvg*0.7;downloadSpeedAvg=rawDownload*0.3+downloadSpeedAvg*0.7;}safeSetHTML('sv-down-speed',formatSpeed(downloadSpeedAvg));safeSetHTML('sv-up-speed',formatSpeed(uploadSpeedAvg));updSpeedChart(uploadSpeedAvg,downloadSpeedAvg);}prevUploadBytes=sData.upload_bytes;prevDownloadBytes=sData.download_bytes;prevStatsTime=now;}safeSetHTML('sv-traffic',(sData.total_traffic_mb||0)+' <span class="stat-unit">MB</span>');safeSetText('sv-requests',sData.total_requests);safeSetText('sv-uptime',sData.uptime);safeSetHTML('sv-disk',(sData.disk_free_gb||0)+' <span class="stat-unit">GB</span>');safeSetText('last-up','Updated '+getLocalTimeString());if(sData.cpu_percent!==undefined&&sData.cpu_percent!==null){const c=sData.cpu_percent;safeSetText('cpu-v',c.toFixed(1)+'%');const bar=$m('cpu-b');if(bar)bar.style.width=c+'%';}else{safeSetText('cpu-v','N/A');const bar=$m('cpu-b');if(bar)bar.style.width='0%';}if(sData.memory_percent!==undefined){const m=sData.memory_percent;safeSetText('mem-v',m.toFixed(1)+'%');const bar=$m('mem-b');if(bar)bar.style.width=m+'%';}const monthlyUsageGB=sData.monthly_usage_bytes?sData.monthly_usage_bytes/1e9:0;const monthlyLimitGB=sData.monthly_limit_bytes?sData.monthly_limit_bytes/1e9:0;safeSetHTML('sv-monthly',monthlyUsageGB.toFixed(1)+' GB'+(monthlyLimitGB>0?' / '+monthlyLimitGB.toFixed(1)+' GB':''));updChart();updDoughnutChart();}catch(err){console.error('loadStats error:',err);}}
async function loadLinks(){try{const r=await fetch('/api/links');if(r.status===401){showLogin();return;}if(!r.ok)return;const d=await r.json();allLinks=d.links||[];filterLinks();}catch(e){console.error('loadLinks error:',e);}}
function setFilter(f,el){cf=f;document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));el.classList.add('active');filterLinks();}
function filterLinks(){const q=($m('srch')?.value||'').toLowerCase();let r=allLinks;if(cf==='active')r=r.filter(l=>l.active);else if(cf==='off')r=r.filter(l=>!l.active);if(q)r=r.filter(l=>l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));renderLinks(r);}
function renderLinks(links){const tb=$m('ltb'),em=$m('lempty');if(!links||!links.length){tb.innerHTML='';em.style.display='block';return;}em.style.display='none';tb.innerHTML=links.map(l=>{const u=l.used_bytes||0,lim=l.limit_bytes||0,pct=lim>0?Math.min(100,(u/lim)*100):0,col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';const ex=fmtExp(l.expires_at),ec=ex==='Expired'?'var(--red)':ex==='∞'?'var(--text3)':'var(--text2)';const cc=l.current_connections||0,mc2=l.max_connections||0,check=selectedUids.has(l.uuid)?'checked':'';const flagEmoji=l.flag?codeToFlag(l.flag):'';const labelDisplay=(flagEmoji?flagEmoji+' ':'')+esc(l.label);return`<tr><td><input type="checkbox" value="${l.uuid}" ${check} onchange="toggleSelectUid('${l.uuid}')"></td><td style="font-weight:700">${labelDisplay}</td><td><span class="tag tag-vless">VLESS</span></td><td><div class="pill"><span class="pill-used">${fmtB(u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${pct}%;background:${col}"></div></div><span class="pill-lim">${fmtLim(lim)}</span></div></td><td>${cc}/${mc2||'∞'}</td><td style="color:${ec}">${ex}</td><td><span class="tag ${l.active?'tag-on':'tag-off'}">${l.active?'On':'Off'}</span></td><td><div style="display:flex;flex-direction:column;gap:4px;align-items:center"><button class="toggle ${l.active?'on':''}" data-uid="${l.uuid}" onclick="togLink(this)"></button><div class="act-group">${l.label==='This Server is Free'?`<button class="act-btn act-copy" onclick="cpLink('${esc(l.vless_link)}')">📋</button><button class="act-btn act-sub" onclick="cpSub('${l.uuid}')">🔗</button><button class="act-btn act-qr" onclick="showQR('${esc(l.vless_link)}')">📷</button>`:`<button class="act-btn act-edit" onclick="showEditMo('${l.uuid}')">✏️</button><button class="act-btn act-copy" onclick="cpLink('${esc(l.vless_link)}')">📋</button><button class="act-btn act-sub" onclick="cpSub('${l.uuid}')">🔗</button><button class="act-btn act-qr" onclick="showQR('${esc(l.vless_link)}')">📷</button><button class="act-btn act-del" onclick="delLink('${l.uuid}')">🗑️</button><button class="act-btn act-edit" onclick="regenerateUUID('${l.uuid}')">🔄</button><button class="act-btn act-del" onclick="disconnectLink('${l.uuid}')">🔌</button>`}</div></div></td></tr>`;}).join('');}
function toggleSelectUid(uid){selectedUids.has(uid)?selectedUids.delete(uid):selectedUids.add(uid);}
function toggleSelectAll(){const all=$m('select-all');const boxes=document.querySelectorAll('#ltb input[type=checkbox]');if(all.checked){boxes.forEach(c=>{c.checked=true;selectedUids.add(c.value);});}else{boxes.forEach(c=>{c.checked=false;selectedUids.clear();});}}
async function batchAction(action){if(selectedUids.size===0)return toast('No items selected',true);if(action==='delete'&&!confirm('Delete selected?'))return;try{const r=await fetch('/api/links/batch',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({uids:Array.from(selectedUids),action})});if(!r.ok){const d=await r.json();toast(d.detail||'Error',true);}else{selectedUids.clear();loadLinks();loadStats();}}catch{toast('Error',true);}}
async function regenerateUUID(uid){const r=await fetch('/api/links/'+uid+'/new-uuid',{method:'POST'});if(r.ok){loadLinks();toast('UUID regenerated');}}
async function disconnectLink(uid){await fetch('/api/links/'+uid+'/disconnect',{method:'POST'});toast('Disconnected');loadLinks();}
let sortCol='created_at',sortDir='desc';
function sortLinks(col){if(sortCol===col)sortDir=sortDir==='asc'?'desc':'asc';else{sortCol=col;sortDir='desc';}allLinks.sort((a,b)=>{let va=a[sortCol]??'',vb=b[sortCol]??'';if(sortCol==='used_bytes'){va=Number(va);vb=Number(vb);}else if(sortCol==='expires_at'){va=va||'';vb=vb||'';}if(va<vb)return sortDir==='asc'?-1:1;if(va>vb)return sortDir==='asc'?1:-1;return 0;});filterLinks();}
async function togLink(el){const uid=el.dataset.uid,l=allLinks.find(x=>x.uuid===uid);if(!l)return;const na=!l.active;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:na})});l.active=na;filterLinks();loadStats();}catch{toast('Failed',true);}}
async function randomInbound(){const names=['User','Client','Node','Peer'];const n=names[Math.floor(Math.random()*names.length)]+'-'+Math.floor(Math.random()*1000);try{await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:n,limit_value:0})});toast('Created '+n);loadLinks();loadStats();}catch{toast('Error',true);}}
function showAddMo(){$m('mo-add').classList.add('show');}
async function createLink(){const label=$m('nl').value.trim()||'This Server is Free';const uuid=$m('auuid').value.trim();const v=parseFloat($m('nv').value)||0,mc=parseInt($m('nc').value)||0,days=parseInt($m('nd').value)||0;const flagCode=$m('flag-code-create').value||'';const fragment=$m('afrag')?.value?.trim()||'';const body={label,uuid,limit_value:v,limit_unit:'GB',max_connections:mc,days_valid:days,custom_path:$m('ap').value.trim(),custom_sni:$m('asni').value.trim(),custom_host:$m('ahost').value.trim(),custom_fp:$m('afp').value.trim(),color:$m('alink-color')?.value||'#7c3aed',flag:flagCode,fragment:fragment};try{await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast('Created');$m('mo-add').classList.remove('show');loadLinks();loadStats();}catch{toast('Error',true);}}
function showEditMo(uid){const l=allLinks.find(x=>x.uuid===uid);if(!l)return;$m('eu').value=uid;$m('euuid').value=l.uuid;$m('en2').value=l.label;$m('el').value=l.limit_bytes>0?(l.limit_bytes/1073741824):'';$m('ec').value=l.max_connections||'';$m('ed').value='';$m('ep').value=l.custom_path||'';$m('esni').value=l.custom_sni||'';$m('ehost').value=l.custom_host||'';$m('efp').value=l.custom_fp||'chrome';$m('efrag').value=l.fragment||'';$m('e-color').value=l.color||'#7c3aed';const flag=l.flag||'';$m('flag-code-edit').value=flag;const sel=$m('flag-select-edit');if(flag&&['cn','nl','ru','us','ca','ir','de','gb','it','fr','tr','ae'].includes(flag)){sel.value=flag;$m('flag-custom-edit').style.display='none';}else if(flag){sel.value='custom';$m('flag-custom-edit').style.display='block';$m('flag-custom-edit').value=flag;}else{sel.value='';$m('flag-custom-edit').style.display='none';}$m('et').textContent='✏️ Edit: '+l.label;$m('mo-edit').classList.add('show');}
async function saveEdit(){const uid=$m('eu').value,v=parseFloat($m('el').value)||0,mc=parseInt($m('ec').value)||0,days=parseInt($m('ed').value)||0;const flagCode=$m('flag-code-edit').value||'';const fragment=$m('efrag').value.trim()||'';const body={limit_value:v,limit_unit:'GB',max_connections:mc,label:$m('en2').value.trim(),custom_path:$m('ep').value.trim(),custom_sni:$m('esni').value.trim(),custom_host:$m('ehost').value.trim(),custom_fp:$m('efp').value.trim(),color:$m('e-color').value,flag:flagCode,fragment:fragment};if(days)body.days_valid=days;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast('Updated');$m('mo-edit').classList.remove('show');loadLinks();}catch{toast('Error',true);}}
async function resetTraf(){const uid=$m('eu').value;if(!confirm('Reset?'))return;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('Reset');loadLinks();}catch{toast('Error',true);}}
async function delLink(uid){if(!confirm('Delete?'))return;try{const r=await fetch('/api/links/'+uid,{method:'DELETE'});if(!r.ok){const d=await r.json();toast(d.detail||'Error',true);}else{toast('Deleted');loadLinks();loadStats();}}catch{toast('Error',true);}}
function cpLink(txt){navigator.clipboard.writeText(txt).then(()=>toast('Copied!')).catch(()=>toast('Failed',true));}
async function cpSub(uid){await navigator.clipboard.writeText('https://'+location.host+'/user/'+uid);toast('User Dashboard URL copied!');}
function showQR(txt){if(txt.length>2000){toast('Link too long for QR',true);return;}const img=$m('qr-img');img.src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(txt);$m('mo-qr').classList.add('show');}
function dlQR(){const a=document.createElement('a');a.href=$m('qr-img').src;a.download='sulgx-qr.png';a.click();}

function initChart(){const ctx=$m('tc');if(!ctx||tChart)return;tChart=new Chart(ctx,{type:'bar',data:{labels:[],datasets:[{label:'MB',data:[],backgroundColor:'rgba(124,58,237,0.5)',borderColor:'#7c3aed',borderWidth:2,barPercentage:0.7}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'var(--text3)'},grid:{display:false}},y:{ticks:{color:'var(--text3)'},grid:{color:'var(--border)'},beginAtZero:true}}}});updChartColors();}
function updChartColors(){if(!tChart)return;const col='var(--text3)';tChart.options.scales.x.ticks.color=col;tChart.options.scales.y.ticks.color=col;tChart.update();}
function updChart(){if(!tChart||!sData.hourly_traffic)return;const labels=[],data=[];for(let h=0;h<24;h++){const key=`${h.toString().padStart(2,'0')}:00`;labels.push(key);data.push(Math.round((sData.hourly_traffic[key]||0)/1048576));}tChart.data.labels=labels;tChart.data.datasets[0].data=data;tChart.update();}
let doughnutChart=null;
function initDoughnutChart(){const ctx=$m('doughnut-chart');if(!ctx||doughnutChart)return;doughnutChart=new Chart(ctx,{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:[]}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'var(--text2)'}}},cutout:'65%'}});}
function updDoughnutChart(){if(!doughnutChart)return;const labels=[],data=[],colors=[];allLinks.filter(l=>l.used_bytes>0).forEach(l=>{labels.push(l.label);data.push(l.used_bytes);colors.push(l.color||'#7c3aed');});doughnutChart.data.labels=labels;doughnutChart.data.datasets[0].data=data;doughnutChart.data.datasets[0].backgroundColor=colors;doughnutChart.update();}
let speedChart=null,speedHistory=[];
function initSpeedChart(){const ctx=$m('speed-chart');if(!ctx||speedChart)return;speedChart=new Chart(ctx,{type:'line',data:{labels:[],datasets:[{label:'DL',borderColor:'#34d399',data:[],tension:0.3,pointRadius:0},{label:'UL',borderColor:'#f87171',data:[],tension:0.3,pointRadius:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'var(--text2)'}},tooltip:{callbacks:{label:ctx=>ctx.dataset.label+': '+formatSpeed(ctx.raw)}}},scales:{x:{ticks:{color:'var(--text3)',maxTicksLimit:10},grid:{display:false}},y:{ticks:{color:'var(--text3)',callback:v=>formatSpeed(v)},grid:{color:'var(--border)'},beginAtZero:true}}}});}
function updSpeedChart(up,down){if(!speedChart)return;const t=getLocalTimeString();speedHistory.push({t,up,down});if(speedHistory.length>60)speedHistory.shift();const maxVal=Math.max(...speedHistory.map(s=>Math.max(s.up,s.down)),1);speedChart.options.scales.y.max=maxVal*1.2;speedChart.data.labels=speedHistory.map(s=>s.t);speedChart.data.datasets[0].data=speedHistory.map(s=>s.down);speedChart.data.datasets[1].data=speedHistory.map(s=>s.up);speedChart.update();}

async function loadAddrs(){try{const r=await fetch('/api/addresses');if(r.status===401){showLogin();return;}if(!r.ok)return;allAddrs=(await r.json()).addresses||[];renderAddrs();}catch(e){console.error('loadAddrs error:',e);}}
function renderAddrs(){const el=$m('addr-list');if(!el)return;if(!allAddrs.length){el.innerHTML='<div class="empty">No addresses added</div>';return;}el.innerHTML=allAddrs.map((a,i)=>`<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--surface3);border-radius:var(--radius-sm);border:1px solid var(--border);margin-bottom:4px"><div style="display:flex;align-items:center;gap:8px"><input type="checkbox" class="addr-checkbox" data-index="${i}" ${selectedAddrIndices.has(i)?'checked':''} onchange="toggleSelectAddr(${i})"><span style="font-weight:600">${esc(a)}</span></div><div style="display:flex;gap:4px"><button class="act-btn act-edit" onclick="showEditAddr(${i})">✏️</button><button class="act-btn act-del" onclick="delAddr(${i})">🗑️</button></div></div>`).join('');}
function toggleSelectAddr(i){selectedAddrIndices.has(i)?selectedAddrIndices.delete(i):selectedAddrIndices.add(i);}
async function bulkDeleteAddrs(){if(selectedAddrIndices.size===0)return toast('No addresses selected',true);if(!confirm('Delete selected?'))return;const indices=Array.from(selectedAddrIndices);try{const r=await fetch('/api/addresses/bulk-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indices})});if(r.ok){selectedAddrIndices.clear();await loadAddrs();toast('Deleted selected');}}catch{toast('Error',true);}}
function showEditAddr(i){editingAddrIndex=i;$m('edit-addr-input').value=allAddrs[i];$m('mo-addr-edit').classList.add('show');}
async function saveAddrEdit(){const newAddr=$m('edit-addr-input').value.trim();if(!newAddr)return toast('Invalid address',true);try{const r=await fetch('/api/addresses/'+editingAddrIndex,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:newAddr})});if(r.ok){toast('Address updated');$m('mo-addr-edit').classList.remove('show');await loadAddrs();}else{const d=await r.json();toast(d.detail||'Error updating',true);}}catch{toast('Error',true);}}
async function addBatchAddrs(){const raw=$m('batch-addrs').value;const lines=raw.split('\n').map(l=>l.trim()).filter(l=>l);if(!lines.length)return;try{const r=await fetch('/api/addresses/batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({addresses:lines})});if(r.status===401){showLogin();return;}const d=await r.json();toast(`Added ${d.added} addresses`+(d.errors?` (${d.errors} errors)`:''));$m('batch-addrs').value='';await loadAddrs();}catch{toast('Batch add failed',true);}}
async function deleteAllAddrs(){if(!confirm('Delete all addresses?'))return;try{await fetch('/api/addresses',{method:'DELETE'});toast('All deleted');await loadAddrs();}catch{toast('Error',true);}}
async function delAddr(i){if(!confirm('Delete?'))return;try{await fetch('/api/addresses/'+i,{method:'DELETE'});toast('Deleted');await loadAddrs();}catch{toast('Error',true);}}
async function exportLinks(){try{const r=await fetch('/api/export-links');const data=await r.json();const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='sulgx-links.json';a.click();}catch{toast('Export failed',true);}}
async function importLinks(input){const file=input.files[0];if(!file)return;try{const text=await file.text();const data=JSON.parse(text);const r=await fetch('/api/import-links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const res=await r.json();toast(`Imported ${res.imported} links`);loadLinks();loadStats();}catch{toast('Import failed',true);}input.value='';}

let currentProvider=null;
const dnsRanges=new Set(['1.1.1.1','1.0.0.1','9.9.9.9','149.112.112.112','208.67.222.222','208.67.220.220']);
const providerIPs={"arvancloud":{"ipv4":["185.143.232.0/22","188.229.116.16/30","94.101.182.0/27","2.144.3.128/28","37.32.16.0/27","37.32.17.0/27","37.32.18.0/27","37.32.19.0/27","185.215.232.0/22","178.131.120.48/28","185.143.235.0/24"]},"cloudflare":{"ipv4":["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"]},"fastly":{"ipv4":["23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23","103.245.224.0/24","104.156.80.0/20","140.248.64.0/18","140.248.128.0/17","146.75.0.0/17","151.101.0.0/16","157.52.64.0/18","167.82.0.0/17","167.82.128.0/20","167.82.160.0/20","167.82.224.0/20","172.111.64.0/18","185.31.16.0/22","199.27.72.0/21","199.232.0.0/16"]},"Google":{"ipv4":["34.0.0.0/15","34.2.0.0/16","34.64.0.0/10","34.128.0.0/10","35.216.0.0/14","104.132.0.0/14"]},"Railway":{"ipv4":["69.46.46.0/24","208.77.244.0/24","208.77.245.0/24","208.77.246.0/24","208.77.247.0/24","208.77.248.0/24"]},"GitHub":{"ipv4":["140.82.112.0/20","143.55.64.0/20","192.30.252.0/22"]},"Netflix":{"ipv4":["23.246.0.0/18","37.77.184.0/21","45.57.0.0/17","64.120.128.0/17","66.197.128.0/17","69.53.224.0/19","198.45.48.0/20"]},"Spotify":{"ipv4":["23.92.96.0/20","78.31.8.0/22","193.182.8.0/21","193.235.232.0/24"]}};
function buildProviderPills(){const container=$m('provider-btns');if(!container)return;container.innerHTML='';Object.keys(providerIPs).forEach(prov=>{const btn=document.createElement('button');btn.className='chip';btn.textContent=prov;btn.onclick=()=>selectProvider(prov,btn);if(prov==='Railway')btn.classList.add('railway-hl');container.appendChild(btn);});const customBtn=document.createElement('button');customBtn.className='chip';customBtn.textContent='Custom';customBtn.onclick=()=>selectProvider('Custom',customBtn);container.appendChild(customBtn);}
function selectProvider(prov,btn){document.querySelectorAll('#provider-btns .chip').forEach(b=>b.classList.remove('active'));btn.classList.add('active');currentProvider=prov;const rangeSection=$m('range-section'),railNote=$m('railway-note');if(prov==='Custom'){rangeSection.style.display='none';railNote.style.display='none';$m('scan-ips').value='';return;}rangeSection.style.display='flex';railNote.style.display=(prov==='Railway')?'block':'none';const rangeBtns=$m('range-btns');rangeBtns.innerHTML='';const ranges=providerIPs[prov]?.ipv4||[];ranges.forEach(r=>{const b=document.createElement('button');b.className='chip';b.textContent=r;b.onclick=()=>{loadRangeIPs(r,b);};rangeBtns.appendChild(b);});const allIPs=[];ranges.forEach(r=>{allIPs.push(...expandCIDR(r));});$m('scan-ips').value=allIPs.join('\n');}
function loadRangeIPs(range,btn){document.querySelectorAll('#range-btns .chip').forEach(b=>b.classList.remove('active'));if(btn)btn.classList.add('active');$m('scan-ips').value=expandCIDR(range).join('\n');}
function expandCIDR(cidr){const parts=cidr.split('/');if(parts.length!==2)return[cidr];const ip=parts[0].trim(),mask=parseInt(parts[1]);if(isNaN(mask)||mask<16||mask>32)return[cidr];const ipParts=ip.split('.').map(Number);if(ipParts.length!==4||ipParts.some(p=>isNaN(p)||p>255))return[cidr];const count=Math.pow(2,32-mask);const limit=Math.min(count,256);if(count>limit)toast('Large range: only first 256 IPs extracted.');const start=(ipParts[0]<<24)+(ipParts[1]<<16)+(ipParts[2]<<8)+ipParts[3];const base=start&(~((1<<(32-mask))-1));const result=[];for(let i=0;i<limit;i++){const addr=base+i;const ipStr=`${(addr>>>24)&255}.${(addr>>>16)&255}.${(addr>>>8)&255}.${addr&255}`;if(dnsRanges.has(ipStr))continue;result.push(ipStr);}return result;}
let totalScanCount=0,scannedCount=0,wsScanner=null;
function stopScan(){if(wsScanner){wsScanner.close();wsScanner=null;}$m('scan-start-btn').style.display='inline-flex';$m('scan-stop-btn').style.display='none';}
async function startIPScan(){const raw=$m('scan-ips').value;const lines=raw.split('\n').map(l=>l.trim()).filter(l=>l);if(!lines.length)return;const items=[];lines.forEach(l=>{if(l.includes('/'))items.push(...expandCIDR(l));else if(!dnsRanges.has(l.trim()))items.push(l.trim());});const unique=[...new Set(items)];const MAX_IPS=256;if(unique.length>MAX_IPS){toast(`Max ${MAX_IPS} IPs allowed. You entered ${unique.length}.`,true);return;}totalScanCount=unique.length;scannedCount=0;$m('scan-tbody').innerHTML='';$m('scan-progress').style.width='0%';$m('progress-text').textContent='0%';$m('scan-start-btn').style.display='none';$m('scan-stop-btn').style.display='inline-flex';if(wsScanner)wsScanner.close();const proto=location.protocol==='https:'?'wss:':'ws:';wsScanner=new WebSocket(`${proto}//${location.host}/ws/scanner`);wsScanner.onopen=()=>wsScanner.send(JSON.stringify({ips:unique}));wsScanner.onmessage=(e)=>{const d=JSON.parse(e.data);if(d.done){wsScanner.close();$m('scan-start-btn').style.display='inline-flex';$m('scan-stop-btn').style.display='none';toast('Scan finished.');return;}scannedCount++;const pct=Math.round((scannedCount/totalScanCount)*100);$m('scan-progress').style.width=pct+'%';$m('progress-text').textContent=pct+'%';const row=`<tr><td>${esc(d.ip)}</td><td style="color:${d.ok?'var(--green)':'var(--red)'}">${d.ok?'✅ Reachable':'❌ Failed'}</td><td>${d.latency?d.latency+' ms':'–'}</td></tr>`;$m('scan-tbody').insertAdjacentHTML('beforeend',row);};wsScanner.onerror=()=>{toast('Scanner error (timeout?)',true);$m('scan-start-btn').style.display='inline-flex';$m('scan-stop-btn').style.display='none';};wsScanner.onclose=()=>{$m('scan-start-btn').style.display='inline-flex';$m('scan-stop-btn').style.display='none';};}
function sortBestIPs(){const rows=Array.from($m('scan-tbody').querySelectorAll('tr'));const items=[];rows.forEach(r=>{const cells=r.querySelectorAll('td');const ip=cells[0].textContent.trim();const ok=cells[1].textContent.includes('✅');const lat=parseFloat(cells[2].textContent);if(ok&&!isNaN(lat))items.push({ip,lat});});if(items.length===0){toast('No reachable IPs',true);return;}items.sort((a,b)=>a.lat-b.lat);$m('scan-tbody').innerHTML=items.map(i=>`<tr><td>${esc(i.ip)}</td><td style="color:var(--green)">✅ Reachable</td><td>${i.lat} ms</td></tr>`).join('');}
function copyReachableSorted(){const rows=Array.from($m('scan-tbody').querySelectorAll('tr'));const reachable=[];rows.forEach(r=>{const cells=r.querySelectorAll('td');const ip=cells[0].textContent.trim();const ok=cells[1].textContent.includes('✅');const lat=parseFloat(cells[2].textContent);if(ok&&!isNaN(lat))reachable.push({ip,lat});});if(reachable.length===0){toast('No reachable IPs found',true);return;}reachable.sort((a,b)=>a.lat-b.lat);navigator.clipboard.writeText(reachable.map(item=>item.ip).join('\n')).then(()=>toast(`Copied ${reachable.length} IPs sorted by latency`)).catch(()=>toast('Failed to copy',true));}

async function loadLogs(){try{const r=await fetch('/api/logs');if(r.status===401){showLogin();return;}const d=await r.json();const logs=d.logs||[];const tbody=$m('logs-tbody'),empty=$m('logs-empty');if(!tbody)return;if(!logs.length){tbody.innerHTML='';empty.style.display='block';return;}empty.style.display='none';tbody.innerHTML=logs.map((l,i)=>{const local=new Date(l.time);local.setMinutes(local.getMinutes()+local.getTimezoneOffset()+timezoneOffset*60);return`<tr><td>${i+1}</td><td>${local.toISOString().replace('T',' ').split('.')[0]}</td><td>${esc(l.type||'Event')}</td><td>${esc(l.error||'')}</td></tr>`;}).join('');}catch(err){console.error('loadLogs error:',err);}}
async function loadLoginLogs(){try{const r=await fetch('/api/login-logs');if(!r.ok)return;const d=await r.json();const tbody=$m('login-logs-tbody');if(!tbody)return;tbody.innerHTML=d.logs.map(l=>`<tr><td>${timeAgo(l.timestamp)}</td><td><div style="font-weight:600">${esc(l.ip)}</div><div style="font-size:0.7rem;color:var(--text3);max-width:140px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(l.user_agent)}">${esc(l.user_agent)}</div></td><td style="color:${l.success?'var(--green)':'var(--red)'}">${l.success?'✅ Success':'❌ Failed'}</td></tr>`).join('');}catch(e){}}
function timeAgo(ts){const then=new Date(ts),now=new Date(),diff=Math.floor((now-then)/1000);if(diff<60)return'Just now';if(diff<3600)return Math.floor(diff/60)+'m ago';if(diff<86400)return Math.floor(diff/3600)+'h ago';return new Date(ts).toLocaleDateString();}
async function loadTelegramSettings(){try{const r=await fetch('/api/settings');if(r.status===401){showLogin();return;}const d=await r.json();$m('tg-token').value=d.tg_bot_token||'';$m('tg-chat-id').value=d.tg_chat_id||'';$m('tg-interval').value=d.telegram_interval||'1';const events=(d.telegram_events||'').split(',');document.querySelectorAll('.tg-event').forEach(cb=>cb.checked=events.includes(cb.value));$m('tg-templates-en').value=d.telegram_templates_en||'{"quota_90":"⚠️ {label} ({uid}) used 90% of quota","login":"🔐 SulgX Panel login\\n🌐 IP: {ip}\\n🤖 UA: {ua}\\n📅 {time}","expiry":"⏰ {label} expired","error":"❌ Error on {label}: check logs"}';$m('tg-templates-fa').value=d.telegram_templates_fa||'{"quota_90":"⚠️ {label} ({uid}) ۹۰٪ کوتا","login":"🔐 ورود SulgX\\n🌐 IP: {ip}\\n🤖 UA: {ua}\\n📅 {time}","expiry":"⏰ {label} منقضی شد","error":"❌ خطا در {label}: بررسی شود"}';const tgLang=d.telegram_lang||'en';const toggle=$m('tg-lang-toggle');if(tgLang==='fa'){toggle.classList.remove('on');$m('tg-lang-label').textContent='فارسی';$m('tg-lang-hidden').value='fa';}else{toggle.classList.add('on');$m('tg-lang-label').textContent='English';$m('tg-lang-hidden').value='en';}}catch(err){console.error('loadTelegram error:',err);}}
async function saveTelegramSettings(){const token=$m('tg-token').value.trim(),chat=$m('tg-chat-id').value.trim();const interval=$m('tg-interval').value.trim();const events=Array.from(document.querySelectorAll('.tg-event:checked')).map(cb=>cb.value).join(',');const templates_en=$m('tg-templates-en').value.trim();const templates_fa=$m('tg-templates-fa').value.trim();const tglang=$m('tg-lang-hidden').value;try{await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tg_bot_token:token,tg_chat_id:chat,telegram_interval:interval,telegram_events:events,telegram_templates_en:templates_en,telegram_templates_fa:templates_fa,telegram_lang:tglang})});toast('Saved');}catch{toast('Error',true);}}
async function testTelegram(){const token=$m('tg-token').value.trim(),chat=$m('tg-chat-id').value.trim();if(!token||!chat){toast('Fill token and chat ID',true);return;}const tglang=$m('tg-lang-hidden').value;const msg=tglang==='fa'?'✅ SulgX متصل شد':'✅ SulgX is connected';try{const res=await fetch(`https://api.telegram.org/bot${token}/sendMessage`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:chat,text:msg})});if(res.ok)toast('Test message sent!');else toast('Failed to send',true);}catch{toast('Error',true);}}
function toggleTgLang(){const toggle=$m('tg-lang-toggle');toggle.classList.toggle('on');const isEn=toggle.classList.contains('on');$m('tg-lang-label').textContent=isEn?'English':'فارسی';$m('tg-lang-hidden').value=isEn?'en':'fa';}
function previewTemplate(){const isEn=$m('tg-lang-toggle').classList.contains('on');const targetId=isEn?'tg-templates-en':'tg-templates-fa';const textarea=$m(targetId);const previewDiv=$m('tg-preview');if(!textarea||!previewDiv)return;try{const sanitized=textarea.value.replace(/[\u0000-\u001f]/g,function(ch){if(ch==='\n')return'\\n';if(ch==='\r')return'\\r';if(ch==='\t')return'\\t';return'';});const templates=JSON.parse(sanitized);const mockData={label:"SulgX_User",uid:"sulgx-7b8c-49ed-b45a",ip:"85.201.32.44",ua:"Mozilla/5.0 (iPhone; iOS 18)",time:new Date().toISOString().replace('T',' ').substring(0,19)};let html="";for(const[key,templateText]of Object.entries(templates)){let text=templateText;text=text.replace(/{label}/g,mockData.label).replace(/{uid}/g,mockData.uid).replace(/{ip}/g,mockData.ip).replace(/{ua}/g,mockData.ua).replace(/{time}/g,mockData.time);html+=`<div style="margin-bottom:6px;border-bottom:1px solid var(--border);padding-bottom:4px"><span style="color:var(--primary);font-weight:700;font-size:0.75rem">[${key}]:</span><br>${text}</div>`;}const domain=window.location.host||'your-domain.com';html+=`<div style="margin-top:6px;padding-top:4px;color:var(--green)">⚠️ <i>Auto appended:</i><br>🔗 https://${domain}/panel</div>`;previewDiv.innerHTML=html;previewDiv.style.border='1px solid var(--primary)';}catch(e){previewDiv.innerHTML=`<span style="color:var(--red)">❌ Invalid JSON: ${e.message}</span>`;previewDiv.style.border='1px solid var(--red)';}}

async function loadGeneralSettings(){try{const r=await fetch('/api/settings');if(!r.ok)return;const d=await r.json();$m('set-footer').value=d.footer_text||'';$m('set-default-path').value=d.default_path||'';timezoneOffset=parseFloat(d.timezone_offset)||0;$m('set-default-limit').value=d.default_limit_bytes?(parseInt(d.default_limit_bytes)/1073741824).toFixed(1):'';$m('set-default-expiry').value=d.default_expiry_days||'';$m('set-default-maxconn').value=d.default_max_connections||'';$m('set-scanner-timeout').value=d.scanner_timeout||'4';$m('set-monthly-limit').value=d.monthly_limit_gb||'';$m('set-max-scan-ips').value=d.max_scan_ips||'256';$m('set-keep-alive-interval').value=d.keep_alive_interval||'300';updateSettingsStatus(d);updateDashboardStatusCards(d);if(d.keep_alive_mode){setKeepAliveMode(d.keep_alive_mode);$m('set-keepalive-enabled').value=d.keep_alive_enabled==='1'?'1':'0';const card=$m('card-keepalive');if(d.keep_alive_enabled==='1'){card.classList.add('active');card.classList.remove('inactive');}else{card.classList.add('inactive');card.classList.remove('active');}}if(timezoneOffset===3.5)setPanelTZ(3.5,'Tehran');else if(timezoneOffset===0)setPanelTZ(0,'UTC');else{toggleCustomTZInput(true);$m('custom-tz-value').value=timezoneOffset;}const savedTheme=d.theme_color||'dark';setPanelTheme(savedTheme);}catch(e){}}
async function saveGeneralSettings(){const footer=$m('set-footer').value.trim();const defPath=$m('set-default-path').value.trim();const logEnabled=$m('set-log-toggle').value;const themeColor=$m('set-theme-color')?.value||theme;const defLimit=parseFloat($m('set-default-limit').value)*1073741824;const defExpiry=$m('set-default-expiry').value.trim();const defMaxConn=$m('set-default-maxconn').value.trim();const scannerTimeout=$m('set-scanner-timeout').value.trim();const monthlyLimit=$m('set-monthly-limit').value.trim();const maxScanIps=$m('set-max-scan-ips').value.trim();const keepAliveInterval=$m('set-keep-alive-interval').value.trim();const keepAliveEnabled=$m('set-keepalive-enabled').value;var keepAliveModeEl=$m('set-keepalive-mode');var keepAliveMode=keepAliveModeEl?keepAliveModeEl.value:'simple';const autoDisable=$m('set-auto-disable').value;const tgReport=$m('set-tg-report').value;const tgNotify=$m('set-tg-notify').value;try{await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({footer_text:footer,default_path:defPath,timezone_offset:timezoneOffset,log_enabled:logEnabled,theme_color:themeColor,default_lang:lang,default_limit_bytes:isNaN(defLimit)?'':String(Math.round(defLimit)),default_expiry_days:defExpiry,default_max_connections:defMaxConn,scanner_timeout:scannerTimeout,monthly_limit_gb:monthlyLimit,max_scan_ips:maxScanIps,keep_alive_interval:keepAliveInterval,keep_alive_enabled:keepAliveEnabled,keep_alive_mode:keepAliveMode,auto_disable_enabled:autoDisable,telegram_report_enabled:tgReport,telegram_notify_enabled:tgNotify})});toast('Saved');loadGeneralSettings();}catch{toast('Error',true);}}
function generateUUID(id){const uuid=crypto.randomUUID?crypto.randomUUID():'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,c=>{const r=Math.random()*16|0;return(c=='x'?r:(r&0x3|0x8)).toString(16);});$m(id).value=uuid;}
function toggleAdv(id){const el=$m(id);el.style.display=el.style.display==='none'?'block':'none';}
function filterLogs(){const q=($m('log-search').value||'').toLowerCase();document.querySelectorAll('#logs-tbody tr').forEach(row=>{if(!q){row.style.display='';return;}row.style.display=row.innerText.toLowerCase().includes(q)?'':'none';});}
function clearLogSearch(){$m('log-search').value='';filterLogs();}
async function clearLogs(){if(!confirm('Clear all logs?'))return;await fetch('/api/logs/clear',{method:'DELETE'});loadLogs();}
async function fetchLogSize(){const r=await fetch('/api/logs/size');const d=await r.json();toast(`Log entries: ${d.count}, Size: ${d.size_kb} KB`);}
async function resetAllSettings(){if(!confirm('Are you sure? All settings (except password) will reset to defaults.'))return;try{const r=await fetch('/api/settings/reset',{method:'POST'});if(!r.ok)throw new Error((await r.json()).detail);toast('Settings reset. Reloading...');setTimeout(()=>location.reload(),1500);}catch(e){toast(e.message,true);}}
async function chgPw(){const cur=$m('cpw').value,nw=$m('npw').value;if(!cur||!nw){toast('Fill fields',true);return;}if(nw.length<8){toast('Password must be at least 8 characters',true);return;}if(!/[A-Z]/.test(nw)||!/[a-z]/.test(nw)||!/[0-9]/.test(nw)){toast('Password must contain uppercase, lowercase, and digit',true);return;}try{const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});if(!r.ok)throw new Error((await r.json()).detail||'Error');toast('Password updated');}catch(e){toast(e.message,true);}}

function applyProfile(){const p=$m('eres-profile').value;if(!p)return;const pr={default:{path:'',sni:'',host:'',fp:'chrome'},youtube:{path:'/youtubei/v1/image',sni:'www.youtube.com',host:'www.youtube.com',fp:'chrome'},instagram:{path:'/graphql',sni:'www.instagram.com',host:'www.instagram.com',fp:'chrome'},twitter:{path:'/ws',sni:'twitter.com',host:'twitter.com',fp:'chrome'},tiktok:{path:'/ws',sni:'www.tiktok.com',host:'www.tiktok.com',fp:'chrome'},whatsapp:{path:'/ws/chat/v4',sni:'web.whatsapp.com',host:'web.whatsapp.com',fp:'safari'},telegram:{path:'/ws',sni:'telegram.org',host:'telegram.org',fp:'chrome'},netflix:{path:'/ws',sni:'www.netflix.com',host:'www.netflix.com',fp:'chrome'},spotify:{path:'/ws',sni:'www.spotify.com',host:'www.spotify.com',fp:'chrome'},google:{path:'/ws',sni:'www.google.com',host:'www.google.com',fp:'chrome'}};if(pr[p]){$m('ep').value=pr[p].path||'';$m('esni').value=pr[p].sni||'';$m('ehost').value=pr[p].host||'';$m('efp').value=pr[p].fp||'chrome';}}
function applyProfileCreate(){const p=$m('ares-profile').value;if(!p)return;const pr={default:{path:'',sni:'',host:'',fp:'chrome'},youtube:{path:'/youtubei/v1/image',sni:'www.youtube.com',host:'www.youtube.com',fp:'chrome'},instagram:{path:'/graphql',sni:'www.instagram.com',host:'www.instagram.com',fp:'chrome'},twitter:{path:'/ws',sni:'twitter.com',host:'twitter.com',fp:'chrome'},tiktok:{path:'/ws',sni:'www.tiktok.com',host:'www.tiktok.com',fp:'chrome'},whatsapp:{path:'/ws/chat/v4',sni:'web.whatsapp.com',host:'web.whatsapp.com',fp:'safari'},telegram:{path:'/ws',sni:'telegram.org',host:'telegram.org',fp:'chrome'},netflix:{path:'/ws',sni:'www.netflix.com',host:'www.netflix.com',fp:'chrome'},spotify:{path:'/ws',sni:'www.spotify.com',host:'www.spotify.com',fp:'chrome'},google:{path:'/ws',sni:'www.google.com',host:'www.google.com',fp:'chrome'}};if(pr[p]){$m('ap').value=pr[p].path||'';$m('asni').value=pr[p].sni||'';$m('ahost').value=pr[p].host||'';$m('afp').value=pr[p].fp||'chrome';}}
function applyFlagCreate(){const sel=$m('flag-select-create').value;const customInput=$m('flag-custom-create');const hidden=$m('flag-code-create');if(sel==='custom'){customInput.style.display='block';hidden.value=customInput.value.trim().toLowerCase();}else{customInput.style.display='none';hidden.value=sel;}}
function applyFlagEdit(){const sel=$m('flag-select-edit').value;const customInput=$m('flag-custom-edit');const hidden=$m('flag-code-edit');if(sel==='custom'){customInput.style.display='block';hidden.value=customInput.value.trim().toLowerCase();}else{customInput.style.display='none';hidden.value=sel;}}

document.addEventListener('keydown',e=>{if(e.ctrlKey||e.metaKey){const pages=['dashboard','inbounds','addresses','ipscanner','logs','telegram','settings'];const num=parseInt(e.key);if(num>=1&&num<=pages.length)switchPage(pages[num-1]);}});
if(window.matchMedia('(prefers-color-scheme: dark)').matches&&!localStorage.getItem('theme'))setTheme('dark');
setTheme(theme);setLang(lang);checkAuth();
setInterval(()=>{if(isAuthenticated){loadStats();loadLinks();}},12000);
</script>
</body>
</html>"""
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_class=HTMLResponse)
async def panel_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

if __name__ == "__main__":
    import sys
    import subprocess
    import os
    port = int(os.environ.get("PORT", CONFIG.get("port", 8000)))
    logger.info(f"Starting SulgX Panel on port {port}")
    try:
        subprocess.run(
            [
                sys.executable, "-m", "uvicorn",
                "main:app",
                "--host", "0.0.0.0", 
                "--port", str(port),  
                "--proxy-headers",
                "--forwarded-allow-ips", "*"
            ],
            check=True
        )
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)
