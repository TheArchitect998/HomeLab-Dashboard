#!/usr/bin/env python3
import asyncio
import getpass
import hashlib
import hmac
import importlib.util
import json
import logging
import math
import os
import pathlib
import re
import secrets
import smtplib
import sqlite3
import ssl
import sys
import tempfile
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime
from email.message import EmailMessage
from types import SimpleNamespace
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

def env(name, default=None):
    """Read LABGUARD_<name>, falling back to the legacy HOMELAB_<name> variable."""
    return os.environ.get(f"LABGUARD_{name}", os.environ.get(f"HOMELAB_{name}", default))


config_file = env("DASHBOARD_CONFIG")
if config_file:
    spec = importlib.util.spec_from_file_location("cfg", pathlib.Path(config_file))
    cfg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cfg)
else:
    try:
        urls = json.loads(os.environ.get("AGENT_URLS", "[]"))
    except json.JSONDecodeError as error:
        raise RuntimeError("AGENT_URLS must be a JSON array of URLs") from error
    if not isinstance(urls, list) or any(not isinstance(url, str) or not url.strip() for url in urls):
        raise RuntimeError("AGENT_URLS must be a JSON array of non-empty URLs")
    agents = {}
    for index, url in enumerate(urls):
        url = url.rstrip("/")
        if url.endswith("/api/metrics"):
            url = url[:-len("/api/metrics")]
        agents[f"agent-{index + 1}"] = {"url": url}
        if os.environ.get("AGENT_CA_CERT"):
            agents[f"agent-{index + 1}"]["ca_cert"] = os.environ["AGENT_CA_CERT"]
    cfg = SimpleNamespace(AGENTS=agents, AGENT_KEY=os.environ.get("AGENT_KEY", ""),
                          STATE_DIR=env("STATE_DIR", "/opt/labguard/state"))

STATE_DIR = pathlib.Path(getattr(cfg, "STATE_DIR", "/opt/labguard/state"))
STATE_FILE = STATE_DIR / "settings.json"
ITERATIONS = 600_000
SESSION_SECONDS = 12 * 60 * 60
EVENT_TYPES = {"ssh_login", "ssh_logout", "fail2ban", "docker"}
HISTORY_INTERVAL = 60
HISTORY_RETENTION = 30 * 24 * 60 * 60
HISTORY_BUCKETS = {1: 60, 24: 300, 168: 3600, 720: 14400}
hardware_checked = {}
PROVIDERS = ("telegram", "discord", "ntfy", "pushover", "email", "webhook", "gotify")
EDITABLE_PROVIDERS = PROVIDERS[1:]
CHECK_TYPES = ("ping", "http", "tcp", "dns")
CHECK_INTERVAL = 60
CHECK_FAILURES = 2
MAX_CHECKS = 50
check_status = {}
check_failures = {}
logger = logging.getLogger("labguard")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
sessions = {}
login_attempts = {}
settings_lock = threading.Lock()
provider_locks = {}
provider_failures = {}


@asynccontextmanager
async def lifespan(app):
    tasks = [asyncio.create_task(coroutine()) for coroutine in (notify_loop, monitoring_loop, history_loop, checks_loop)]
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass


app = FastAPI(title="LabGuard", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
FRONTEND_DIR = pathlib.Path(__file__).parent / "frontend"
if pathlib.Path(__file__).parent.name == "backend" and not FRONTEND_DIR.is_dir():
    FRONTEND_DIR = pathlib.Path(__file__).parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR), check_dir=False), name="static")


def read_settings():
    if not STATE_FILE.exists():
        return {}
    with STATE_FILE.open(encoding="utf-8") as file:
        return json.load(file)


def write_settings(settings):
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, filename = tempfile.mkstemp(dir=STATE_DIR, prefix=".settings-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(settings, file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(filename, STATE_FILE)
    finally:
        if os.path.exists(filename):
            os.unlink(filename)


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS)
    return {"salt": salt, "hash": digest.hex()}


def check_password(password, saved):
    return hmac.compare_digest(password_hash(password, saved["salt"])["hash"], saved["hash"])


def validate_password(password):
    if len(password) < 12 or len(password) > 1024:
        raise HTTPException(400, "Password must contain 12 to 1024 characters")


def require_session(request):
    token = request.cookies.get("labguard_session", "")
    expiry = sessions.get(token, 0)
    if expiry <= time.time():
        sessions.pop(token, None)
        raise HTTPException(401, "Authentication required")


@app.middleware("http")
async def protect_api(request, call_next):
    if request.url.path.startswith("/api/"):
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("origin")
            if request.headers.get("x-requested-with") != "LabGuard" or (
                origin and urlsplit(origin).netloc != request.headers.get("host")
            ):
                return JSONResponse({"detail": "Invalid request origin"}, status_code=403)
        if request.url.path not in ("/api/auth/status", "/api/auth/login"):
            try:
                require_session(request)
            except HTTPException as error:
                return JSONResponse({"detail": error.detail}, status_code=error.status_code)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosiff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


class PasswordInput(BaseModel):
    password: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class TelegramInput(BaseModel):
    enabled: bool
    chat_id: str
    token: str = ""
    events: list[str]


class ProviderInput(BaseModel):
    enabled: bool
    events: list[str]
    webhook_url: str = ""
    server_url: str = ""
    topic: str = ""
    token: str = ""
    user_key: str = ""
    clear_token: bool = False
    host: str = ""
    port: int = 587
    security: str = "starttls"
    username: str = ""
    password: str = ""
    sender: str = ""
    recipient: str = ""


class MonitoringInput(BaseModel):
    temperature_enabled: bool = False
    hardware_enabled: bool = False
    daily_report: bool = False
    daily_report_time: str | None = None
    thresholds: dict[str, float] = {}


@app.get("/api/auth/status")
def auth_status(request: Request):
    configured = "password" in read_settings()
    return {"configured": configured, "authenticated": sessions.get(request.cookies.get("labguard_session", ""), 0) > time.time()}


@app.post("/api/auth/login")
def login(data: PasswordInput, request: Request):
    with settings_lock:
        settings = read_settings()
        if "password" not in settings:
            raise HTTPException(503, "Password setup required on the dashboard host")
        address = request.client.host if request.client else "unknown"
        now = time.time()
        attempts = [t for t in login_attempts.get(address, []) if t > now - 300]
        if len(attempts) >= 5:
            raise HTTPException(429, "Too many login attempts; try again in five minutes")
        if len(data.password) > 1024 or not check_password(data.password, settings["password"]):
            attempts.append(now)
            login_attempts[address] = attempts
            raise HTTPException(401, "Invalid password")
        login_attempts.pop(address, None)
        for expired in [key for key, expiry in sessions.items() if expiry <= now]:
            sessions.pop(expired, None)
        token = secrets.token_urlsafe(32)
        sessions[token] = now + SESSION_SECONDS
    response = JSONResponse({"ok": True})
    response.set_cookie("labguard_session", token, max_age=SESSION_SECONDS, httponly=True,
                        secure=request.url.scheme == "https", samesite="strict", path="/")
    return response


@app.post("/api/auth/logout")
def logout(request: Request):
    sessions.pop(request.cookies.get("labguard_session", ""), None)
    response = JSONResponse({"ok": True})
    response.delete_cookie("labguard_session", path="/")
    return response


@app.post("/api/auth/password")
def change_password(data: PasswordChange):
    with settings_lock:
        settings = read_settings()
        if len(data.current_password) > 1024 or not check_password(data.current_password, settings["password"]):
            raise HTTPException(400, "Invalid current password")
        validate_password(data.new_password)
        settings["password"] = password_hash(data.new_password)
        write_settings(settings)
        sessions.clear()
    return {"ok": True}


@app.get("/api/telegram")
def get_telegram():
    telegram = read_settings().get("telegram", {})
    return {"enabled": telegram.get("enabled", False), "chat_id": telegram.get("chat_id", ""),
            "token_configured": bool(telegram.get("token")), "events": telegram.get("events", []),
            "delivery_paused": delivery_paused("telegram", telegram)}


@app.put("/api/telegram")
def set_telegram(data: TelegramInput):
    with settings_lock:
        settings = read_settings()
        old = settings.get("telegram", {})
        token = data.token.strip() or old.get("token", "")
        chat_id = "".join(c for c in data.chat_id if c.isprintable() and not c.isspace())
        chat_id = chat_id.translate({0x2010: "-", 0x2011: "-", 0x2012: "-", 0x2013: "-", 0x2014: "-", 0x2212: "-"})
        if set(data.events) - EVENT_TYPES:
            raise HTTPException(400, "Unknown event type")
        if data.enabled and (not token or not chat_id or not data.events):
            raise HTTPException(400, "Token, chat ID and at least one event are required")
        if token and (len(token) > 200 or not all(c.isascii() and (c.isalnum() or c in "_:-") for c in token)):
            raise HTTPException(400, "Invalid bot token")
        if chat_id and (len(chat_id) > 100 or not all(c.isascii() and (c.isalnum() or c in "_@-") for c in chat_id)):
            raise HTTPException(400, "Invalid chat ID")
        enabled_at = old.get("enabled_at", 0) if old.get("enabled") or not data.enabled else int(time.time())
        settings["telegram"] = {"enabled": data.enabled, "chat_id": chat_id, "token": token,
                                "events": sorted(set(data.events)), "enabled_at": enabled_at}
        write_settings(settings)
    return {"ok": True}


def enabled_providers(settings):
    providers = {"telegram": settings.get("telegram", {}), **settings.get("providers", {})}
    return {name: providers[name] for name in PROVIDERS if providers.get(name, {}).get("enabled")}


def delivery_paused(provider, settings):
    failure = provider_failures.get(provider)
    fingerprint = hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()
    return bool(failure and failure["fingerprint"] == fingerprint and failure["retry_at"] > time.time())


def valid_http_url(server):
    try:
        url = urlsplit(server)
        valid = (len(server) <= 1000 and url.scheme in ("http", "https") and bool(url.hostname)
                 and not url.username and not url.password and not url.fragment
                 and not any(c.isspace() or ord(c) < 32 for c in server))
        url.port
    except ValueError:
        return False
    return valid


def valid_address(address):
    return bool(re.fullmatch(r"[^@\s<>,;\"]{1,64}@[A-Za-z0-9.-]{1,253}", address))


@app.get("/api/notifications/{provider}")
def get_provider(provider: str):
    if provider not in EDITABLE_PROVIDERS:
        raise HTTPException(404, "Unknown notification provider")
    saved = read_settings().get("providers", {}).get(provider, {})
    return {"enabled": saved.get("enabled", False), "events": saved.get("events", []),
            "server_url": saved.get("server_url", "https://ntfy.sh" if provider == "ntfy" else ""),
            "webhook_configured": bool(saved.get("webhook_url")),
            "topic_configured": bool(saved.get("topic")), "token_configured": bool(saved.get("token")),
            "user_key_configured": bool(saved.get("user_key")), "delivery_paused": delivery_paused(provider, saved),
            "host": saved.get("host", ""), "port": saved.get("port", 587), "security": saved.get("security", "starttls"),
            "username": saved.get("username", ""), "password_configured": bool(saved.get("password")),
            "sender": saved.get("sender", ""), "recipient": saved.get("recipient", "")}


@app.put("/api/notifications/{provider}")
def set_provider(provider: str, data: ProviderInput):
    if provider not in EDITABLE_PROVIDERS:
        raise HTTPException(404, "Unknown notification provider")
    if set(data.events) - EVENT_TYPES:
        raise HTTPException(400, "Unknown event type")
    with settings_lock:
        settings = read_settings()
        providers = settings.get("providers", {})
        old = providers.get(provider, {})
        saved = {"enabled": data.enabled, "events": sorted(set(data.events)),
                 "enabled_at": old.get("enabled_at", 0) if old.get("enabled") or not data.enabled else int(time.time())}
        if provider == "discord":
            webhook = data.webhook_url.strip() or old.get("webhook_url", "")
            if webhook and (len(webhook) > 1000 or not re.fullmatch(
                r"https://(?:discord\.com|discordapp\.com)/api/(?:v\d+/)?webhooks/\d+/[A-Za-z0-9_-]+", webhook
            )):
                raise HTTPException(400, "Invalid Discord webhook URL")
            saved["webhook_url"] = webhook
            configured = bool(webhook)
        elif provider == "ntfy":
            server = data.server_url.strip().rstrip("/")
            topic = data.topic.strip() or old.get("topic", "")
            if data.clear_token and data.token.strip():
                raise HTTPException(400, "Cannot remove and replace the ntfy token at the same time")
            token = "" if data.clear_token else (data.token.strip() or old.get("token", ""))
            try:
                url = urlsplit(server)
                valid_url = (len(server) <= 1000 and url.scheme in ("http", "https") and bool(url.hostname)
                             and not url.username and not url.password and not url.query and not url.fragment
                             and not any(c.isspace() or ord(c) < 32 for c in server))
                url.port
            except ValueError:
                valid_url = False
            if server and not valid_url:
                raise HTTPException(400, "Invalid ntfy server URL")
            if topic and not re.fullmatch(r"[-_A-Za-z0-9]{1,64}", topic):
                raise HTTPException(400, "Invalid ntfy topic")
            if token and (len(token) > 512 or not all(33 <= ord(c) <= 126 for c in token)):
                raise HTTPException(400, "Invalid ntfy token")
            saved.update(server_url=server, topic=topic, token=token)
            configured = bool(server and topic)
        elif provider == "email":
            host = data.host.strip()
            password = "" if data.clear_token else (data.password or old.get("password", ""))
            username = data.username.strip()
            sender, recipient = data.sender.strip(), ", ".join(part.strip() for part in data.recipient.split(",") if part.strip())
            if data.clear_token and data.password:
                raise HTTPException(400, "Cannot remove and replace the SMTP password at the same time")
            if host and not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
                raise HTTPException(400, "Invalid SMTP host")
            if not 1 <= data.port <= 65535 or data.security not in ("starttls", "ssl", "none"):
                raise HTTPException(400, "Invalid SMTP port or security mode")
            if len(username) > 256 or len(password) > 256 or any(ord(c) < 32 for c in username + password):
                raise HTTPException(400, "Invalid SMTP credentials")
            if (sender and not valid_address(sender)) or len(sender) > 320 or len(recipient) > 1000 or any(
                not valid_address(part.strip()) for part in recipient.split(",") if part.strip()
            ):
                raise HTTPException(400, "Invalid e-mail address")
            saved.update(host=host, port=data.port, security=data.security, username=username,
                         password=password, sender=sender, recipient=recipient)
            configured = bool(host and sender and recipient)
        elif provider == "webhook":
            url = data.webhook_url.strip() or old.get("webhook_url", "")
            token = "" if data.clear_token else (data.token.strip() or old.get("token", ""))
            if data.clear_token and data.token.strip():
                raise HTTPException(400, "Cannot remove and replace the webhook token at the same time")
            if url and not valid_http_url(url):
                raise HTTPException(400, "Invalid webhook URL")
            if token and (len(token) > 512 or not all(33 <= ord(c) <= 126 for c in token)):
                raise HTTPException(400, "Invalid webhook token")
            saved.update(webhook_url=url, token=token)
            configured = bool(url)
        elif provider == "gotify":
            server = data.server_url.strip().rstrip("/")
            token = data.token.strip() or old.get("token", "")
            if server and (not valid_http_url(server) or urlsplit(server).query):
                raise HTTPException(400, "Invalid Gotify server URL")
            if token and (len(token) > 512 or not all(33 <= ord(c) <= 126 for c in token)):
                raise HTTPException(400, "Invalid Gotify token")
            saved.update(server_url=server, token=token)
            configured = bool(server and token)
        else:
            token = data.token.strip() or old.get("token", "")
            user_key = data.user_key.strip() or old.get("user_key", "")
            if (token and not re.fullmatch(r"[A-Za-z0-9]{30}", token)) or (
                user_key and not re.fullmatch(r"[A-Za-z0-9]{30}", user_key)
            ):
                raise HTTPException(400, "Invalid Pushover token or user key")
            saved.update(token=token, user_key=user_key)
            configured = bool(token and user_key)
        if data.enabled and not configured:
            raise HTTPException(400, "Provider credentials are required")
        providers[provider] = saved
        settings["providers"] = providers
        write_settings(settings)
    return {"ok": True}


@app.get("/api/monitoring")
def get_monitoring():
    settings = read_settings().get("monitoring", {})
    return {"temperature_enabled": settings.get("temperature_enabled", False),
            "hardware_enabled": settings.get("hardware_enabled", False),
            "daily_report": settings.get("daily_report", False),
            "daily_report_time": settings.get("daily_report_time", "12:00"),
            "thresholds": {name: settings.get("thresholds", {}).get(name, 45.0) for name in cfg.AGENTS}}


@app.put("/api/monitoring")
def set_monitoring(data: MonitoringInput):
    import math
    if data.daily_report_time is not None and not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", data.daily_report_time):
        raise HTTPException(400, "Invalid daily report time (HH:MM)")
    if set(data.thresholds) - set(cfg.AGENTS) or any(
        not math.isfinite(value) or value < -50 or value > 150 for value in data.thresholds.values()
    ):
        raise HTTPException(400, "Invalid host or temperature threshold (-50 to 150 °C)")
    with settings_lock:
        settings = read_settings()
        if (data.temperature_enabled or data.hardware_enabled or data.daily_report) and not enabled_providers(settings):
            raise HTTPException(400, "Enable a notification provider first")
        old = settings.get("monitoring", {})
        report_started_at = old.get("report_started_at", 0) if old.get("daily_report") else int(time.time())
        temperature_started_at = old.get("temperature_started_at", 0) if old.get("temperature_enabled") else int(time.time())
        hardware_started_at = old.get("hardware_started_at", 0) if old.get("hardware_enabled") else int(time.time())
        settings["monitoring"] = {"temperature_enabled": data.temperature_enabled,
                                  "hardware_enabled": data.hardware_enabled,
                                  "daily_report": data.daily_report,
                                  "daily_report_time": data.daily_report_time or old.get("daily_report_time", "12:00"),
                                  "thresholds": data.thresholds,
                                  "report_started_at": report_started_at,
                                  "temperature_started_at": temperature_started_at,
                                  "hardware_started_at": hardware_started_at}
        write_settings(settings)
    return {"ok": True}


async def agent_get(item, path, client=None, timeout=20, **kwargs):
    """Query an agent with its own key (falling back to AGENT_KEY) and optional pinned CA certificate."""
    key = item.get("key") or cfg.AGENT_KEY
    headers = {"X-Agent-Key": key} if key else {}
    url = item["url"].rstrip("/") + path
    if client is None or item.get("ca_cert"):
        async with httpx.AsyncClient(timeout=timeout, verify=item.get("ca_cert") or True) as own_client:
            return await own_client.get(url, headers=headers, **kwargs)
    return await client.get(url, headers=headers, **kwargs)


async def fetch(name, item):
    try:
        response = await agent_get(item, "/api/metrics", timeout=8)
        response.raise_for_status()
        data = response.json()
        data["online"] = True
        return name, data
    except (httpx.HTTPError, ValueError, TypeError) as error:
        return name, {"online": False, "error": str(error)}


@app.get("/", response_class=HTMLResponse)
def index():
    return (FRONTEND_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/api/dashboard")
async def dashboard():
    results = await asyncio.gather(*(fetch(name, item) for name, item in cfg.AGENTS.items()))
    return dict(results)


def open_history_db():
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = STATE_DIR / "metrics.sqlite3"
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(fd)
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS metrics (
            host TEXT NOT NULL, time INTEGER NOT NULL,
            cpu REAL, ram REAL, disk REAL, temperature REAL,
            PRIMARY KEY(host, time)
        );
        CREATE INDEX IF NOT EXISTS metrics_time ON metrics(time);
        CREATE TABLE IF NOT EXISTS container_metrics (
            host TEXT NOT NULL, container TEXT NOT NULL, time INTEGER NOT NULL,
            cpu REAL, ram REAL, rx REAL, tx REAL,
            PRIMARY KEY(host, container, time)
        );
        CREATE INDEX IF NOT EXISTS container_metrics_time ON container_metrics(time);
    """)
    return db


def container_rows(name, slot, data):
    stats = data.get("docker_stats")
    if not isinstance(stats, dict) or not stats.get("available") or not isinstance(stats.get("containers"), list):
        return []
    rows = []
    for item in stats["containers"]:
        container = item.get("name") if isinstance(item, dict) else None
        if not isinstance(container, str) or not container or len(container) > 128:
            continue
        values = []
        for key in ("cpu_percent", "ram_percent", "net_rx_bytes_per_s", "net_tx_bytes_per_s"):
            value = item.get(key)
            valid = (not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)
                     and value >= 0)
            values.append(value if valid else None)
        rows.append((name, container, slot, *values))
    return rows


async def collect_history(now):
    results = await asyncio.gather(*(fetch(name, item) for name, item in cfg.AGENTS.items()))
    slot = int(now // HISTORY_INTERVAL) * HISTORY_INTERVAL
    rows = []
    container_data = []
    for name, data in results:
        if not data.get("online"):
            logger.warning("History collection failed for %s: %s", name, data.get("error", "agent offline"))
            continue
        container_data += container_rows(name, slot, data)
        values = []
        for key in ("cpu_percent", "ram_percent", "storage_percent", "temperature_c"):
            value = data.get(key)
            valid = (not isinstance(value, bool) and isinstance(value, (int, float))
                     and math.isfinite(value) and (key == "temperature_c" or 0 <= value <= 100))
            if not valid:
                if value is not None:
                    logger.warning("Invalid history metric %s for %s", key, name)
                value = None
            values.append(value)
        rows.append((name, slot, *values))
    db = open_history_db()
    try:
        db.executemany("INSERT OR REPLACE INTO metrics VALUES (?, ?, ?, ?, ?, ?)", rows)
        db.executemany("INSERT OR REPLACE INTO container_metrics VALUES (?, ?, ?, ?, ?, ?, ?)", container_data)
        db.execute("DELETE FROM metrics WHERE time < ?", (slot - HISTORY_RETENTION + HISTORY_INTERVAL,))
        db.execute("DELETE FROM container_metrics WHERE time < ?", (slot - HISTORY_RETENTION + HISTORY_INTERVAL,))
        db.commit()
    finally:
        db.close()


async def history_loop():
    while True:
        try:
            await collect_history(time.time())
        except (OSError, sqlite3.Error) as error:
            logger.error("History collection failed: %s", error)
        await asyncio.sleep(HISTORY_INTERVAL - time.time() % HISTORY_INTERVAL)


@app.get("/api/history")
def history(host: str, hours: int = 24):
    if host not in cfg.AGENTS:
        raise HTTPException(404, "Unknown host")
    if hours not in HISTORY_BUCKETS:
        raise HTTPException(400, "Invalid history range")
    bucket_size = HISTORY_BUCKETS[hours]
    end = int(time.time() // HISTORY_INTERVAL) * HISTORY_INTERVAL + HISTORY_INTERVAL
    start = end - hours * 3600
    first = start // bucket_size * bucket_size
    db = open_history_db()
    try:
        rows = db.execute("""
            SELECT (time / ?) * ? AS bucket, COUNT(*),
                   AVG(cpu), AVG(ram), AVG(disk), AVG(temperature),
                   COUNT(cpu), COUNT(ram), COUNT(disk), COUNT(temperature)
            FROM metrics WHERE host = ? AND time >= ? AND time < ?
            GROUP BY bucket ORDER BY bucket
        """, (bucket_size, bucket_size, host, start, end)).fetchall()
    finally:
        db.close()
    grouped = {row[0]: row[1:] for row in rows}
    points = []
    for bucket in range(first, end, bucket_size):
        count, cpu, ram, disk, temperature, cpu_count, ram_count, disk_count, temp_count = grouped.get(
            bucket, (0, None, None, None, None, 0, 0, 0, 0))
        expected = (min(bucket + bucket_size, end) - max(bucket, start)) // HISTORY_INTERVAL
        points.append({"time": max(bucket, start), "cpu": cpu, "ram": ram, "disk": disk,
                       "temperature": temperature, "complete": count == expected,
                       "missing": {"cpu": cpu_count < expected, "ram": ram_count < expected,
                                   "disk": disk_count < expected, "temperature": temp_count < expected}})
    return {"host": host, "hours": hours, "bucket_seconds": bucket_size, "points": points}


@app.get("/api/history/containers")
def container_history(host: str, hours: int = 24):
    if host not in cfg.AGENTS:
        raise HTTPException(404, "Unknown host")
    if hours not in HISTORY_BUCKETS:
        raise HTTPException(400, "Invalid history range")
    bucket_size = HISTORY_BUCKETS[hours]
    end = int(time.time() // HISTORY_INTERVAL) * HISTORY_INTERVAL + HISTORY_INTERVAL
    start = end - hours * 3600
    db = open_history_db()
    try:
        rows = db.execute("""
            SELECT container, (time / ?) * ? AS bucket, AVG(cpu), AVG(ram), AVG(rx), AVG(tx)
            FROM container_metrics WHERE host = ? AND time >= ? AND time < ?
            GROUP BY container, bucket ORDER BY container, bucket
        """, (bucket_size, bucket_size, host, start, end)).fetchall()
    finally:
        db.close()
    containers = {}
    for container, bucket, cpu, ram, rx, tx in rows:
        containers.setdefault(container, []).append(
            {"time": max(bucket, start), "cpu": cpu, "ram": ram, "rx": rx, "tx": tx})
    return {"host": host, "hours": hours, "bucket_seconds": bucket_size, "containers": containers}


class CheckInput(BaseModel):
    name: str
    type: str
    target: str
    port: int | None = None
    notify: bool = True


class ChecksInput(BaseModel):
    checks: list[CheckInput]


def normalize_check(check):
    name, target = check.name.strip(), check.target.strip()
    if not re.fullmatch(r"[^\x00-\x1f]{1,64}", name):
        raise HTTPException(400, "Invalid check name (1-64 characters)")
    if check.type not in CHECK_TYPES:
        raise HTTPException(400, "Unknown check type")
    port = None
    if check.type == "http":
        if not valid_http_url(target):
            raise HTTPException(400, "Invalid HTTP check URL")
    else:
        if not re.fullmatch(r"[A-Za-z0-9:][A-Za-z0-9._:-]{0,252}", target):
            raise HTTPException(400, "Invalid check host")
        if check.type == "tcp":
            if check.port is None or not 1 <= check.port <= 65535:
                raise HTTPException(400, "A TCP check needs a port (1-65535)")
            port = check.port
    return {"name": name, "type": check.type, "target": target, "port": port, "notify": check.notify}


@app.get("/api/checks")
def get_checks():
    checks = read_settings().get("checks", [])
    return {"checks": [{**check, "status": check_status.get(check["name"])} for check in checks]}


@app.put("/api/checks")
def set_checks(data: ChecksInput):
    if len(data.checks) > MAX_CHECKS:
        raise HTTPException(400, f"At most {MAX_CHECKS} checks are allowed")
    checks = [normalize_check(check) for check in data.checks]
    if len({check["name"] for check in checks}) != len(checks):
        raise HTTPException(400, "Check names must be unique")
    with settings_lock:
        settings = read_settings()
        settings["checks"] = checks
        write_settings(settings)
    return {"ok": True}


async def run_check(check):
    """Run one reachability check and return (ok, latency in ms, error)."""
    start = time.monotonic()
    kind, target = check["type"], check["target"]
    try:
        if kind == "http":
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                response = await client.get(target)
            error = None if response.status_code < 400 else f"HTTP {response.status_code}"
        elif kind == "tcp":
            _, writer = await asyncio.wait_for(asyncio.open_connection(target, check["port"]), 10)
            writer.close()
            error = None
        elif kind == "dns":
            await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(target, None), 10)
            error = None
        else:
            try:
                process = await asyncio.create_subprocess_exec(
                    "ping", "-c", "1", "-W", "3", target,
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            except FileNotFoundError:
                return False, None, "ping is not installed"
            try:
                error = None if await asyncio.wait_for(process.wait(), 10) == 0 else "No ping reply"
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                error = "Timeout"
    except asyncio.TimeoutError:
        return False, None, "Timeout"
    except (OSError, httpx.HTTPError, ValueError) as exception:
        return False, None, type(exception).__name__
    return error is None, round((time.monotonic() - start) * 1000) if error is None else None, error


async def evaluate_checks(client, db, providers, checks, now, runner=run_check):
    """Run all checks, track failures and notify when a check goes down or recovers."""
    results = await asyncio.gather(*(runner(check) for check in checks))
    names = {check["name"] for check in checks}
    for name in set(check_status) - names:
        check_status.pop(name, None)
        check_failures.pop(name, None)
    if db is not None:
        for (name,) in db.execute("SELECT DISTINCT name FROM provider_checks").fetchall():
            if name not in names:
                db.execute("DELETE FROM provider_checks WHERE name=?", (name,))
        db.commit()
    for check, (ok, latency, error) in zip(checks, results):
        name = check["name"]
        check_failures[name] = 0 if ok else check_failures.get(name, 0) + 1
        down = check_failures[name] >= CHECK_FAILURES
        check_status[name] = {"ok": ok, "down": down, "latency_ms": latency, "error": error, "checked_at": now}
        if db is None or not check.get("notify", True):
            continue
        for provider, provider_settings in providers.items():
            if delivery_paused(provider, provider_settings):
                continue
            row = db.execute("SELECT down FROM provider_checks WHERE name=? AND provider=?", (name, provider)).fetchone()
            if bool(row and row[0]) == down or (row is None and not down):
                continue
            if down:
                text = f"🔴 Check ausgefallen: {name} ({check['type']} {check['target']})\n{error or ''}".rstrip()
            else:
                text = f"🟢 Check wieder erreichbar: {name}"
            try:
                await send_notification(client, provider, provider_settings, text)
                db.execute("INSERT OR REPLACE INTO provider_checks VALUES (?, ?, ?)", (name, provider, int(down)))
                db.commit()
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exception:
                logger.error("Check notification failed for %s (%s): %s", name, provider, notification_error(exception))


async def checks_loop():
    db = None
    try:
        while True:
            try:
                settings = read_settings()
                checks = settings.get("checks", [])
                if checks or check_status:
                    providers = enabled_providers(settings)
                    if db is None and (providers or checks):
                        db = open_monitoring_db()
                    async with httpx.AsyncClient(timeout=20) as client:
                        await evaluate_checks(client, db, providers, checks, int(time.time()))
            except (OSError, ValueError, sqlite3.Error) as error:
                logger.error("Reachability checks failed: %s", error)
            await asyncio.sleep(CHECK_INTERVAL - time.time() % CHECK_INTERVAL)
    finally:
        if db is not None:
            db.close()


def notification_text(name, event):
    if event["type"] == "docker" and event.get("action") in ("start", "die"):
        action = event["action"]
        code = str(event["exit_code"]) if event.get("exit_code") is not None else ""
        exit_descriptions = {"0": "Successful shutdown", "143": "Graceful termination (SIGTERM)",
                             "1": "Application error", "2": "Misuse of shell builtins",
                             "126": "Command cannot execute", "127": "File or directory not found",
                             "128": "Invalid argument", "130": "Container terminated by user",
                             "134": "Abnormal termination (SIGABRT)", "137": "Immediate termination (SIGKILL)",
                             "139": "Segmentation fault", "255": "Unknown error"}
        symbol = "🟢" if action == "start" else ("⛵" if code in ("0", "143") else "❌")
        status = "started" if action == "start" else "stopped!"
        message = f"{symbol} {event.get('name') or 'Unknown'} {status}\n🖥 Host: {name}\nImage: {event.get('image') or 'Nicht verfügbar'}"
        if action == "die":
            description = exit_descriptions.get(code)
            message += f"\n{description + ': ' if description else ''}Exit code {code or 'Nicht verfügbar'}"
        return message
    if event["type"] not in ("ssh_login", "ssh_logout") or "user" not in event:
        return f"{name}: {event['message']}"
    action = "🔓 SSH-Login" if event["type"] == "ssh_login" else "🔐 SSH-Logout"
    timestamp = datetime.fromtimestamp(event["timestamp"]).astimezone().strftime("%d.%m.%Y %H:%M:%S %z")
    return (f"{action}\n"
            f"🖥 Host: {name}\n"
            f"👤 Benutzer: {event['user'] or 'Nicht verfügbar'}\n"
            f"🌐 IP-Adresse: {event.get('remote_ip') or 'Nicht verfügbar'}\n"
            f"⏰ Zeit: {timestamp}")


def notification_error(error):
    if isinstance(error, httpx.HTTPStatusError):
        return f"HTTP {error.response.status_code}"
    return type(error).__name__


async def poll_notifications(client, settings, cursors, now, provider="telegram"):
    if delivery_paused(provider, settings):
        return
    for name, item in cfg.AGENTS.items():
        for kind in EVENT_TYPES:
            key = (name, kind)
            if kind not in settings["events"]:
                cursors.pop(key, None)
                continue
            since = cursors.setdefault(key, now)
            if since >= now:
                continue
            try:
                response = await agent_get(item, "/api/events", client,
                                           params={"since": since, "until": now, "types": [kind]})
                response.raise_for_status()
                for event in response.json()["events"]:
                    if event["type"] != kind:
                        raise ValueError("Unexpected event type")
                    await send_notification(client, provider, settings, notification_text(name, event))
                cursors[key] = now
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
                logger.error("Notification polling failed for %s (%s, %s): %s", name, kind, provider, notification_error(error))


async def send_telegram(client, settings, message):
    response = await client.post(f"https://api.telegram.org/bot{settings['token']}/sendMessage",
                                 json={"chat_id": settings["chat_id"], "text": message})
    response.raise_for_status()
    if not response.json().get("ok"):
        raise ValueError("Telegram rejected the message")


async def send_notification(client, provider, settings, message):
    fingerprint = hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()
    lock = provider_locks.setdefault(provider, asyncio.Lock())
    async with lock:
        failure = provider_failures.get(provider)
        if failure and failure["fingerprint"] != fingerprint:
            provider_failures.pop(provider, None)
            failure = None
        if failure and time.time() < failure["retry_at"]:
            raise ValueError("Notification provider temporarily paused")
        try:
            await deliver_notification(client, provider, settings, message)
            provider_failures.pop(provider, None)
        except httpx.HTTPStatusError as error:
            status = error.response.status_code
            if 400 <= status < 500:
                retry_at = float("inf")
                if status == 429 and provider != "pushover":
                    try:
                        delay = max(15, min(float(error.response.headers.get("Retry-After", "60")), 86400))
                    except ValueError:
                        delay = 60
                    retry_at = time.time() + delay
                provider_failures[provider] = {"fingerprint": fingerprint, "retry_at": retry_at}
                logger.error("Notification provider %s paused after HTTP %s; check its configuration", provider, status)
            raise
        except ValueError:
            if provider == "pushover":
                provider_failures[provider] = {"fingerprint": fingerprint, "retry_at": float("inf")}
                logger.error("Notification provider %s paused after rejecting a request", provider)
            raise


async def deliver_notification(client, provider, settings, message):
    if provider == "telegram":
        await send_telegram(client, settings, message)
        return
    if provider == "discord":
        for offset in range(0, len(message), 1000):
            response = await client.post(settings["webhook_url"], params={"wait": "true"},
                                         json={"content": message[offset:offset + 1000],
                                               "allowed_mentions": {"parse": []}})
            response.raise_for_status()
        return
    elif provider == "ntfy":
        headers = {"Content-Type": "text/plain; charset=utf-8", "Title": "LabGuard"}
        if settings.get("token"):
            headers["Authorization"] = f"Bearer {settings['token']}"
        response = await client.post(f"{settings['server_url']}/{settings['topic']}",
                                     content=message.encode("utf-8"), headers=headers)
    elif provider == "pushover":
        for offset in range(0, len(message), 1000):
            response = await client.post("https://api.pushover.net/1/messages.json",
                                         data={"token": settings["token"], "user": settings["user_key"],
                                               "message": message[offset:offset + 1000]})
            response.raise_for_status()
            if response.json().get("status") != 1:
                raise ValueError("Pushover rejected the message")
        return
    elif provider == "email":
        try:
            await asyncio.to_thread(send_email, settings, message)
        except (smtplib.SMTPException, OSError) as error:
            raise ValueError("SMTP delivery failed") from error
        return
    elif provider == "webhook":
        headers = {"Authorization": f"Bearer {settings['token']}"} if settings.get("token") else {}
        response = await client.post(settings["webhook_url"], headers=headers,
                                     json={"source": "labguard", "message": message, "text": message})
    elif provider == "gotify":
        response = await client.post(f"{settings['server_url']}/message", headers={"X-Gotify-Key": settings["token"]},
                                     json={"title": "LabGuard", "message": message, "priority": 5})
    else:
        raise ValueError("Unknown notification provider")
    response.raise_for_status()


def send_email(settings, message):
    mail = EmailMessage()
    mail["Subject"] = "LabGuard: " + message.splitlines()[0][:80] if message.strip() else "LabGuard"
    mail["From"] = settings["sender"]
    mail["To"] = settings["recipient"]
    mail.set_content(message)
    context = ssl.create_default_context()
    security = settings.get("security", "starttls")
    smtp = (smtplib.SMTP_SSL(settings["host"], settings.get("port", 465), timeout=20, context=context)
            if security == "ssl" else smtplib.SMTP(settings["host"], settings.get("port", 587), timeout=20))
    with smtp:
        if security == "starttls":
            smtp.starttls(context=context)
        if settings.get("username"):
            smtp.login(settings["username"], settings.get("password", ""))
        smtp.send_message(mail)


@app.post("/api/notifications/{provider}/test")
async def test_provider(provider: str):
    if provider not in PROVIDERS:
        raise HTTPException(404, "Unknown notification provider")
    settings = enabled_providers(read_settings()).get(provider)
    if not settings:
        raise HTTPException(400, "Enable the notification provider first")
    provider_failures.pop(provider, None)
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            await send_notification(client, provider, settings, "LabGuard: test notification")
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
        logger.error("Test notification failed for %s: %s", provider, notification_error(error))
        raise HTTPException(502, "Test notification failed; check the dashboard logs") from error
    return {"ok": True}


def open_monitoring_db():
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = STATE_DIR / "monitoring.sqlite3"
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(fd)
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS samples (host TEXT, time REAL, temperature REAL);
        CREATE TABLE IF NOT EXISTS events (host TEXT, kind TEXT, time REAL, event_id TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS cursors (host TEXT, kind TEXT, started INTEGER, until_time INTEGER,
                                             PRIMARY KEY(host, kind));
        CREATE TABLE IF NOT EXISTS temperatures (host TEXT PRIMARY KEY, above INTEGER, last_sent REAL);
        CREATE TABLE IF NOT EXISTS reports (host TEXT, day TEXT, PRIMARY KEY(host, day));
        CREATE TABLE IF NOT EXISTS provider_temperatures (
            host TEXT, provider TEXT, above INTEGER, last_sent REAL, PRIMARY KEY(host, provider));
        CREATE TABLE IF NOT EXISTS provider_reports (
            host TEXT, provider TEXT, day TEXT, PRIMARY KEY(host, provider, day));
        CREATE TABLE IF NOT EXISTS provider_hardware (
            host TEXT, provider TEXT, issues TEXT, last_sent REAL, PRIMARY KEY(host, provider));
        CREATE TABLE IF NOT EXISTS provider_checks (
            name TEXT, provider TEXT, down INTEGER, PRIMARY KEY(name, provider));
        CREATE TABLE IF NOT EXISTS migrations (name TEXT PRIMARY KEY);
    """)
    if not db.execute("SELECT 1 FROM migrations WHERE name = ?", ("notification_providers",)).fetchone():
        db.execute("INSERT OR IGNORE INTO provider_temperatures SELECT host, 'telegram', above, last_sent FROM temperatures")
        db.execute("INSERT OR IGNORE INTO provider_reports SELECT host, 'telegram', day FROM reports")
        db.execute("INSERT INTO migrations VALUES (?)", ("notification_providers",))
        db.commit()
    return db


async def collect_report_events(client, db, now, report_started_at=0):
    for name, item in cfg.AGENTS.items():
        for kind in ("ssh_login", "ssh_logout", "docker"):
            row = db.execute("SELECT started, until_time FROM cursors WHERE host=? AND kind=?", (name, kind)).fetchone()
            if row is None:
                db.execute("INSERT INTO cursors VALUES (?, ?, ?, ?)", (name, kind, now, now))
                db.commit()
                continue
            if row[1] < report_started_at:
                db.execute("UPDATE cursors SET started=?, until_time=? WHERE host=? AND kind=?",
                           (report_started_at, report_started_at, name, kind))
                db.commit()
                row = (report_started_at, report_started_at)
            since = row[1]
            if since >= now:
                continue
            try:
                response = await agent_get(item, "/api/events", client,
                                           params={"since": since, "until": now, "types": [kind], "details": "false"})
                response.raise_for_status()
                events = response.json()["events"]
                for event in events:
                    timestamp = float(event["timestamp"])
                    if event["type"] != kind or not since <= timestamp < now:
                        raise ValueError("Invalid event")
                    digest = hashlib.sha256(json.dumps([name, event], sort_keys=True, ensure_ascii=False).encode()).hexdigest()
                    db.execute("INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?)", (name, kind, timestamp, digest))
                db.execute("UPDATE cursors SET until_time=?, started=CASE WHEN ? > 120 THEN ? ELSE started END WHERE host=? AND kind=?",
                           (now, now - since, now, name, kind))
                db.commit()
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
                db.rollback()
                logger.error("Report collection failed for %s (%s): %s", name, kind, type(error).__name__)


async def collect_temperatures(client, db, monitoring, telegram, now, providers=None):
    providers = {"telegram": telegram} if providers is None else providers
    for name, item in cfg.AGENTS.items():
        try:
            sample = db.execute("SELECT time, temperature FROM samples WHERE host=? ORDER BY time DESC LIMIT 1",
                                (name,)).fetchone()
            if sample is None or now - sample[0] >= 300:
                response = await agent_get(item, "/api/metrics", client)
                response.raise_for_status()
                value = response.json().get("temperature_c")
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                    raise ValueError("Temperature unavailable")
                db.execute("INSERT INTO samples VALUES (?, ?, ?)", (name, now, value))
                db.commit()
            else:
                value = sample[1]
            if not monitoring.get("temperature_enabled"):
                continue
            threshold = monitoring.get("thresholds", {}).get(name, 45.0)
            above = value > threshold
            for provider, provider_settings in providers.items():
                if delivery_paused(provider, provider_settings):
                    continue
                state = db.execute("SELECT above, last_sent FROM provider_temperatures WHERE host=? AND provider=?",
                                   (name, provider)).fetchone()
                if state is not None and state[1] < max(monitoring.get("temperature_started_at", 0),
                                                        provider_settings.get("enabled_at", 0)):
                    state = None
                if above and (state is None or not state[0]):
                    text = f"⚠️ Warnung: Temperatur des {name} überschritten!\nAktuell: {value:.1f}°C (Schwelle: {threshold:g}°C)"
                elif above and state[0] and now - state[1] >= 300:
                    text = f"🌡️ Aktuelle Temperatur des {name}: {value:.1f}°C (Schwelle: {threshold:g}°C)"
                elif not above and state is not None and state[0]:
                    text = f"✅ Temperatur des {name} wieder normal.\nAktuell: {value:.1f}°C (Schwelle: {threshold:g}°C)"
                else:
                    continue
                try:
                    await send_notification(client, provider, provider_settings, text)
                    db.execute("INSERT OR REPLACE INTO provider_temperatures VALUES (?, ?, ?, ?)",
                               (name, provider, int(above), now))
                    db.commit()
                except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
                    logger.error("Temperature notification failed for %s (%s): %s", name, provider, notification_error(error))
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
            logger.error("Temperature monitoring failed for %s: %s", name, notification_error(error))


def hardware_issues(data):
    """Sorted problem descriptions from S.M.A.R.T. and ZFS data, or None if neither source reported."""
    issues, reported = [], False
    smart = data.get("smart")
    if isinstance(smart, dict) and smart.get("available"):
        reported = True
        for disk in smart.get("disks", []):
            if disk.get("available"):
                issues += [f"S.M.A.R.T. {disk.get('device')} ({disk.get('model') or '?'}): {problem}"
                           for problem in disk.get("problems", [])]
    zfs = data.get("zfs")
    if isinstance(zfs, dict) and zfs.get("available"):
        reported = True
        issues += [f"ZFS {pool.get('name')}: {pool.get('health')}" for pool in zfs.get("pools", [])
                   if pool.get("health") != "ONLINE"]
    return sorted(issues) if reported else None


async def collect_hardware_alerts(client, db, monitoring, now, providers):
    for name, item in cfg.AGENTS.items():
        if now - hardware_checked.get(name, 0) < 300:
            continue
        try:
            response = await agent_get(item, "/api/metrics", client)
            response.raise_for_status()
            issues = hardware_issues(response.json())
            hardware_checked[name] = now
            if issues is None:
                continue
            for provider, provider_settings in providers.items():
                if delivery_paused(provider, provider_settings):
                    continue
                state = db.execute("SELECT issues, last_sent FROM provider_hardware WHERE host=? AND provider=?",
                                   (name, provider)).fetchone()
                if state is not None and state[1] < max(monitoring.get("hardware_started_at", 0),
                                                        provider_settings.get("enabled_at", 0)):
                    state = None
                known = json.loads(state[0]) if state else []
                if issues == known:
                    continue
                if issues:
                    text = f"⚠️ Hardware-Warnung für {name}:\n" + "\n".join(f"• {issue}" for issue in issues)
                else:
                    text = f"✅ Hardware-Warnungen für {name} behoben."
                try:
                    await send_notification(client, provider, provider_settings, text)
                    db.execute("INSERT OR REPLACE INTO provider_hardware VALUES (?, ?, ?, ?)",
                               (name, provider, json.dumps(issues), now))
                    db.commit()
                except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
                    logger.error("Hardware notification failed for %s (%s): %s", name, provider, notification_error(error))
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
            logger.error("Hardware monitoring failed for %s: %s", name, notification_error(error))


async def send_daily_reports(client, db, telegram, now, providers=None, report_time="12:00"):
    providers = {"telegram": telegram} if providers is None else providers
    local = datetime.fromtimestamp(now).astimezone()
    hour, minute = map(int, report_time.split(":"))
    if (local.hour, local.minute) < (hour, minute):
        return
    day = local.date().isoformat()
    for name in cfg.AGENTS:
        since = now - 86400
        average = db.execute("SELECT AVG(temperature) FROM samples WHERE host=? AND time>=? AND time<?",
                             (name, since, now)).fetchone()[0]
        temperature = f"{average:.1f}°C" if average is not None else "Nicht verfügbar"
        sample_count = db.execute("SELECT COUNT(*) FROM samples WHERE host=? AND time>=? AND time<?",
                                  (name, since, now)).fetchone()[0]
        lines = [f"{name}:\n📊 Tägliche Zusammenfassung (letzte 24h):",
                 f"Durchschnittstemperatur: {temperature} ({sample_count} Messungen"
                 + (", unvollständig)" if sample_count < 287 else ")")]
        for kind, label in (("ssh_login", "SSH-Logins"), ("ssh_logout", "SSH-Logouts"), ("docker", "Docker-Ereignisse")):
            count = db.execute("SELECT COUNT(*) FROM events WHERE host=? AND kind=? AND time>=? AND time<?",
                               (name, kind, since, now)).fetchone()[0]
            cursor = db.execute("SELECT started, until_time FROM cursors WHERE host=? AND kind=?", (name, kind)).fetchone()
            partial = not cursor or cursor[0] > since or cursor[1] < now - 30
            lines.append(f"{label}: {count}" + (" (unvollständig)" if partial else ""))
        for provider, provider_settings in providers.items():
            if delivery_paused(provider, provider_settings):
                continue
            if db.execute("SELECT 1 FROM provider_reports WHERE host=? AND provider=? AND day=?",
                          (name, provider, day)).fetchone():
                continue
            try:
                await send_notification(client, provider, provider_settings, "\n".join(lines))
                db.execute("INSERT INTO provider_reports VALUES (?, ?, ?)", (name, provider, day))
                db.commit()
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
                logger.error("Daily report failed for %s (%s): %s", name, provider, notification_error(error))


async def monitoring_loop():
    db = None
    try:
        while True:
            try:
                settings = read_settings()
                monitoring = settings.get("monitoring", {})
                providers = enabled_providers(settings)
                enabled = providers and (monitoring.get("temperature_enabled") or monitoring.get("hardware_enabled")
                                         or monitoring.get("daily_report"))
                if enabled:
                    if db is None:
                        db = open_monitoring_db()
                    now = int(time.time())
                    async with httpx.AsyncClient(timeout=20) as client:
                        if monitoring.get("daily_report"):
                            await collect_report_events(client, db, now, monitoring.get("report_started_at", 0))
                        if not monitoring.get("temperature_enabled"):
                            db.execute("DELETE FROM provider_temperatures")
                            db.commit()
                        if monitoring.get("hardware_enabled"):
                            await collect_hardware_alerts(client, db, monitoring, now, providers)
                        else:
                            db.execute("DELETE FROM provider_hardware")
                            db.commit()
                        await collect_temperatures(client, db, monitoring, {}, now, providers)
                        if monitoring.get("daily_report"):
                            await send_daily_reports(client, db, {}, now, providers,
                                                     monitoring.get("daily_report_time", "12:00"))
                    db.execute("DELETE FROM samples WHERE time < ?", (now - 90000,))
                    db.execute("DELETE FROM events WHERE time < ?", (now - 90000,))
                    db.execute("DELETE FROM provider_reports WHERE day < ?", (datetime.fromtimestamp(now - 31 * 86400).date().isoformat(),))
                    db.execute("DELETE FROM reports WHERE day < ?", (datetime.fromtimestamp(now - 31 * 86400).date().isoformat(),))
                    db.commit()
            except (OSError, ValueError, sqlite3.Error) as error:
                logger.error("Monitoring failed: %s", error)
            await asyncio.sleep(15)
    finally:
        if db is not None:
            db.close()


async def notify_loop():
    cursors = {}
    while True:
        try:
            providers = enabled_providers(read_settings())
            for provider in list(cursors):
                if provider not in providers:
                    del cursors[provider]
            if providers:
                async with httpx.AsyncClient(timeout=20) as client:
                    now = int(time.time())
                    await asyncio.gather(*(poll_notifications(client, settings, cursors.setdefault(provider, {}), now, provider)
                                           for provider, settings in providers.items()))
        except (OSError, ValueError) as error:
            logger.error("Cannot read notification settings: %s", error)
        await asyncio.sleep(15)


if __name__ == "__main__":
    if sys.argv[1:] != ["setup"]:
        sys.exit("Usage: python dashboard_api.py setup")
    settings = read_settings()
    if "password" in settings:
        sys.exit("Password already configured; change it in the dashboard.")
    password = getpass.getpass("New dashboard password (at least 12 characters): ")
    if password != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match.")
    try:
        validate_password(password)
    except HTTPException as error:
        sys.exit(error.detail)
    settings["password"] = password_hash(password)
    write_settings(settings)
    print(f"Password configured in {STATE_FILE}.")
