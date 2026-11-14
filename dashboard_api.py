#!/usr/bin/env python3
import asyncio
import getpass
import hashlib
import hmac
import importlib.util
import json
import logging
import os
import pathlib
import secrets
import sqlite3
import sys
import tempfile
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime
from types import SimpleNamespace
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

config_file = os.environ.get("HOMELAB_DASHBOARD_CONFIG")
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
    cfg = SimpleNamespace(AGENTS=agents, AGENT_KEY=os.environ.get("AGENT_KEY", ""),
                          STATE_DIR=os.environ.get("HOMELAB_STATE_DIR", "/opt/homelab-dashboard/state"))

STATE_DIR = pathlib.Path(getattr(cfg, "STATE_DIR", "/opt/homelab-dashboard/state"))
STATE_FILE = STATE_DIR / "settings.json"
ITERATIONS = 600_000
SESSION_SECONDS = 12 * 60 * 60
EVENT_TYPES = {"ssh_login", "ssh_logout", "fail2ban", "docker"}
logger = logging.getLogger("homelab-dashboard")
sessions = {}
login_attempts = {}
settings_lock = threading.Lock()


@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(notify_loop())
    monitoring_task = asyncio.create_task(monitoring_loop())
    try:
        yield
    finally:
        task.cancel()
        monitoring_task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        try:
            await monitoring_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="HomeLab Dashboard", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
FRONTEND_DIR = pathlib.Path(__file__).parent / "frontend"
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
    token = request.cookies.get("homelab_session", "")
    expiry = sessions.get(token, 0)
    if expiry <= time.time():
        sessions.pop(token, None)
        raise HTTPException(401, "Authentication required")


@app.middleware("http")
async def protect_api(request, call_next):
    if request.url.path.startswith("/api/"):
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("origin")
            if request.headers.get("x-requested-with") != "HomeLab" or (
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

class MonitoringInput(BaseModel):
    temperature_enabled: bool = False
    daily_report: bool = False
    thresholds: dict[str, float] = {}


@app.get("/api/auth/status")
def auth_status(request: Request):
    configured = "password" in read_settings()
    return {"configured": configured, "authenticated": sessions.get(request.cookies.get("homelab_session", ""), 0) > time.time()}


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
    response.set_cookie("homelab_session", token, max_age=SESSION_SECONDS, httponly=True,
                        secure=request.url.scheme == "https", samesite="strict", path="/")
    return response


@app.post("/api/auth/logout")
def logout(request: Request):
    sessions.pop(request.cookies.get("homelab_session", ""), None)
    response = JSONResponse({"ok": True})
    response.delete_cookie("homelab_session", path="/")
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
            "token_configured": bool(telegram.get("token")), "events": telegram.get("events", [])}


@app.put("/api/telegram")
def set_telegram(data: TelegramInput):
    with settings_lock:
        settings = read_settings()
        old = settings.get("telegram", {})
        token = data.token.strip() or old.get("token", "")
        chat_id = data.chat_id.strip()
        if set(data.events) - EVENT_TYPES:
            raise HTTPException(400, "Unknown event type")
        if data.enabled and (not token or not chat_id or not data.events):
            raise HTTPException(400, "Token, chat ID and at least one event are required")
        if token and (len(token) > 200 or not all(c.isascii() and (c.isalnum() or c in "_:-") for c in token)):
            raise HTTPException(400, "Invalid bot token")
        if chat_id and (len(chat_id) > 100 or not all(c.isascii() and (c.isalnum() or c in "_@-") for c in chat_id)):
            raise HTTPException(400, "Invalid chat ID")
        settings["telegram"] = {"enabled": data.enabled, "chat_id": chat_id, "token": token,
                                "events": sorted(set(data.events))}
        write_settings(settings)
    return {"ok": True}

@app.get("/api/monitoring")
def get_monitoring():
    settings = read_settings().get("monitoring", {})
    return {"temperature_enabled": settings.get("temperature_enabled", False),
            "daily_report": settings.get("daily_report", False),
            "thresholds": {name: settings.get("thresholds", {}).get(name, 45.0) for name in cfg.AGENTS}}


@app.put("/api/monitoring")
def set_monitoring(data: MonitoringInput):
    import math
    if set(data.thresholds) - set(cfg.AGENTS) or any(
        not math.isfinite(value) or value < -50 or value > 150 for value in data.thresholds.values()
    ):
        raise HTTPException(400, "Invalid host or temperature threshold (-50 to 150 °C)")
    with settings_lock:
        settings = read_settings()
        if (data.temperature_enabled or data.daily_report) and not settings.get("telegram", {}).get("enabled"):
            raise HTTPException(400, "Enable Telegram first")
        old = settings.get("monitoring", {})
        report_started_at = old.get("report_started_at", 0) if old.get("daily_report") else int(time.time())
        temperature_started_at = old.get("temperature_started_at", 0) if old.get("temperature_enabled") else int(time.time())
        settings["monitoring"] = {"temperature_enabled": data.temperature_enabled,
                                  "daily_report": data.daily_report, "thresholds": data.thresholds,
                                  "report_started_at": report_started_at,
                                  "temperature_started_at": temperature_started_at}
        write_settings(settings)
    return {"ok": True}


async def fetch(name, item):
    try:
        headers = {"X-Agent-Key": cfg.AGENT_KEY} if cfg.AGENT_KEY else {}
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.get(item["url"].rstrip("/") + "/api/metrics", headers=headers)
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


async def poll_notifications(client, settings, cursors, now):
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
                headers = {"X-Agent-Key": cfg.AGENT_KEY} if cfg.AGENT_KEY else {}
                response = await client.get(item["url"].rstrip("/") + "/api/events",
                                            params={"since": since, "until": now, "types": [kind]},
                                            headers=headers)
                response.raise_for_status()
                for event in response.json()["events"]:
                    if event["type"] != kind:
                        raise ValueError("Unexpected event type")
                    result = await client.post(
                        f"https://api.telegram.org/bot{settings['token']}/sendMessage",
                        json={"chat_id": settings["chat_id"], "text": notification_text(name, event)})
                    result.raise_for_status()
                    if not result.json().get("ok"):
                        raise ValueError("Telegram rejected the message")
                cursors[key] = now
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
                logger.error("Notification polling failed for %s (%s): %s", name, kind, type(error).__name__)


async def send_telegram(client, settings, message):
    response = await client.post(f"https://api.telegram.org/bot{settings['token']}/sendMessage",
                                 json={"chat_id": settings["chat_id"], "text": message})
    response.raise_for_status()
    if not response.json().get("ok"):
        raise ValueError("Telegram rejected the message")


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
    """)
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
                headers = {"X-Agent-Key": cfg.AGENT_KEY} if cfg.AGENT_KEY else {}
                response = await client.get(item["url"].rstrip("/") + "/api/events",
                                            params={"since": since, "until": now, "types": [kind], "details": "false"},
                                            headers=headers)
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


async def collect_temperatures(client, db, monitoring, telegram, now):
    for name, item in cfg.AGENTS.items():
        last_sample = db.execute("SELECT MAX(time) FROM samples WHERE host=?", (name,)).fetchone()[0]
        if last_sample is not None and now - last_sample < 300:
            continue
        try:
            headers = {"X-Agent-Key": cfg.AGENT_KEY} if cfg.AGENT_KEY else {}
            response = await client.get(item["url"].rstrip("/") + "/api/metrics", headers=headers)
            response.raise_for_status()
            value = response.json().get("temperature_c")
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("Temperature unavailable")
            import math
            if not math.isfinite(value):
                raise ValueError("Temperature unavailable")
            db.execute("INSERT INTO samples VALUES (?, ?, ?)", (name, now, value))
            db.commit()
            if not monitoring.get("temperature_enabled"):
                continue
            threshold = monitoring.get("thresholds", {}).get(name, 45.0)
            above = value > threshold
            state = db.execute("SELECT above, last_sent FROM temperatures WHERE host=?", (name,)).fetchone()
            if state is not None and state[1] < monitoring.get("temperature_started_at", 0):
                state = None
            if above and (state is None or not state[0]):
                text = f"⚠️ Warnung: Temperatur des {name} überschritten!\nAktuell: {value:.1f}°C (Schwelle: {threshold:g}°C)"
            elif above and state[0] and now - state[1] >= 300:
                text = f"🌡️ Aktuelle Temperatur des {name}: {value:.1f}°C (Schwelle: {threshold:g}°C)"
            elif not above and state is not None and state[0]:
                text = f"✅ Temperatur des {name} wieder normal.\nAktuell: {value:.1f}°C (Schwelle: {threshold:g}°C)"
            else:
                continue
            await send_telegram(client, telegram, text)
            db.execute("INSERT OR REPLACE INTO temperatures VALUES (?, ?, ?)", (name, int(above), now))
            db.commit()
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
            logger.error("Temperature monitoring failed for %s: %s", name, type(error).__name__)


async def send_daily_reports(client, db, telegram, now):
    local = datetime.fromtimestamp(now).astimezone()
    if local.hour < 12:
        return
    day = local.date().isoformat()
    for name in cfg.AGENTS:
        if db.execute("SELECT 1 FROM reports WHERE host=? AND day=?", (name, day)).fetchone():
            continue
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
        try:
            await send_telegram(client, telegram, "\n".join(lines))
            db.execute("INSERT INTO reports VALUES (?, ?)", (name, day))
            db.commit()
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
            logger.error("Daily report failed for %s: %s", name, type(error).__name__)


async def monitoring_loop():
    db = None
    try:
        while True:
            try:
                settings = read_settings()
                monitoring = settings.get("monitoring", {})
                telegram = settings.get("telegram", {})
                enabled = telegram.get("enabled") and (monitoring.get("temperature_enabled") or monitoring.get("daily_report"))
                if enabled:
                    if db is None:
                        db = open_monitoring_db()
                    now = int(time.time())
                    async with httpx.AsyncClient(timeout=20) as client:
                        if monitoring.get("daily_report"):
                            await collect_report_events(client, db, now, monitoring.get("report_started_at", 0))
                        if not monitoring.get("temperature_enabled"):
                            db.execute("DELETE FROM temperatures")
                            db.commit()
                        await collect_temperatures(client, db, monitoring, telegram, now)
                        if monitoring.get("daily_report"):
                            await send_daily_reports(client, db, telegram, now)
                    db.execute("DELETE FROM samples WHERE time < ?", (now - 90000,))
                    db.execute("DELETE FROM events WHERE time < ?", (now - 90000,))
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
            settings = read_settings().get("telegram", {})
            if settings.get("enabled"):
                async with httpx.AsyncClient(timeout=20) as client:
                    await poll_notifications(client, settings, cursors, int(time.time()))
            else:
                cursors.clear()
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
