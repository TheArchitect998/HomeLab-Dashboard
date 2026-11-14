#!/usr/bin/env python3
import ipaddress, json, os, platform, re, shutil, socket, subprocess, time
from datetime import datetime, timezone
from typing import Any
import psutil
from fastapi import FastAPI, Header, HTTPException, Query

app = FastAPI(title="HomeLab agent", docs_url=None, redoc_url=None)
KEY = os.environ.get("HOMELAB_AGENT_KEY", "")

def run(cmd: list[str], timeout=5) -> dict[str, Any]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = "\n".join(part.strip() for part in [proc.stdout, proc.stderr] if part and part.strip())
        return {"rc": proc.returncode, "out": out or ""}
    except Exception as e:
        return {"rc": 1, "out": f"error: {e}"}

def auth(x_agent_key: str | None):
    if KEY and x_agent_key != KEY:
        raise HTTPException(401, "invalid agent key")

def firewall() -> dict[str, Any]:
    result = run(["sudo", "-n", "ufw", "status"])
    status = result["out"]
    active = "status: active" in status.lower()
    return {"active": active, "raw": status if status else "UFW is inactive or not configured."}

def fail2ban() -> dict[str, Any]:
    result = run(["sudo", "-n", "fail2ban-client", "status"])
    status = result["out"]
    active = "jail list:" in status.lower()
    jails, details = [], {}
    if active:
        # Find the line containing "Jail list:" - handle backticks and extra spaces
        jail_line = next((x for x in status.splitlines() if "jail list:" in x.lower()), "")
        if jail_line:
            # Extract everything after the colon, split by comma, strip whitespace
            jail_str = jail_line.split(":", 1)[-1]
            jails = [j.strip() for j in jail_str.split(",") if j.strip()]

        # Get details for each jail
        for jail in jails:
            out = run(["sudo", "-n", "fail2ban-client", "status", jail])
            details[jail] = out["out"]
    return {"active": active, "jails": jails, "details": details, "raw": status if status else "Fail2Ban not active or not configured."}

def docker() -> list[dict[str, Any]]:
    raw = run(["docker", "ps", "-a", "--format", "{{json .}}"])
    result = []
    for line in raw["out"].splitlines():
        try:
            x = json.loads(line)
            name = x.get("Names", "")
            inspect = run(["docker", "inspect", "--format", "{{json .State}}", name])
            state = json.loads(inspect["out"]) if inspect["out"].startswith("{") else {}
            result.append({"name": name, "image": x.get("Image"), "status": x.get("Status"), "state": state.get("Status"), "started_at": state.get("StartedAt"), "restart_count": state.get("RestartCount", 0)})
        except Exception:
            pass
    return result

def ssh_session_details(entry: dict[str, Any], timestamp: float, kind: str) -> dict[str, Any]:
    match = re.search(r"session (?:opened|closed) for user ([^\s(]+)", entry["MESSAGE"])
    user = match.group(1) if match else None
    details = {"user": user, "remote_ip": None}
    pid, boot_id = entry.get("_PID", ""), entry.get("_BOOT_ID", "")
    if not user or not isinstance(pid, str) or not re.fullmatch(r"\d+", pid) or not isinstance(boot_id, str) or not re.fullmatch(r"[a-fA-F0-9]{32}", boot_id):
        return details

    result = run(["journalctl", "--no-pager", "-o", "json", f"_BOOT_ID={boot_id}",
                  f"_PID={pid}", "--until", f"@{int(timestamp) + 1}"], timeout=15)
    if result["rc"] != 0:
        raise HTTPException(503, f"SSH journal read failed: {result['out']}")
    records = []
    for line in result["out"].splitlines():
        try:
            record = json.loads(line)
            recorded_at = int(record["__REALTIME_TIMESTAMP"]) / 1_000_000
            text = record.get("MESSAGE", "")
        except (ValueError, KeyError, TypeError) as error:
            raise HTTPException(503, "Invalid SSH journal entry") from error
        if recorded_at <= timestamp and isinstance(text, str):
            records.append((recorded_at, text))
    records.sort(key=lambda item: item[0])

    opened_at = timestamp
    if kind == "ssh_logout":
        opened_at = None
        for recorded_at, text in records:
            if recorded_at >= timestamp:
                break
            session = re.search(r"session (opened|closed) for user ([^\s(]+)", text)
            if session:
                opened_at = recorded_at if session.group(1) == "opened" and session.group(2) == user else None
        if opened_at is None:
            return details

    for recorded_at, text in reversed(records):
        if recorded_at > opened_at or opened_at - recorded_at > 120:
            continue
        accepted = re.search(r"\bAccepted \S+ for (\S+) from (\S+) port \d+", text)
        if accepted and accepted.group(1) == user:
            try:
                details["remote_ip"] = str(ipaddress.ip_address(accepted.group(2)))
            except ValueError:
                continue
            break
    return details

@app.get("/api/events")
def events(since: int, until: int, types: list[str] = Query(default=[]), details: bool = True,
           x_agent_key: str | None = Header(default=None)):
    auth(x_agent_key)
    allowed = {"ssh_login", "ssh_logout", "fail2ban", "docker"}
    if since < 0 or until <= since or set(types) - allowed:
        raise HTTPException(400, "Invalid event query")
    events_found = []
    if set(types) & {"ssh_login", "ssh_logout", "fail2ban"}:
        result = run(["journalctl", "--no-pager", "-o", "json", "--since", f"@{since}", "--until", f"@{until}"], timeout=15)
        if result["rc"] != 0:
            raise HTTPException(503, f"Journal read failed: {result['out']}")
        for line in result["out"].splitlines():
            try:
                entry = json.loads(line)
                timestamp = int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000
                message = entry.get("MESSAGE", "")
                identifier = entry.get("SYSLOG_IDENTIFIER", "")
            except (ValueError, KeyError, TypeError) as error:
                raise HTTPException(503, "Invalid journal entry") from error
            if not since <= timestamp < until or not isinstance(message, str):
                continue
            kind = None
            if identifier.startswith("sshd") or identifier == "ssh":
                if "session opened for user" in message:
                    kind = "ssh_login"
                elif "session closed for user" in message:
                    kind = "ssh_logout"
            elif identifier.startswith("fail2ban") and re.search(r"\]\s+(?:Ban|Unban)\s+", message):
                kind = "fail2ban"
            if kind in types:
                event = {"type": kind, "message": message, "timestamp": timestamp}
                if details and kind in ("ssh_login", "ssh_logout"):
                    event.update(ssh_session_details(entry, timestamp, kind))
                events_found.append(event)
    if "docker" in types:
        result = run(["docker", "events", "--since", str(since), "--until", str(until),
                      "--filter", "type=container", "--format", "{{json .}}"], timeout=15)
        if result["rc"] != 0:
            raise HTTPException(503, f"Docker event read failed: {result['out']}")
        for line in result["out"].splitlines():
            try:
                event = json.loads(line)
                timestamp = int(event["timeNano"]) / 1_000_000_000
                action = event["Action"]
                attributes = event["Actor"]["Attributes"]
                name = attributes.get("name") or event["id"][:12]
            except (ValueError, KeyError, TypeError) as error:
                raise HTTPException(503, "Invalid Docker event") from error
            if since <= timestamp < until and action in ("start", "die"):
                events_found.append({"type": "docker", "message": f"Docker {action}: {name}",
                                     "timestamp": timestamp, "action": action, "name": name,
                                     "image": attributes.get("image"), "exit_code": attributes.get("exitCode")})
    return {"events": sorted(events_found, key=lambda event: event["timestamp"])}

@app.get("/api/health")
def health(x_agent_key: str | None = Header(default=None)):
    auth(x_agent_key); return {"ok": True}

@app.get("/api/metrics")
def metrics(x_agent_key: str | None = Header(default=None)):
    auth(x_agent_key)
    root = shutil.disk_usage("/")
    temp = None
    try:
        temps = psutil.sensors_temperatures()
        values = [v.current for group in temps.values() for v in group if v.current is not None]
        temp = round(max(values), 1) if values else None
    except Exception: pass
    return {"host": socket.gethostname(), "platform": platform.platform(), "timestamp": datetime.now(timezone.utc).isoformat(), "temperature_c": temp, "cpu_percent": psutil.cpu_percent(interval=0.2), "ram_percent": psutil.virtual_memory().percent, "storage_percent": round(root.used / root.total * 100, 1), "storage_free_bytes": root.free, "uptime_seconds": int(time.time() - psutil.boot_time()), "ufw": firewall(), "fail2ban": fail2ban(), "docker": docker()}
