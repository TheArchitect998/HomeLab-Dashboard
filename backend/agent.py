#!/usr/bin/env python3
import json
import os
import subprocess
from typing import Any

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="HomeLab agent", docs_url=None, redoc_url=None)
KEY = os.environ.get("HOMELAB_AGENT_KEY", "")


def run(cmd: list[str], timeout: int = 5) -> dict[str, Any]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = "\n".join(
            part.strip() for part in [proc.stdout, proc.stderr] if part and part.strip()
        )
        return {"rc": proc.returncode, "out": output or ""}
    except Exception as exc:  # pragma: no cover - defensive fallback
        return {"rc": 1, "out": f"error: {exc}"}


def auth(x_agent_key: str | None):
    if KEY and x_agent_key != KEY:
        raise HTTPException(401, "invalid agent key")


def firewall() -> dict[str, Any]:
    result = run(["sudo", "-n", "ufw", "status"])
    status = result["out"]
    active = "status: active" in status.lower()
    return {
        "active": active,
        "raw": status if status else "UFW is inactive or not configured.",
    }


def fail2ban() -> dict[str, Any]:
    result = run(["sudo", "-n", "fail2ban-client", "status"])
    status = result["out"]
    active = "jail list:" in status.lower()
    jails: list[str] = []
    details: dict[str, str] = {}

    if active:
        jail_line = next((line for line in status.splitlines() if "jail list:" in line.lower()), "")
        if jail_line:
            jail_text = jail_line.split(":", 1)[-1]
            jails = [j.strip() for j in jail_text.split(",") if j.strip()]
        for jail in jails:
            out = run(["sudo", "-n", "fail2ban-client", "status", jail])
            details[jail] = out["out"]

    return {
        "active": active,
        "jails": jails,
        "details": details,
        "raw": status if status else "Fail2Ban not active or not configured.",
    }


@app.get("/api/health")
def health(x_agent_key: str | None = Header(default=None)):
    auth(x_agent_key)
    return {"ok": True}


@app.get("/api/metrics")
def metrics(x_agent_key: str | None = Header(default=None)):
    auth(x_agent_key)
    import platform
    import shutil
    import socket
    import time
    from datetime import datetime, timezone

    import psutil

    root = shutil.disk_usage("/")
    temp = None
    try:
        temps = psutil.sensors_temperatures()
        values = [
            v.current for group in temps.values() for v in group if v.current is not None
        ]
        temp = round(max(values), 1) if values else None
    except Exception:
        pass

    return {
        "host": socket.gethostname(),
        "platform": platform.platform(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "temperature_c": temp,
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "ram_percent": psutil.virtual_memory().percent,
        "storage_percent": round(root.used / root.total * 100, 1),
        "storage_free_bytes": root.free,
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "ufw": firewall(),
        "fail2ban": fail2ban(),
        "docker": [],
    }
