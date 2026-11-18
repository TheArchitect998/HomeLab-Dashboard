#!/usr/bin/env python3
import hmac, ipaddress, json, os, platform, re, shutil, socket, subprocess, threading, time
from datetime import datetime, timezone
from typing import Any
import psutil
from fastapi import FastAPI, Header, HTTPException, Query

COMMANDS = {
    "journalctl": "journalctl",
    "ufw": "ufw",
    "fail2ban-client": "fail2ban-client",
    "smartctl": "smartctl",
    "nvidia-smi": "nvidia-smi",
    "zpool": "zpool",
    "docker": "docker",
}
SUDO_COMMANDS = {"ufw", "fail2ban-client", "smartctl"}


def env(name: str, default: str = "") -> str:
    """Read LABGUARD_<name>, falling back to the legacy HOMELAB_<name> variable."""
    return os.environ.get(f"LABGUARD_{name}", os.environ.get(f"HOMELAB_{name}", default))


app = FastAPI(title="LabGuard agent", docs_url=None, redoc_url=None)
KEY = env("AGENT_KEY")
CONTAINER_MODE = env("AGENT_CONTAINER") == "1"
if len(KEY.strip()) < 16 or KEY.strip() != KEY or KEY == "change-me":
    raise RuntimeError("LABGUARD_AGENT_KEY is required: at least 16 characters, no surrounding whitespace, not the example value")
if CONTAINER_MODE:
    psutil.PROCFS_PATH = "/host/proc"


def journal_command() -> list[str]:
    if not CONTAINER_MODE:
        return ["journalctl"]
    directory = env("JOURNAL_DIR")
    if not directory or not os.path.isdir(directory):
        raise HTTPException(503, "Host journal is not configured or accessible")
    try:
        with os.scandir(directory) as entries:
            if not any(entry.name.endswith((".journal", ".journal~")) for entry in entries):
                raise HTTPException(503, "Host journal directory contains no journal files")
    except OSError as error:
        raise HTTPException(503, f"Host journal is not accessible: {error}") from error
    return ["journalctl", f"--directory={directory}"]


def security_command(tool: str) -> list[str] | None:
    if tool not in ("ufw", "fail2ban-client"):
        raise ValueError("Unsupported security command")
    if CONTAINER_MODE:
        flag = "UFW" if tool == "ufw" else "FAIL2BAN"
        if env(f"ENABLE_{flag}") != "1":
            return None
        return [COMMANDS[tool]] if tool == "ufw" else [
            COMMANDS[tool], "-s", env("FAIL2BAN_SOCKET", "/run/fail2ban/fail2ban.sock")
        ]
    return ["sudo", "-n", COMMANDS[tool]]


def allowed_command(cmd: list[str]) -> list[str]:
    if not cmd:
        raise ValueError("Empty command")
    if cmd[0] != "sudo":
        executable = COMMANDS.get(cmd[0])
        if executable is None:
            raise ValueError(f"Unsupported command: {cmd[0]}")
        return [executable, *cmd[1:]]
    if len(cmd) < 3 or cmd[1] != "-n" or cmd[2] not in SUDO_COMMANDS:
        raise ValueError("Unsupported sudo command")
    return ["sudo", "-n", COMMANDS[cmd[2]], *cmd[3:]]


def run(cmd: list[str], timeout=5) -> dict[str, Any]:
    command = allowed_command(cmd)
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, shell=False)
        out = "\n".join(part.strip() for part in [proc.stdout, proc.stderr] if part and part.strip())
        return {"rc": proc.returncode, "out": out or ""}
    except Exception as e:
        return {"rc": 1, "out": f"error: {e}"}

def auth(x_agent_key: str | None):
    if not x_agent_key or not hmac.compare_digest(x_agent_key.encode(), KEY.encode()):
        raise HTTPException(401, "invalid agent key")

def firewall() -> dict[str, Any]:
    command = security_command("ufw")
    if command is None:
        return {"active": None, "raw": "UFW access is not enabled for this agent."}
    result = run(command + ["status"])
    status = result["out"]
    if result["rc"] != 0 or not re.search(r"status:\s*(active|inactive)\b", status, re.I):
        return {"active": None, "raw": status or "UFW status could not be determined."}
    active = bool(re.search(r"status:\s*active\b", status, re.I))
    return {"active": active, "raw": status}

def fail2ban() -> dict[str, Any]:
    command = security_command("fail2ban-client")
    if command is None:
        return {"active": None, "jails": [], "details": {}, "raw": "Fail2Ban access is not enabled for this agent."}
    result = run(command + ["status"])
    status = result["out"]
    if result["rc"] != 0 or "jail list:" not in status.lower():
        return {"active": None, "jails": [], "details": {}, "raw": status or "Fail2Ban status could not be determined."}
    active = "jail list:" in status.lower()
    jails, details = [], {}
    if active:
        # Find the line containing "Jail list:" - handle backticks and extra spaces
        jail_line = next((x for x in status.splitlines() if "jail list:" in x.lower()), "")
        if jail_line:
            # Extract everything after the colon, split by comma, strip whitespace
            jail_str = jail_line.split(":", 1)[-1]
            jails = [j.strip() for j in jail_str.split(",") if valid_cli_name(j.strip())]

        # Get details for each jail
        for jail in jails:
            out = run(command + ["status", jail])
            details[jail] = out["out"]
    return {"active": active, "jails": jails, "details": details, "raw": status if status else "Fail2Ban not active or not configured."}

_io_lock = threading.Lock()
_io_state: dict[str, Any] = {"time": None, "disk": None, "net": None, "rates": None}
_cache: dict[str, tuple[float, Any]] = {}
IGNORED_INTERFACES = ("veth", "docker", "br-")


def sample_io():
    return time.monotonic(), psutil.disk_io_counters(), psutil.net_io_counters(pernic=True)


def io_rates() -> dict[str, Any]:
    """Per-second disk and network rates from counter deltas between calls."""
    with _io_lock:
        previous = (_io_state["time"], _io_state["disk"], _io_state["net"])
        if previous[0] is None:
            previous = sample_io()
            time.sleep(0.5)
        elif time.monotonic() - previous[0] < 1 and _io_state["rates"]:
            return _io_state["rates"]
        now, disk, net = sample_io()
        elapsed = max(now - previous[0], 0.001)
        rate = lambda new, old: max(0, new - old) / elapsed
        disk_io = None
        if disk is not None and previous[1] is not None:
            disk_io = {"read_bytes_per_s": rate(disk.read_bytes, previous[1].read_bytes),
                       "write_bytes_per_s": rate(disk.write_bytes, previous[1].write_bytes)}
        interfaces = []
        for name, counters in sorted(net.items()):
            old = previous[2].get(name)
            if old is None or name == "lo" or name.startswith(IGNORED_INTERFACES):
                continue
            interfaces.append({"name": name, "rx_bytes_per_s": rate(counters.bytes_recv, old.bytes_recv),
                               "tx_bytes_per_s": rate(counters.bytes_sent, old.bytes_sent)})
        rates = {"disk_io": disk_io, "network": interfaces}
        _io_state.update(time=now, disk=disk, net=net, rates=rates)
        return rates


def cached(key: str, seconds: float, producer):
    saved = _cache.get(key)
    if saved and time.monotonic() - saved[0] < seconds:
        return saved[1]
    value = producer()
    _cache[key] = (time.monotonic(), value)
    return value


def unavailable(reason: str) -> dict[str, Any]:
    return {"available": False, "reason": reason}


def smart_command() -> list[str]:
    return [COMMANDS["smartctl"]] if CONTAINER_MODE else ["sudo", "-n", COMMANDS["smartctl"]]


def smart_disk(device: dict[str, Any]) -> dict[str, Any]:
    name, kind = device.get("name", ""), device.get("type")
    if not re.fullmatch(r"/dev/[A-Za-z0-9/_-]+", name) or not (kind is None or re.fullmatch(r"[A-Za-z0-9,]+", kind)):
        raise ValueError("Invalid device")
    # smartctl exit codes are bit masks, so the JSON output is used regardless of the return code
    result = run(smart_command() + ["-j", "-H", "-A", "-n", "standby"] + (["-d", kind] if kind else []) + [name], timeout=15)
    try:
        data = json.loads(result["out"])
    except ValueError:
        return {"device": name, "available": False, "reason": result["out"][:200] or "No smartctl output"}
    messages = [m.get("string", "") for m in data.get("smartctl", {}).get("messages", []) if m.get("severity") == "error"]
    if "passed" not in data.get("smart_status", {}):
        return {"device": name, "available": False, "reason": "; ".join(messages) or "SMART status unavailable"}
    attributes = {a.get("id"): a.get("raw", {}).get("value") for a in data.get("ata_smart_attributes", {}).get("table", [])}
    nvme = data.get("nvme_smart_health_information_log", {})
    problems = []
    if not data["smart_status"]["passed"]:
        problems.append("SMART health check failed")
    for attribute, label in ((5, "reallocated sectors"), (197, "pending sectors"), (198, "uncorrectable sectors")):
        if isinstance(attributes.get(attribute), int) and attributes[attribute] > 0:
            problems.append(f"{attributes[attribute]} {label}")
    if nvme.get("critical_warning"):
        problems.append("NVMe critical warning")
    if nvme.get("media_errors"):
        problems.append(f"{nvme['media_errors']} media errors")
    return {"device": name, "available": True, "model": data.get("model_name"), "passed": data["smart_status"]["passed"],
            "temperature_c": data.get("temperature", {}).get("current"),
            "power_on_hours": data.get("power_on_time", {}).get("hours"),
            "percentage_used": nvme.get("percentage_used"), "problems": problems}


def smart() -> dict[str, Any]:
    if env("ENABLE_SMART") != "1":
        return unavailable("S.M.A.R.T. access is not enabled for this agent.")
    if CONTAINER_MODE and not shutil.which("smartctl"):
        return unavailable("smartctl is not installed in this agent image.")
    scan = run(smart_command() + ["--scan", "-j"])
    try:
        devices = json.loads(scan["out"]).get("devices", [])
    except ValueError:
        return unavailable(scan["out"][:200] or "smartctl scan failed")
    if not devices:
        return unavailable("No S.M.A.R.T. capable devices found.")
    disks = []
    for device in devices:
        try:
            disks.append(smart_disk(device))
        except ValueError:
            continue
    return {"available": True, "disks": disks}


def gpu() -> dict[str, Any]:
    if not shutil.which("nvidia-smi"):
        return unavailable("No NVIDIA GPU tools found.")
    result = run(["nvidia-smi", "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                  "--format=csv,noheader,nounits"])
    if result["rc"] != 0:
        return unavailable(result["out"][:200] or "nvidia-smi failed")
    gpus = []
    for line in result["out"].splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) != 5:
            continue
        number = lambda value: float(value) if re.fullmatch(r"\d+(\.\d+)?", value) else None
        gpus.append({"name": parts[0], "utilization_percent": number(parts[1]), "memory_used_mib": number(parts[2]),
                     "memory_total_mib": number(parts[3]), "temperature_c": number(parts[4])})
    return {"available": True, "gpus": gpus} if gpus else unavailable("No GPU reported.")


def zfs() -> dict[str, Any]:
    if not shutil.which("zpool"):
        return unavailable("ZFS tools not found.")
    result = run(["zpool", "list", "-H", "-p", "-o", "name,health,size,allocated"])
    if result["rc"] != 0:
        return unavailable(result["out"][:200] or "zpool failed")
    pools = []
    for line in result["out"].splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and parts[2].isdigit() and parts[3].isdigit() and int(parts[2]):
            pools.append({"name": parts[0], "health": parts[1], "size_bytes": int(parts[2]),
                          "used_percent": round(int(parts[3]) / int(parts[2]) * 100, 1)})
    return {"available": True, "pools": pools} if pools else unavailable("No ZFS pools found.")


def battery() -> dict[str, Any]:
    try:
        info = psutil.sensors_battery()
    except Exception:
        info = None
    if info is None:
        return unavailable("No battery found.")
    return {"available": True, "percent": round(info.percent, 1), "charging": info.power_plugged}


def swap_percent() -> float | None:
    try:
        swap = psutil.swap_memory()
    except Exception:
        return None
    return swap.percent if swap.total else None


def safely(producer) -> dict[str, Any]:
    try:
        return producer()
    except Exception as error:
        return unavailable(f"error: {error}")


def valid_cli_name(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value))


def docker() -> tuple[list[dict[str, Any]], str | None]:
    raw = run(["docker", "ps", "-a", "--format", "{{json .}}"])
    if raw["rc"] != 0:
        return [], raw["out"] or "Docker status could not be determined."
    result = []
    errors = []
    for line in raw["out"].splitlines():
        try:
            x = json.loads(line)
            name = x.get("Names", "")
            if not isinstance(name, str) or not valid_cli_name(name):
                errors.append(f"Invalid Docker container name: {name!r}")
                continue
            inspect = run(["docker", "inspect", "--format", "{{json .State}}", "--", name])
            if inspect["rc"] != 0:
                errors.append(f"{name}: {inspect['out'] or 'Docker inspect failed'}")
            state = json.loads(inspect["out"]) if inspect["out"].startswith("{") else {}
            result.append({"name": name, "image": x.get("Image"), "status": x.get("Status"), "state": state.get("Status"), "started_at": state.get("StartedAt"), "restart_count": state.get("RestartCount", 0)})
        except (ValueError, TypeError, AttributeError) as error:
            errors.append(f"Invalid Docker response: {error}")
    return result, "; ".join(errors) or None

UNIT_FACTORS = {"b": 1, "kb": 1000, "mb": 1000**2, "gb": 1000**3, "tb": 1000**4,
                "kib": 1024, "mib": 1024**2, "gib": 1024**3, "tib": 1024**4}
_container_net: dict[str, tuple[float, float, float]] = {}


def parse_size(text: str) -> float | None:
    match = re.fullmatch(r"\s*([0-9.]+)\s*([A-Za-z]+)\s*", text or "")
    factor = UNIT_FACTORS.get(match.group(2).lower()) if match else None
    return float(match.group(1)) * factor if factor else None


def parse_percent(text: str) -> float | None:
    try:
        return float((text or "").strip().rstrip("%"))
    except ValueError:
        return None


def container_stats() -> dict[str, Any]:
    """Per-container CPU, memory and network values; network rates come from totals between samples."""
    raw = run(["docker", "stats", "--no-stream", "--format", "{{json .}}"], timeout=6)
    if raw["rc"] != 0:
        return unavailable(raw["out"] or "Docker statistics could not be determined.")
    now, containers, seen = time.monotonic(), [], set()
    for line in raw["out"].splitlines():
        try:
            row = json.loads(line)
            name = row["Name"]
        except (ValueError, KeyError, TypeError):
            continue
        used, _, limit = str(row.get("MemUsage", "")).partition("/")
        received, _, sent = str(row.get("NetIO", "")).partition("/")
        rx, tx = parse_size(received), parse_size(sent)
        entry = {"name": name, "cpu_percent": parse_percent(row.get("CPUPerc")),
                 "ram_percent": parse_percent(row.get("MemPerc")), "ram_bytes": parse_size(used),
                 "ram_limit_bytes": parse_size(limit), "net_rx_bytes_per_s": None, "net_tx_bytes_per_s": None}
        previous = _container_net.get(name)
        if previous and rx is not None and tx is not None and now - previous[0] >= 5 and rx >= previous[1] and tx >= previous[2]:
            elapsed = now - previous[0]
            entry["net_rx_bytes_per_s"] = (rx - previous[1]) / elapsed
            entry["net_tx_bytes_per_s"] = (tx - previous[2]) / elapsed
        if rx is not None and tx is not None and (previous is None or now - previous[0] >= 5 or rx < previous[1] or tx < previous[2]):
            _container_net[name] = (now, rx, tx)
        seen.add(name)
        containers.append(entry)
    for name in set(_container_net) - seen:
        del _container_net[name]
    return {"available": True, "containers": containers}


def ssh_session_details(entry: dict[str, Any], timestamp: float, kind: str) -> dict[str, Any]:
    match = re.search(r"session (?:opened|closed) for user ([^\s(]+)", entry["MESSAGE"])
    user = match.group(1) if match else None
    details = {"user": user, "remote_ip": None}
    pid, boot_id = entry.get("_PID", ""), entry.get("_BOOT_ID", "")
    if not user or not isinstance(pid, str) or not re.fullmatch(r"\d+", pid) or not isinstance(boot_id, str) or not re.fullmatch(r"[a-fA-F0-9]{32}", boot_id):
        return details

    result = run(journal_command() + ["--no-pager", "-o", "json", f"_BOOT_ID={boot_id}",
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
        result = run(journal_command() + ["--no-pager", "-o", "json", "--since", f"@{since}", "--until", f"@{until}"], timeout=15)
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
    root = shutil.disk_usage("/host/root" if CONTAINER_MODE else "/")
    temp = None
    try:
        temps = psutil.sensors_temperatures()
        values = [v.current for group in temps.values() for v in group if v.current is not None]
        temp = round(max(values), 1) if values else None
    except Exception: pass
    containers, docker_error = docker()
    rates = safely(io_rates)
    return {"host": socket.gethostname(), "platform": platform.platform(), "timestamp": datetime.now(timezone.utc).isoformat(), "temperature_c": temp, "cpu_percent": psutil.cpu_percent(interval=0.2), "ram_percent": psutil.virtual_memory().percent, "storage_percent": round(root.used / root.total * 100, 1), "storage_free_bytes": root.free, "uptime_seconds": int(time.time() - psutil.boot_time()), "ufw": firewall(), "fail2ban": fail2ban(), "docker": containers, "docker_error": docker_error,
            "docker_stats": unavailable("Docker is not available") if docker_error and not containers else safely(lambda: cached("docker_stats", 30, container_stats)),
            "swap_percent": swap_percent(), "disk_io": rates.get("disk_io"), "network": rates.get("network"),
            "smart": safely(lambda: cached("smart", 600, smart)), "gpu": safely(lambda: cached("gpu", 30, gpu)),
            "zfs": safely(lambda: cached("zfs", 30, zfs)), "battery": safely(battery)}