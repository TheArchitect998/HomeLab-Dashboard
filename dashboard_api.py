#!/usr/bin/env python3
import json
import os
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="HomeLab dashboard", docs_url=None, redoc_url=None)


def load_agent_urls() -> list[str]:
    raw = os.environ.get("AGENT_URLS", "[]")
    try:
        urls = json.loads(raw)
        return [str(url) for url in urls if isinstance(url, str)]
    except Exception:
        return []


@app.get("/")
def index() -> HTMLResponse:
    index_file = Path(__file__).resolve().parent / "frontend" / "index.html"
    return HTMLResponse(index_file.read_text(encoding="utf-8"))


@app.get("/api/dashboard")
async def dashboard():
    hosts = load_agent_urls()
    result: dict[str, dict] = {}

    if not hosts:
        return result

    async with httpx.AsyncClient(timeout=5) as client:
        for index, url in enumerate(hosts):
            host_name = f"agent-{index + 1}"
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, dict):
                        result[host_name] = {**data, "online": True}
                    else:
                        result[host_name] = {"online": False, "error": "Unexpected response format"}
                else:
                    result[host_name] = {
                        "online": False,
                        "error": f"HTTP {response.status_code}: {response.text[:200]}",
                    }
            except Exception as exc:
                result[host_name] = {"online": False, "error": str(exc)}

    return result
