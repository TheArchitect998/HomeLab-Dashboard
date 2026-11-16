import importlib.util
import json
import os
import pathlib
import runpy
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from datetime import datetime

import httpx
from fastapi.testclient import TestClient


ROOT = pathlib.Path(__file__).parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        config = pathlib.Path(cls.temp.name) / "config.py"
        config.write_text(f"AGENTS = {{}}\nAGENT_KEY = ''\nSTATE_DIR = {str(pathlib.Path(cls.temp.name) / 'state')!r}\n")
        with patch.dict(os.environ, {"HOMELAB_DASHBOARD_CONFIG": str(config)}):
            cls.dashboard = load_module("dashboard_test", ROOT.parent / "dashboard_api.py")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        test_state = tempfile.TemporaryDirectory()
        self.addCleanup(test_state.cleanup)
        self.dashboard.STATE_DIR = pathlib.Path(test_state.name) / "state"
        self.dashboard.STATE_FILE = self.dashboard.STATE_DIR / "settings.json"
        self.dashboard.sessions.clear()
        self.dashboard.login_attempts.clear()
        self.dashboard.provider_failures.clear()
        self.dashboard.provider_locks.clear()
        self.dashboard.write_settings({"password": self.dashboard.password_hash("correct-password")})
        self.client = TestClient(self.dashboard.app)
        self.headers = {"X-Requested-With": "HomeLab"}

    def login(self, password="correct-password"):
        return self.client.post("/api/auth/login", json={"password": password}, headers=self.headers)

    def test_existing_agent_urls_environment_configuration(self):
            variables = {"AGENT_URLS": json.dumps(["http://one:9100/api/metrics", "http://two:9100/"]),
                         "AGENT_KEY": "test-key", "HOMELAB_STATE_DIR": str(self.dashboard.STATE_DIR)}
            with patch.dict(os.environ, variables, clear=True):
                module = runpy.run_path(str(ROOT.parent / "dashboard_api.py"), run_name="public_config_test")
            self.assertEqual(module["cfg"].AGENTS, {"agent-1": {"url": "http://one:9100"},
                                                   "agent-2": {"url": "http://two:9100"}})
            self.assertEqual(module["cfg"].AGENT_KEY, "test-key")
            with patch.dict(os.environ, {"AGENT_URLS": "invalid"}, clear=True):
                with self.assertRaisesRegex(RuntimeError, "AGENT_URLS"):
                    runpy.run_path(str(ROOT.parent / "dashboard_api.py"), run_name="public_config_test")

    def test_dashboard_serves_frontend_from_repository(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, (ROOT.parent / "frontend" / "index.html").read_text(encoding="utf-8"))

    def test_initial_setup_is_local_and_cannot_overwrite_password(self):
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory) / "config.py"
            state = pathlib.Path(directory) / "state"
            config.write_text(f"AGENTS = {{}}\nAGENT_KEY = ''\nSTATE_DIR = {str(state)!r}\n")
            with patch.dict(os.environ, {"HOMELAB_DASHBOARD_CONFIG": str(config)}), \
                 patch.object(sys, "argv", ["dashboard_api.py", "setup"]), \
                 patch("getpass.getpass", side_effect=["first-password-123", "first-password-123"]):
                runpy.run_path(str(ROOT.parent / "dashboard_api.py"), run_name="__main__")
                with self.assertRaisesRegex(SystemExit, "already configured"):
                    runpy.run_path(str(ROOT.parent / "dashboard_api.py"), run_name="__main__")
            stored = json.loads((state / "settings.json").read_text())
            self.assertTrue(self.dashboard.check_password("first-password-123", stored["password"]))

    def test_authentication_and_password_change(self):
        self.assertEqual(self.client.get("/api/dashboard").status_code, 401)
        self.assertEqual(self.login("wrong-password").status_code, 401)
        self.assertEqual(self.login().status_code, 200)
        self.assertEqual(self.client.get("/api/dashboard").json(), {})
        self.assertEqual(self.client.post("/api/auth/password", headers=self.headers, json={
            "current_password": "correct-password", "new_password": "new-password-123"
        }).status_code, 200)
        self.assertEqual(self.client.get("/api/dashboard").status_code, 401)
        self.assertEqual(self.login("correct-password").status_code, 401)
        self.assertEqual(self.login("new-password-123").status_code, 200)
        self.assertEqual(self.client.post("/api/auth/logout", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get("/api/dashboard").status_code, 401)

    def test_setup_and_request_origin(self):
        self.dashboard.write_settings({})
        self.assertEqual(self.login().status_code, 503)
        self.dashboard.write_settings({"password": self.dashboard.password_hash("correct-password")})
        self.assertEqual(self.client.post("/api/auth/login", json={"password": "correct-password"}).status_code, 403)
        self.assertEqual(self.client.post("/api/auth/login", json={"password": "correct-password"},
                                         headers={**self.headers, "Origin": "https://evil.example"}).status_code, 403)
        self.assertEqual(self.login().status_code, 200)

    def test_login_throttling_and_secure_cookie(self):
        for _ in range(5):
            self.assertEqual(self.login("wrong-password").status_code, 401)
        self.assertEqual(self.login().status_code, 429)
        self.dashboard.login_attempts.clear()
        client = TestClient(self.dashboard.app, base_url="https://testserver")
        response = client.post("/api/auth/login", json={"password": "correct-password"}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("secure", response.headers["set-cookie"].lower())
        self.assertIn("httponly", response.headers["set-cookie"].lower())
        self.assertIn("samesite=strict", response.headers["set-cookie"].lower())

    def test_telegram_token_not_returned_and_preserved(self):
        self.login()
        payload = {"enabled": True, "chat_id": "-123", "token": "123:abc-def", "events": ["ssh_login", "docker"]}
        self.assertEqual(self.client.put("/api/telegram", json=payload, headers=self.headers).status_code, 200)
        saved = self.client.get("/api/telegram").json()
        self.assertNotIn("token", saved)
        self.assertTrue(saved["token_configured"])
        payload["token"] = ""
        self.assertEqual(self.client.put("/api/telegram", json=payload, headers=self.headers).status_code, 200)
        self.assertEqual(self.dashboard.read_settings()["telegram"]["token"], "123:abc-def")
        payload["events"] = ["unknown"]
        self.assertEqual(self.client.put("/api/telegram", json=payload, headers=self.headers).status_code, 400)

    def test_notification_delivery_and_retry(self):
        requests = []
        def handler(request):
            requests.append(request)
            if request.url.host == "agent.test":
                return httpx.Response(200, json={"events": [{"type": "docker", "message": "Docker start: web"}]})
            return httpx.Response(503 if len(requests) == 2 else 200, json={"ok": True})

        async def run():
            settings = {"events": ["docker"], "token": "123:abc", "chat_id": "-123"}
            cursors = {}
            with patch.object(self.dashboard.cfg, "AGENTS", {"host": {"url": "http://agent.test"}}):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    await self.dashboard.poll_notifications(client, settings, cursors, 100)
                    self.assertEqual(requests, [])
                    await self.dashboard.poll_notifications(client, settings, cursors, 115)
                    self.assertEqual(cursors[("host", "docker")], 100)
                    await self.dashboard.poll_notifications(client, settings, cursors, 130)
                    self.assertEqual(cursors[("host", "docker")], 130)
            self.assertEqual(json.loads(requests[-1].content), {"chat_id": "-123", "text": "host: Docker start: web"})
        import asyncio
        asyncio.run(run())

    def test_provider_settings_preserve_secrets_and_support_monitoring(self):
        self.login()
        discord = {"enabled": True, "events": ["docker"],
                   "webhook_url": "https://discord.com/api/webhooks/123/test-secret"}
        self.assertEqual(self.client.put("/api/notifications/discord", json=discord, headers=self.headers).status_code, 200)
        saved = self.client.get("/api/notifications/discord").json()
        self.assertTrue(saved["webhook_configured"])
        self.assertNotIn("webhook_url", saved)
        discord["webhook_url"] = ""
        self.assertEqual(self.client.put("/api/notifications/discord", json=discord, headers=self.headers).status_code, 200)
        self.assertEqual(self.dashboard.read_settings()["providers"]["discord"]["webhook_url"],
                         "https://discord.com/api/webhooks/123/test-secret")
        discord["webhook_url"] = "https://discord.com.evil.test/api/webhooks/123/test"
        self.assertEqual(self.client.put("/api/notifications/discord", json=discord, headers=self.headers).status_code, 400)
        ntfy = {"enabled": True, "events": [], "server_url": "http://ntfy.test:8080",
                "topic": "private_topic", "token": "tk_test"}
        self.assertEqual(self.client.put("/api/notifications/ntfy", json=ntfy, headers=self.headers).status_code, 200)
        saved = self.client.get("/api/notifications/ntfy").json()
        self.assertTrue(saved["topic_configured"] and saved["token_configured"])
        self.assertNotIn("topic", saved)
        self.assertNotIn("token", saved)
        ntfy.update(topic="", token="", clear_token=True)
        self.assertEqual(self.client.put("/api/notifications/ntfy", json=ntfy, headers=self.headers).status_code, 200)
        self.assertEqual(self.dashboard.read_settings()["providers"]["ntfy"]["token"], "")
        ntfy["server_url"] = "https://user:password@ntfy.test"
        self.assertEqual(self.client.put("/api/notifications/ntfy", json=ntfy, headers=self.headers).status_code, 400)
        pushover = {"enabled": True, "events": ["ssh_login"], "token": "A" * 30, "user_key": "B" * 30}
        self.assertEqual(self.client.put("/api/notifications/pushover", json=pushover, headers=self.headers).status_code, 200)
        self.assertNotIn("user_key", self.client.get("/api/notifications/pushover").json())
        pushover.update(token="", user_key="")
        self.assertEqual(self.client.put("/api/notifications/pushover", json=pushover, headers=self.headers).status_code, 200)
        self.assertEqual(self.dashboard.read_settings()["providers"]["pushover"]["user_key"], "B" * 30)
        with patch.object(self.dashboard.cfg, "AGENTS", {"host": {"url": "http://agent.test"}}):
            payload = {"temperature_enabled": True, "daily_report": True, "thresholds": {"host": 45}}
            self.assertEqual(self.client.put("/api/monitoring", json=payload, headers=self.headers).status_code, 200)

    def test_provider_delivery_formats_and_independent_retry(self):
        import asyncio
        requests = []
        discord_failures = [1]
        def handler(request):
            requests.append(request)
            if request.url.host == "agent.test":
                return httpx.Response(200, json={"events": [{"type": "docker", "message": "started"}]})
            if request.url.host == "discord.com":
                if discord_failures[0]:
                    discord_failures[0] -= 1
                    return httpx.Response(503)
                return httpx.Response(204)
            if request.url.host == "api.pushover.net":
                return httpx.Response(200, json={"status": 1})
            return httpx.Response(200, json={"ok": True})

        async def run():
            telegram = {"events": ["docker"], "token": "123:abc", "chat_id": "1"}
            discord = {"events": ["docker"], "webhook_url": "https://discord.com/api/webhooks/123/test"}
            ntfy = {"server_url": "http://ntfy.test", "topic": "private", "token": "tk_test"}
            pushover = {"token": "A" * 30, "user_key": "B" * 30}
            cursors = {"telegram": {}, "discord": {}}
            with patch.object(self.dashboard.cfg, "AGENTS", {"host": {"url": "http://agent.test"}}):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    for provider, settings in (("telegram", telegram), ("discord", discord)):
                        await self.dashboard.poll_notifications(client, settings, cursors[provider], 100, provider)
                    for provider, settings in (("telegram", telegram), ("discord", discord)):
                        await self.dashboard.poll_notifications(client, settings, cursors[provider], 115, provider)
                    self.assertEqual(cursors["telegram"][("host", "docker")], 115)
                    self.assertEqual(cursors["discord"][("host", "docker")], 100)
                    await self.dashboard.poll_notifications(client, discord, cursors["discord"], 130, "discord")
                    await self.dashboard.send_notification(client, "ntfy", ntfy, "Warnung 🌡️")
                    await self.dashboard.send_notification(client, "pushover", pushover, "Warnung")
            telegram_requests = [r for r in requests if r.url.host == "api.telegram.org"]
            self.assertEqual(len(telegram_requests), 1)
            discord_request = [r for r in requests if r.url.host == "discord.com"][-1]
            self.assertEqual(json.loads(discord_request.content)["allowed_mentions"], {"parse": []})
            self.assertEqual(discord_request.url.params["wait"], "true")
            ntfy_request = next(r for r in requests if r.url.host == "ntfy.test")
            self.assertEqual(ntfy_request.content.decode(), "Warnung 🌡️")
            self.assertEqual(ntfy_request.headers["Authorization"], "Bearer tk_test")
            pushover_request = next(r for r in requests if r.url.host == "api.pushover.net")
            self.assertIn(b"message=Warnung", pushover_request.content)
        asyncio.run(run())

    def test_permanent_provider_failure_is_paused_until_settings_change(self):
        import asyncio
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(400)
        async def run():
            settings = {"token": "A" * 30, "user_key": "B" * 30, "events": ["docker"]}
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                with self.assertRaises(httpx.HTTPStatusError):
                    await self.dashboard.send_notification(client, "pushover", settings, "first")
                with self.assertRaises(ValueError):
                    await self.dashboard.send_notification(client, "pushover", settings, "second")
                with patch.object(self.dashboard.cfg, "AGENTS", {"host": {"url": "http://agent.test"}}):
                    await self.dashboard.poll_notifications(client, settings, {("host", "docker"): 100}, 115, "pushover")
                self.assertEqual(len(requests), 1)
                self.assertTrue(self.dashboard.delivery_paused("pushover", settings))
                self.assertFalse(self.dashboard.delivery_paused("pushover", {**settings, "user_key": "C" * 30}))
        asyncio.run(run())

    def test_test_notification_endpoint_uses_saved_secrets_and_surfaces_failure(self):
        requests = []
        status = [400]
        def handler(request):
            requests.append(request)
            return httpx.Response(status[0])
        factory = httpx.AsyncClient
        self.assertEqual(self.client.post("/api/notifications/ntfy/test", headers=self.headers).status_code, 401)
        self.login()
        settings = {"enabled": True, "events": [], "server_url": "http://ntfy.test",
                    "topic": "secret_topic", "token": "secret_token"}
        self.assertEqual(self.client.put("/api/notifications/ntfy", json=settings, headers=self.headers).status_code, 200)
        with patch.object(self.dashboard.httpx, "AsyncClient",
                          side_effect=lambda **kwargs: factory(transport=httpx.MockTransport(handler), **kwargs)):
            response = self.client.post("/api/notifications/ntfy/test", headers=self.headers)
            self.assertEqual(response.status_code, 502)
            self.assertNotIn("secret", response.text)
            self.assertTrue(self.client.get("/api/notifications/ntfy").json()["delivery_paused"])
            status[0] = 200
            self.assertEqual(self.client.post("/api/notifications/ntfy/test", headers=self.headers).status_code, 200)
            self.assertFalse(self.client.get("/api/notifications/ntfy").json()["delivery_paused"])
        self.assertEqual(len(requests), 2)

    def test_ntfy_test_message_over_local_http(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append((self.path, self.headers.get("Authorization"),
                                 self.rfile.read(int(self.headers["Content-Length"])).decode()))
                self.send_response(200)
                self.end_headers()
            def log_message(self, format, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.login()
            settings = {"enabled": True, "events": [], "server_url": f"http://127.0.0.1:{server.server_port}",
                        "topic": "private_topic", "token": "tk_test"}
            self.assertEqual(self.client.put("/api/notifications/ntfy", json=settings, headers=self.headers).status_code, 200)
            self.assertEqual(self.client.post("/api/notifications/ntfy/test", headers=self.headers).status_code, 200)
            self.assertEqual(requests, [("/private_topic", "Bearer tk_test", "HomeLab Dashboard: test notification")])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_ssh_notification_format_and_missing_ip(self):
        event = {"type": "ssh_login", "message": "original", "timestamp": 1730000000,
                 "user": "pi", "remote_ip": "2001:db8::1"}
        message = self.dashboard.notification_text("HomeLab 1", event)
        self.assertIn("🔓 SSH-Login\n", message)
        self.assertIn("🖥 Host: HomeLab 1", message)
        self.assertIn("👤 Benutzer: pi", message)
        self.assertIn("🌐 IP-Adresse: 2001:db8::1", message)
        self.assertRegex(message, r"⏰ Zeit: \d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2} [+-]\d{4}")
        event.update(type="ssh_logout", remote_ip=None)
        message = self.dashboard.notification_text("HomeLab 1", event)
        self.assertIn("🔐 SSH-Logout", message)
        self.assertIn("🌐 IP-Adresse: Nicht verfügbar", message)
        self.assertEqual(self.dashboard.notification_text("old", {"type": "ssh_login", "message": "original"}), "old: original")

    def test_formatted_ssh_event_is_sent_to_telegram(self):
        requests = []
        def handler(request):
            requests.append(request)
            if request.url.host == "agent.test":
                return httpx.Response(200, json={"events": [{"type": "ssh_logout", "timestamp": 1730000000,
                                                            "message": "session closed", "user": "pi",
                                                            "remote_ip": "192.0.2.10"}]})
            return httpx.Response(200, json={"ok": True})

        async def run():
            settings = {"events": ["ssh_logout"], "token": "123:abc", "chat_id": "-123"}
            cursors = {("HomeLab", "ssh_logout"): 100}
            with patch.object(self.dashboard.cfg, "AGENTS", {"HomeLab": {"url": "http://agent.test"}}):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    await self.dashboard.poll_notifications(client, settings, cursors, 115)
            payload = json.loads(requests[-1].content)
            self.assertEqual(payload["chat_id"], "-123")
            self.assertIn("🔐 SSH-Logout", payload["text"])
            self.assertIn("👤 Benutzer: pi", payload["text"])
            self.assertIn("🌐 IP-Adresse: 192.0.2.10", payload["text"])
            self.assertNotIn("parse_mode", payload)
            self.assertEqual(cursors[("HomeLab", "ssh_logout")], 115)
        import asyncio
        asyncio.run(run())

    def test_monitoring_settings_validate_hosts_and_require_telegram(self):
        self.login()
        payload = {"temperature_enabled": True, "daily_report": True, "thresholds": {"host": 45}}
        with patch.object(self.dashboard.cfg, "AGENTS", {"host": {"url": "http://agent.test"}}):
            self.assertEqual(self.client.put("/api/monitoring", json=payload, headers=self.headers).status_code, 400)
            settings = self.dashboard.read_settings()
            settings["telegram"] = {"enabled": True}
            self.dashboard.write_settings(settings)
            self.assertEqual(self.client.put("/api/monitoring", json=payload, headers=self.headers).status_code, 200)
            self.assertEqual(self.client.get("/api/monitoring").json()["thresholds"], {"host": 45})
            payload["thresholds"] = {"other": 45}
            self.assertEqual(self.client.put("/api/monitoring", json=payload, headers=self.headers).status_code, 400)

    def test_daily_report_time_settings_and_validation(self):
        self.login()
        self.assertEqual(self.client.get("/api/monitoring").json()["daily_report_time"], "12:00")
        payload = {"daily_report_time": "07:35"}
        self.assertEqual(self.client.put("/api/monitoring", json=payload, headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get("/api/monitoring").json()["daily_report_time"], "07:35")
        self.assertEqual(self.client.put("/api/monitoring", json={}, headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get("/api/monitoring").json()["daily_report_time"], "07:35")
        for value in ("7:35", "24:00", "12:60", "", "12:00:00", "１２:００"):
            self.assertEqual(self.client.put("/api/monitoring", json={"daily_report_time": value},
                                             headers=self.headers).status_code, 400)
        self.assertEqual(self.client.get("/api/monitoring").json()["daily_report_time"], "07:35")
        for value in ("00:00", "23:59"):
            self.assertEqual(self.client.put("/api/monitoring", json={"daily_report_time": value},
                                             headers=self.headers).status_code, 200)

    def test_daily_report_time_boundary_and_changes(self):
        import asyncio

        async def run():
            db = self.dashboard.open_monitoring_db()
            providers = {"telegram": {"token": "123:abc", "chat_id": "1"},
                         "ntfy": {"server_url": "http://ntfy.test", "topic": "topic"}}
            before = int(datetime(2026, 11, 14, 7, 34, 59).astimezone().timestamp())
            at = int(datetime(2026, 11, 14, 7, 35).astimezone().timestamp())
            tomorrow = int(datetime(2026, 11, 15, 7, 35).astimezone().timestamp())
            with patch.object(self.dashboard.cfg, "AGENTS", {"host": {"url": "http://agent.test"}}), \
                 patch.object(self.dashboard, "send_notification", new_callable=AsyncMock) as send:
                await self.dashboard.send_daily_reports(None, db, {}, before, providers, "07:35")
                self.assertEqual(send.await_count, 0)
                await self.dashboard.send_daily_reports(None, db, {}, at, providers, "07:35")
                self.assertEqual(send.await_count, 2)
                await self.dashboard.send_daily_reports(None, db, {}, at, providers, "06:00")
                await self.dashboard.send_daily_reports(None, db, {}, tomorrow, providers, "08:00")
                self.assertEqual(send.await_count, 2)
                await self.dashboard.send_daily_reports(None, db, {}, tomorrow, providers, "07:35")
                self.assertEqual(send.await_count, 4)
            db.close()
        asyncio.run(run())

    def test_docker_notification_format(self):
        event = {"type": "docker", "action": "start", "name": "dockhand", "image": "example/image:latest"}
        self.assertIn("🟢 dockhand started", self.dashboard.notification_text("host", event))
        event.update(action="die", exit_code="143")
        self.assertIn("Graceful termination (SIGTERM): Exit code 143", self.dashboard.notification_text("host", event))
        event["exit_code"] = "137"
        self.assertIn("❌ dockhand stopped!", self.dashboard.notification_text("host", event))

    def test_temperature_transition_reminders_and_report(self):
        import asyncio
        messages = []
        temperature = [48.2]
        def handler(request):
            if request.url.host == "agent.test":
                return httpx.Response(200, json={"temperature_c": temperature[0]})
            messages.append(json.loads(request.content)["text"])
            return httpx.Response(200, json={"ok": True})

        async def run():
            db = self.dashboard.open_monitoring_db()
            monitoring = {"temperature_enabled": True, "thresholds": {"host": 45}}
            telegram = {"token": "123:abc", "chat_id": "1"}
            with patch.object(self.dashboard.cfg, "AGENTS", {"host": {"url": "http://agent.test"}}):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    await self.dashboard.collect_temperatures(client, db, monitoring, telegram, 1000)
                    await self.dashboard.collect_temperatures(client, db, monitoring, telegram, 1100)
                    await self.dashboard.collect_temperatures(client, db, monitoring, telegram, 1300)
                    temperature[0] = 37.4
                    await self.dashboard.collect_temperatures(client, db, monitoring, telegram, 1600)
                    self.assertEqual(len(messages), 3)
                    self.assertIn("⚠️", messages[0])
                    self.assertIn("🌡️", messages[1])
                    self.assertIn("✅", messages[2])
                    now = int(datetime(2026, 11, 14, 12, 0).astimezone().timestamp())
                    await self.dashboard.send_daily_reports(client, db, telegram, now)
                    await self.dashboard.send_daily_reports(client, db, telegram, now)
                    self.assertEqual(len(messages), 4)
                    self.assertIn("SSH-Logins: 0 (unvollständig)", messages[3])
                    self.assertIn("Durchschnittstemperatur: Nicht verfügbar", messages[3])
            db.close()
        asyncio.run(run())

    def test_multi_provider_temperature_and_report_retries_are_independent(self):
        import asyncio
        requests = []
        temperature = [50]
        ntfy_failures = [1]
        def handler(request):
            requests.append(request)
            if request.url.host == "agent.test":
                return httpx.Response(200, json={"temperature_c": temperature[0]})
            if request.url.host == "ntfy.test" and ntfy_failures[0]:
                ntfy_failures[0] -= 1
                return httpx.Response(503)
            return httpx.Response(200, json={"ok": True})

        async def run():
            providers = {
                "telegram": {"token": "123:abc", "chat_id": "1"},
                "ntfy": {"server_url": "http://ntfy.test", "topic": "topic"},
            }
            monitoring = {"temperature_enabled": True, "thresholds": {"host": 45}}
            db = self.dashboard.open_monitoring_db()
            with patch.object(self.dashboard.cfg, "AGENTS", {"host": {"url": "http://agent.test"}}):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    await self.dashboard.collect_temperatures(client, db, monitoring, {}, 1000, providers)
                    await self.dashboard.collect_temperatures(client, db, monitoring, {}, 1015, providers)
                    self.assertEqual(len([r for r in requests if r.url.host == "api.telegram.org"]), 1)
                    self.assertEqual(len([r for r in requests if r.url.host == "ntfy.test"]), 2)
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM samples").fetchone()[0], 1)
                    temperature[0] = 40
                    await self.dashboard.collect_temperatures(client, db, monitoring, {}, 1300, providers)
                    self.assertEqual(len([r for r in requests if r.url.host == "api.telegram.org"]), 2)
                    self.assertEqual(len([r for r in requests if r.url.host == "ntfy.test"]), 3)
                    now = int(datetime(2026, 11, 14, 12, 0).astimezone().timestamp())
                    ntfy_failures[0] = 1
                    await self.dashboard.send_daily_reports(client, db, {}, now, providers)
                    await self.dashboard.send_daily_reports(client, db, {}, now + 15, providers)
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM provider_reports").fetchone()[0], 2)
                    self.assertEqual(len([r for r in requests if r.url.host == "api.telegram.org"]), 3)
                    self.assertEqual(len([r for r in requests if r.url.host == "ntfy.test"]), 5)
            db.close()
        asyncio.run(run())

    def test_notification_state_migrates_existing_telegram_reports(self):
        self.dashboard.STATE_DIR.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.dashboard.STATE_DIR / "monitoring.sqlite3")
        db.executescript("""
            CREATE TABLE temperatures (host TEXT PRIMARY KEY, above INTEGER, last_sent REAL);
            CREATE TABLE reports (host TEXT, day TEXT, PRIMARY KEY(host, day));
            INSERT INTO temperatures VALUES ('host', 1, 123);
            INSERT INTO reports VALUES ('host', '2026-11-14');
        """)
        db.close()
        db = self.dashboard.open_monitoring_db()
        self.assertEqual(db.execute("SELECT host, provider, above, last_sent FROM provider_temperatures").fetchall(),
                         [("host", "telegram", 1, 123)])
        self.assertEqual(db.execute("SELECT host, provider, day FROM provider_reports").fetchall(),
                         [("host", "telegram", "2026-11-14")])
        db.close()
        db = self.dashboard.open_monitoring_db()
        self.assertEqual(db.execute("SELECT COUNT(*) FROM provider_reports").fetchone()[0], 1)
        db.close()

    def test_report_collection_persists_events_and_marks_gaps(self):
        import asyncio
        requests = []
        def handler(request):
            requests.append(request)
            kind = request.url.params["types"]
            events = [{"type": kind, "timestamp": 110, "message": f"{kind} event"}] if int(request.url.params["since"]) <= 110 < int(request.url.params["until"]) else []
            return httpx.Response(200, json={"events": events})

        async def run():
            db = self.dashboard.open_monitoring_db()
            with patch.object(self.dashboard.cfg, "AGENTS", {"host": {"url": "http://agent.test"}}):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    await self.dashboard.collect_report_events(client, db, 100)
                    self.assertEqual(len(requests), 0)
                    await self.dashboard.collect_report_events(client, db, 115)
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 3)
                    db.close()
                    db = self.dashboard.open_monitoring_db()
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 3)
                    await self.dashboard.collect_report_events(client, db, 120)
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 3)
                    await self.dashboard.collect_report_events(client, db, 300)
                    self.assertEqual(db.execute("SELECT started FROM cursors WHERE kind='docker'").fetchone()[0], 300)
            db.close()
        asyncio.run(run())

    def test_complete_report_counts_each_host_over_24_hours(self):
        import asyncio
        messages = []
        def handler(request):
            messages.append(json.loads(request.content)["text"])
            return httpx.Response(200, json={"ok": True})

        async def run():
            db = self.dashboard.open_monitoring_db()
            now = int(datetime(2026, 11, 14, 12, 0).astimezone().timestamp())
            host = "report-host"
            db.executemany("INSERT INTO samples VALUES (?, ?, ?)",
                           [(host, now - 86400 + i * 300, 30.0) for i in range(288)])
            for kind in ("ssh_login", "ssh_logout", "docker"):
                db.execute("INSERT INTO cursors VALUES (?, ?, ?, ?)", (host, kind, now - 86400, now))
            db.executemany("INSERT INTO events VALUES (?, ?, ?, ?)", [
                (host, "ssh_login", now - 100, "login-1"),
                (host, "ssh_login", now - 200, "login-2"),
                (host, "docker", now - 300, "docker-1"),
                ("other", "ssh_login", now - 100, "other-1"),
                (host, "ssh_login", now - 86401, "old-1"),
            ])
            db.commit()
            with patch.object(self.dashboard.cfg, "AGENTS", {host: {"url": "http://agent.test"}}):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    await self.dashboard.send_daily_reports(client, db, {"token": "123:abc", "chat_id": "1"}, now)
            self.assertIn("Durchschnittstemperatur: 30.0°C (288 Messungen)", messages[0])
            self.assertIn("SSH-Logins: 2", messages[0])
            self.assertIn("SSH-Logouts: 0", messages[0])
            self.assertIn("Docker-Ereignisse: 1", messages[0])
            self.assertNotIn("unvollständig", messages[0])
            db.close()
        asyncio.run(run())

    def test_history_collection_retention_and_unavailable_metrics(self):
        import asyncio
        now = 3_000_000
        agents = {"online": {"url": "http://online.test"}, "offline": {"url": "http://offline.test"}}
        db = self.dashboard.open_history_db()
        db.executemany("INSERT INTO metrics VALUES (?, ?, ?, ?, ?, ?)", [
            ("online", now - self.dashboard.HISTORY_RETENTION, 1, 2, 3, 4),
            ("online", now - self.dashboard.HISTORY_RETENTION + 60, 5, 6, 7, 8),
        ])
        db.commit()
        db.close()
        async def fetch(name, item):
            if name == "offline":
                return name, {"online": False, "error": "unreachable"}
            return name, {"online": True, "cpu_percent": 20, "ram_percent": 30,
                          "storage_percent": 40, "temperature_c": None}
        with patch.object(self.dashboard.cfg, "AGENTS", agents), \
             patch.object(self.dashboard, "fetch", new=AsyncMock(side_effect=fetch)):
            with self.assertLogs("homelab-dashboard", level="WARNING") as logs:
                asyncio.run(self.dashboard.collect_history(now))
            self.assertIn("offline", logs.output[0])
            asyncio.run(self.dashboard.collect_history(now))
        db = self.dashboard.open_history_db()
        rows = db.execute("SELECT host, time, cpu, ram, disk, temperature FROM metrics ORDER BY time").fetchall()
        db.close()
        self.assertEqual(rows, [
            ("online", now - self.dashboard.HISTORY_RETENTION + 60, 5, 6, 7, 8),
            ("online", now, 20, 30, 40, None),
        ])

    def test_history_api_scopes_hosts_and_marks_missing_data(self):
        now = 1_800_000
        agents = {"host": {"url": "http://agent.test"}, "other": {"url": "http://other.test"}}
        db = self.dashboard.open_history_db()
        db.executemany("INSERT INTO metrics VALUES (?, ?, ?, ?, ?, ?)", [
            ("host", now - 300 + i * 60, 10 + i, 20, 30, None if i == 0 else 50)
            for i in range(5)
        ] + [
            ("host", now, 40, 50, 60, 70),
            ("other", now, 99, 99, 99, 99),
        ])
        db.commit()
        db.close()
        self.assertEqual(self.client.get("/api/history", params={"host": "host"}).status_code, 401)
        self.login()
        with patch.object(self.dashboard.cfg, "AGENTS", agents), patch.object(self.dashboard.time, "time", return_value=now):
            self.assertEqual(self.client.get("/api/history", params={"host": "missing"}).status_code, 404)
            self.assertEqual(self.client.get("/api/history", params={"host": "host", "hours": 2}).status_code, 400)
            response = self.client.get("/api/history", params={"host": "host", "hours": 24})
            for hours, bucket, count in ((1, 60, 60), (168, 3600, 169), (720, 14400, 181)):
                data = self.client.get("/api/history", params={"host": "host", "hours": hours}).json()
                self.assertEqual((data["bucket_seconds"], len(data["points"])), (bucket, count))
        self.assertEqual(response.status_code, 200)
        history = response.json()
        self.assertEqual(history["bucket_seconds"], 300)
        previous, current = history["points"][-2:]
        self.assertEqual(previous["cpu"], 12)
        self.assertTrue(previous["complete"])
        self.assertTrue(previous["missing"]["temperature"])
        self.assertFalse(previous["missing"]["cpu"])
        self.assertEqual(current["cpu"], 40)
        self.assertTrue(current["complete"])
        self.assertFalse(any(current["missing"].values()))
        self.assertIsNone(history["points"][0]["cpu"])
        self.assertFalse(history["points"][0]["complete"])

    def test_history_runs_without_telegram_and_survives_restart(self):
        import time
        agents = {"host": {"url": "http://agent.test"}}
        result = ("host", {"online": True, "cpu_percent": 23, "ram_percent": 34,
                           "storage_percent": 45, "temperature_c": 56})
        with patch.object(self.dashboard.cfg, "AGENTS", agents), \
             patch.object(self.dashboard, "fetch", new=AsyncMock(return_value=result)):
            with TestClient(self.dashboard.app) as client:
                self.assertEqual(client.post("/api/auth/login", json={"password": "correct-password"},
                                             headers=self.headers).status_code, 200)
                for _ in range(40):
                    response = client.get("/api/history", params={"host": "host", "hours": 1})
                    if response.json()["points"][-1]["cpu"] == 23:
                        break
                    time.sleep(0.05)
                else:
                    self.fail("Background history collection did not run")
        db = self.dashboard.open_history_db()
        try:
            self.assertEqual(db.execute("SELECT cpu, ram, disk, temperature FROM metrics").fetchone(),
                             (23, 34, 45, 56))
        finally:
            db.close()
        with patch.object(self.dashboard.cfg, "AGENTS", agents), \
             patch.object(self.dashboard, "fetch", new=AsyncMock(return_value=("host", {"online": False, "error": "offline"}))):
            with self.assertLogs("homelab-dashboard", level="WARNING"):
                with TestClient(self.dashboard.app) as client:
                    self.assertEqual(client.post("/api/auth/login", json={"password": "correct-password"},
                                                 headers=self.headers).status_code, 200)
                    response = client.get("/api/history", params={"host": "host", "hours": 1})
                    self.assertEqual(response.json()["points"][-1]["cpu"], 23)


class AgentEventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = load_module("agent_test", ROOT / "agent.py")
        cls.client = TestClient(cls.agent.app)

    def test_event_filtering_and_half_open_interval(self):
        journal = [
            {"__REALTIME_TIMESTAMP": "101000000", "SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "pam_unix(sshd:session): session opened for user alice"},
            {"__REALTIME_TIMESTAMP": "102000000", "SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "pam_unix(sshd:session): session closed for user alice"},
            {"__REALTIME_TIMESTAMP": "103000000", "SYSLOG_IDENTIFIER": "fail2ban-server", "MESSAGE": "[sshd] Ban 192.0.2.1"},
            {"__REALTIME_TIMESTAMP": "105000000", "SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "session opened for user late"},
        ]
        docker = [
            {"timeNano": 104000000000, "Action": "start", "Actor": {"Attributes": {"name": "web"}}},
            {"timeNano": 104500000000, "Action": "stop", "Actor": {"Attributes": {"name": "web"}}},
        ]
        def fake_run(command, timeout=5):
            data = journal if command[0] == "journalctl" else docker
            return {"rc": 0, "out": "\n".join(json.dumps(item) for item in data)}

        with patch.object(self.agent, "run", side_effect=fake_run):
            response = self.client.get("/api/events", params=[
                ("since", 100), ("until", 105), ("types", "ssh_login"),
                ("types", "ssh_logout"), ("types", "fail2ban"), ("types", "docker")])
        self.assertEqual(response.status_code, 200)
        self.assertEqual([event["type"] for event in response.json()["events"]],
                         ["ssh_login", "ssh_logout", "fail2ban", "docker"])

    def test_source_error_is_not_silenced(self):
        with patch.object(self.agent, "run", return_value={"rc": 1, "out": "denied"}):
            response = self.client.get("/api/events", params={"since": 100, "until": 105, "types": "docker"})
        self.assertEqual(response.status_code, 503)

    def test_ssh_login_and_logout_correlate_ip_across_poll_intervals(self):
        boot = "a" * 32
        def entry(second, message):
            return {"__REALTIME_TIMESTAMP": str(second * 1_000_000), "SYSLOG_IDENTIFIER": "sshd",
                    "_PID": "42", "_BOOT_ID": boot, "MESSAGE": message}
        journal = [
            entry(99, "Accepted publickey for alice from 2001:db8::1 port 50000 ssh2"),
            entry(101, "pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)"),
            entry(500, "pam_unix(sshd:session): session closed for user alice"),
        ]
        def fake_run(command, timeout=5):
            return {"rc": 0, "out": "\n".join(json.dumps(item) for item in journal)}
        with patch.object(self.agent, "run", side_effect=fake_run) as run:
            login = self.client.get("/api/events", params={"since": 100, "until": 110, "types": "ssh_login"}).json()["events"][0]
            logout = self.client.get("/api/events", params={"since": 495, "until": 510, "types": "ssh_logout"}).json()["events"][0]
        self.assertEqual((login["user"], login["remote_ip"]), ("alice", "2001:db8::1"))
        self.assertEqual((logout["user"], logout["remote_ip"]), ("alice", "2001:db8::1"))
        self.assertTrue(any(f"_BOOT_ID={boot}" in call.args[0] and "_PID=42" in call.args[0] for call in run.call_args_list))

    def test_ssh_ip_is_unknown_when_no_matching_recent_accept(self):
        boot = "b" * 32
        def entry(second, message):
            return {"__REALTIME_TIMESTAMP": str(second * 1_000_000), "SYSLOG_IDENTIFIER": "sshd",
                    "_PID": "55", "_BOOT_ID": boot, "MESSAGE": message}
        journal = [
            entry(1, "Accepted publickey for alice from 192.0.2.1 port 1234 ssh2"),
            entry(190, "Accepted publickey for bob from 192.0.2.2 port 1234 ssh2"),
            entry(200, "pam_unix(sshd:session): session opened for user alice"),
        ]
        with patch.object(self.agent, "run", return_value={"rc": 0, "out": "\n".join(json.dumps(item) for item in journal)}):
            result = self.client.get("/api/events", params={"since": 199, "until": 201, "types": "ssh_login"}).json()["events"][0]
        self.assertEqual(result["user"], "alice")
        self.assertIsNone(result["remote_ip"])

    def test_event_api_requires_configured_key(self):
        with patch.object(self.agent, "KEY", "agent-secret"):
            self.assertEqual(self.client.get("/api/events", params={"since": 100, "until": 105}).status_code, 401)

    def test_container_security_sources_are_unavailable_until_enabled(self):
        with patch.object(self.agent, "CONTAINER_MODE", True), \
             patch.dict(os.environ, {"HOMELAB_ENABLE_UFW": "0", "HOMELAB_ENABLE_FAIL2BAN": "0",
                                     "HOMELAB_JOURNAL_DIR": ""}), \
             patch.object(self.agent, "run") as run:
            self.assertIsNone(self.agent.firewall()["active"])
            self.assertIsNone(self.agent.fail2ban()["active"])
            response = self.client.get("/api/events", params={"since": 100, "until": 105, "types": "ssh_login"})
            self.assertEqual(response.status_code, 503)
            run.assert_not_called()

    def test_configured_container_journal_uses_host_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            pathlib.Path(directory, "system.journal").touch()
            entry = {"__REALTIME_TIMESTAMP": "101000000", "SYSLOG_IDENTIFIER": "sshd",
                     "MESSAGE": "session opened for user alice"}
            with patch.object(self.agent, "CONTAINER_MODE", True), \
                 patch.dict(os.environ, {"HOMELAB_JOURNAL_DIR": directory}), \
                 patch.object(self.agent, "run", return_value={"rc": 0, "out": json.dumps(entry)}) as run:
                response = self.client.get("/api/events", params={"since": 100, "until": 105,
                                                                   "types": "ssh_login", "details": "false"})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(len(response.json()["events"]), 1)
                self.assertEqual(run.call_args.args[0][:2], ["journalctl", f"--directory={directory}"])

    def test_enabled_security_commands_and_failures(self):
        with patch.object(self.agent, "CONTAINER_MODE", True), \
             patch.dict(os.environ, {"HOMELAB_ENABLE_UFW": "1", "HOMELAB_ENABLE_FAIL2BAN": "1"}), \
             patch.object(self.agent, "run", side_effect=[
                 {"rc": 0, "out": "Status: inactive"}, {"rc": 1, "out": "permission denied"}
             ]) as run:
            self.assertFalse(self.agent.firewall()["active"])
            self.assertIsNone(self.agent.fail2ban()["active"])
            self.assertEqual(run.call_args_list[0].args[0], ["ufw", "status"])
            self.assertEqual(run.call_args_list[1].args[0], ["fail2ban-client", "-s", "/run/fail2ban/fail2ban.sock", "status"])

    def test_docker_failure_is_explicit(self):
        with patch.object(self.agent, "run", return_value={"rc": 1, "out": "permission denied"}):
            containers, error = self.agent.docker()
        self.assertEqual(containers, [])
        self.assertEqual(error, "permission denied")

    def test_container_fail2ban_uses_configured_socket(self):
        with patch.object(self.agent, "CONTAINER_MODE", True), \
             patch.dict(os.environ, {"HOMELAB_ENABLE_FAIL2BAN": "1",
                                     "HOMELAB_FAIL2BAN_SOCKET": "/host/root/run/fail2ban/fail2ban.sock"}), \
             patch.object(self.agent, "run", return_value={"rc": 0, "out": "Status\n`- Jail list:"}) as run:
            self.assertTrue(self.agent.fail2ban()["active"])
            self.assertEqual(run.call_args.args[0],
                             ["fail2ban-client", "-s", "/host/root/run/fail2ban/fail2ban.sock", "status"])

    def test_docker_event_includes_image_and_exit_code(self):
        event = {"timeNano": 101000000000, "Action": "die",
                 "Actor": {"Attributes": {"name": "dockhand", "image": "example/image:latest", "exitCode": "143"}}}
        with patch.object(self.agent, "run", return_value={"rc": 0, "out": json.dumps(event)}):
            response = self.client.get("/api/events", params={"since": 100, "until": 105, "types": "docker"})
        item = response.json()["events"][0]
        self.assertEqual((item["name"], item["image"], item["exit_code"]), ("dockhand", "example/image:latest", "143"))

    def test_event_counts_do_not_require_ssh_detail_lookup(self):
        entry = {"__REALTIME_TIMESTAMP": "101000000", "SYSLOG_IDENTIFIER": "sshd",
                 "_PID": "42", "_BOOT_ID": "a" * 32, "MESSAGE": "session opened for user alice"}
        with patch.object(self.agent, "run", return_value={"rc": 0, "out": json.dumps(entry)}) as run:
            response = self.client.get("/api/events", params={"since": 100, "until": 105,
                                                              "types": "ssh_login", "details": "false"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("remote_ip", response.json()["events"][0])
        self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()