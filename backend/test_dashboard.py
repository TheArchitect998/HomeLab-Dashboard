import importlib.util
import json
import os
import pathlib
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch
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
