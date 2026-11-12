"""Black-box security checks for the loopback SyncApp host.

Run after `dotnet build SyncApp/SyncApp.csproj` with `python3 tests/http_security.py`.
"""

import http.client
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "SyncApp" / "bin" / "Debug" / "net10.0" / "SyncApp.dll"


class HostSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not APP.is_file():
            raise RuntimeError("Build SyncApp first: dotnet build SyncApp/SyncApp.csproj")
        cls.data = tempfile.TemporaryDirectory(prefix="syncapp-http-test-")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            cls.port = listener.getsockname()[1]
        env = os.environ.copy()
        env["SYNCAPP_DATA_DIR"] = cls.data.name
        env["SYNCAPP_PORT"] = str(cls.port)
        cls.server = subprocess.Popen(
            ["dotnet", str(APP)], cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                status, body = cls.request("GET", "/api/session")
                if status == 200:
                    cls.csrf = json.loads(body)["csrf"]
                    return
            except (ConnectionError, OSError):
                pass
            if cls.server.poll() is not None:
                raise RuntimeError("SyncApp exited while starting: " + cls.server.stderr.read())
            time.sleep(0.1)
        cls.server.terminate()
        raise RuntimeError("SyncApp did not start on loopback")

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        try:
            cls.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.server.kill()
            cls.server.wait(timeout=5)
        cls.server.stderr.close()
        cls.data.cleanup()

    @classmethod
    def request(cls, method, path, headers=None, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read().decode("utf-8", errors="replace")
        finally:
            connection.close()

    def test_missing_or_wrong_csrf_rejected(self):
        payload = json.dumps({"folder": "example", "junkPath": "/missing", "repoPath": "/missing", "passphrase": "abcdefgh"})
        headers = {"Content-Type": "application/json"}
        self.assertEqual(403, self.request("POST", "/api/projects/personal", headers, payload)[0])
        headers["X-SyncApp-CSRF"] = "wrong-token"
        self.assertEqual(403, self.request("POST", "/api/projects/personal", headers, payload)[0])

    def test_foreign_origin_rejected_even_with_valid_csrf(self):
        headers = {"X-SyncApp-CSRF": self.csrf, "Origin": "http://evil.example", "Content-Type": "application/json"}
        self.assertEqual(403, self.request("POST", "/api/projects/personal", headers, "{}")[0])
        self.assertEqual(403, self.request("GET", "/api/session", {"Origin": "http://evil.example"})[0])

    def test_dns_rebinding_host_rejected(self):
        headers = {"Host": "evil.example", "Origin": "http://evil.example", "X-SyncApp-CSRF": self.csrf, "Content-Type": "application/json"}
        self.assertEqual(403, self.request("POST", "/api/projects/personal", headers, "{}")[0])
        self.assertEqual(403, self.request("GET", "/api/session", {"Host": "evil.example"})[0])
        self.assertEqual(403, self.request("GET", "/api/session", {"Host": f"localhost.evil.example:{self.port}"})[0])

    def test_get_cannot_create_project(self):
        status, _ = self.request("GET", "/api/projects/personal")
        self.assertIn(status, (404, 405))
        session = json.loads(self.request("GET", "/api/session")[1])
        self.assertEqual([], session["projects"])

    def test_recovery_uses_normal_guards_and_service_activation(self):
        path = "/api/projects/missing/recover"
        body = json.dumps({"passphrase": "test passphrase"})
        self.assertEqual(403, self.request("POST", path, {"Content-Type": "application/json"}, body)[0])
        headers = {"Content-Type": "application/json", "X-SyncApp-CSRF": self.csrf}
        status, result = self.request("POST", path, headers, body)
        self.assertEqual(404, status, result)
        self.assertEqual("Проект не найден", json.loads(result)["error"])
        self.assertIn(self.request("GET", path)[0], (404, 405))

    def test_oversized_json_request_rejected_before_reading_body(self):
        headers = {"X-SyncApp-CSRF": self.csrf, "Content-Length": str(66 * 1024 * 1024),
                   "Content-Type": "application/json"}
        status, result = self.request("POST", "/api/projects/missing/sync", headers, b"")
        self.assertEqual(413, status, result)

    def test_qr_file_transport_routes_are_removed(self):
        for path in (
            "/api/projects/missing/initial/export",
            "/api/projects/missing/initial/import",
            "/api/projects/missing/initial/import-from-junk",
            "/api/projects/missing/work/export",
            "/api/projects/missing/work/import",
            "/api/projects/missing/receipts/import",
            "/api/projects/missing/receipts/sync",
            "/api/projects/missing/outbox",
        ):
            status, _ = self.request("GET" if path.endswith("outbox") else "POST", path,
                                     {"Content-Type": "application/json", "X-SyncApp-CSRF": self.csrf}, "{}")
            self.assertIn(status, (404, 405), f"legacy transfer route still exists: {path}")

    def test_work_push_true_is_rejected_before_transport_side_effects(self):
        with tempfile.TemporaryDirectory(prefix="syncapp-http-work-") as fixture:
            root = pathlib.Path(fixture)
            source = root / "source"
            junk = root / "junk"
            bare = root / "remote.git"
            for path in (source, junk):
                path.mkdir()
                subprocess.run(["git", "init", "-b", "main"], cwd=path, check=True, capture_output=True)
                subprocess.run(["git", "config", "user.name", "HTTP Test"], cwd=path, check=True)
                subprocess.run(["git", "config", "user.email", "http-test@example.invalid"], cwd=path, check=True)
                (path / "base.txt").write_text("baseline\n", encoding="utf-8")
                subprocess.run(["git", "add", "."], cwd=path, check=True)
                subprocess.run(["git", "commit", "-m", "baseline"], cwd=path, check=True, capture_output=True)
            subprocess.run(["git", "init", "--bare", "-b", "main", str(bare)], check=True, capture_output=True)
            descriptor = {
                "version": 3,
                "projectId": "1" * 32,
                "channelId": "2" * 32,
                "epoch": 1,
                "personalRecipient": "age1personal",
                "personalSigningKey": "public-signing-key",
                "workRecipient": "age1work",
            }
            project_dir = junk / "http-project"
            project_dir.mkdir()
            (project_dir / "project.json").write_text(json.dumps(descriptor, indent=2), encoding="utf-8")
            subprocess.run(["git", "add", "http-project/project.json"], cwd=junk, check=True)
            subprocess.run(["git", "commit", "-m", "descriptor"], cwd=junk, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", str(bare)], cwd=junk, check=True)
            subprocess.run(["git", "push", "-u", "origin", "main"], cwd=junk, check=True, capture_output=True)

            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=junk, text=True).strip()
            marker = root / "push-hook-invoked"
            hook_dir = pathlib.Path(subprocess.check_output(["git", "rev-parse", "--absolute-git-dir"], cwd=junk, text=True).strip()) / "hooks"
            hook = hook_dir / "pre-push"
            hook.write_text(f"#!/bin/sh\nprintf invoked > '{marker}'\n", encoding="utf-8")
            hook.chmod(0o700)
            project = {
                "id": "work-http",
                "side": "Work",
                "folder": "http-project",
                "junkPath": str(junk),
                "repoPath": str(source),
                "branch": "main",
                "projectId": descriptor["projectId"],
                "channelId": descriptor["channelId"],
                "epoch": 1,
                "keysFile": str(root / "missing.key"),
                "personalRecipient": descriptor["personalRecipient"],
                "personalSigningKey": descriptor["personalSigningKey"],
                "workRecipient": descriptor["workRecipient"],
                "baselineCommit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip(),
                "baselineVerified": True,
            }
            personal_project = {**project, "id": "personal-http", "side": "Personal"}
            (pathlib.Path(self.data.name) / "projects.json").write_text(json.dumps([project, personal_project], indent=2) + "\n", encoding="utf-8")
            session_status, session_body = self.request("GET", "/api/session")
            self.assertEqual(200, session_status, session_body)
            session_projects = json.loads(session_body)["projects"]
            self.assertEqual(["Work", "Personal"], [item["side"] for item in session_projects],
                             "HTTP session did not serialize both project roles as strings")
            headers = {"X-SyncApp-CSRF": self.csrf, "Content-Type": "application/json"}
            status, result = self.request("POST", "/api/projects/work-http/sync", headers,
                                          json.dumps({"passphrase": "unused", "push": True, "maxCommits": 0}))
            self.assertEqual(400, status, result)
            self.assertIn("Рабочая сторона доступна для чтения", json.loads(result)["error"])
            self.assertEqual(head, subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=junk, text=True).strip())
            self.assertEqual([], subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=junk, text=True).splitlines())
            self.assertFalse(marker.exists(), "Work HTTP sync invoked git push")


if __name__ == "__main__":
    unittest.main(verbosity=2)
