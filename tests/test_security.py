from __future__ import annotations

import io
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from app import create_app
from app.db import connect


class Client:
    def __init__(self, app):
        self.app = app
        self.cookie = ""

    def request(self, method: str, path: str, data: dict | None = None, remote_addr: str = "127.0.0.1"):
        encoded = urlencode(data or {}).encode()
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(encoded)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "HTTP_COOKIE": self.cookie,
            "REMOTE_ADDR": remote_addr,
            "wsgi.input": io.BytesIO(encoded),
        }
        captured = {}

        def start_response(status, headers):
            captured["status"] = int(status.split()[0])
            captured["headers"] = dict(headers)

        body = b"".join(self.app(environ, start_response))
        if "Set-Cookie" in captured["headers"]:
            self.cookie = captured["headers"]["Set-Cookie"].split(";", 1)[0]
        return captured["status"], captured["headers"], body

    def csrf(self, path: str = "/auth/register") -> str:
        _status, _headers, body = self.request("GET", path)
        match = re.search(rb"name='csrf_token' value='([^']+)'", body)
        if not match:
            raise AssertionError("CSRF token not found")
        return match.group(1).decode()


class SecureWebAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp_dir.name) / "test.sqlite3")
        self.app = create_app(database=self.database, secret_key="test-secret")
        self.client = Client(self.app)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def register(self, username: str = "analyst", password: str = "correct-horse-battery"):
        return self.client.request(
            "POST", "/auth/register", {"username": username, "password": password, "csrf_token": self.client.csrf()}
        )

    def login(self, username: str = "analyst", password: str = "correct-horse-battery"):
        token = self.client.csrf("/auth/login")
        return self.client.request(
            "POST", "/auth/login", {"username": username, "password": password, "csrf_token": token}
        )

    def create_finding(self, title: str = "Suspicious login", details: str = "Five failures followed by success"):
        token = self.client.csrf("/findings/new")
        return self.client.request(
            "POST", "/findings/new", {"title": title, "severity": "high", "details": details, "csrf_token": token}
        )

    def logout(self):
        token = self.client.csrf("/")
        return self.client.request("POST", "/auth/logout", {"csrf_token": token})

    def test_csrf_is_required(self) -> None:
        status, _headers, _body = self.client.request(
            "POST", "/auth/register", {"username": "analyst", "password": "correct-horse-battery"}
        )
        self.assertEqual(status, 400)

    def test_password_is_hashed(self) -> None:
        self.register()
        with connect(self.database) as database:
            stored = database.execute("SELECT password_hash FROM users").fetchone()["password_hash"]
        self.assertNotIn("correct-horse-battery", stored)
        self.assertTrue(stored.startswith("scrypt$"))

    def test_sql_injection_style_login_fails(self) -> None:
        self.register()
        status, _headers, _body = self.login("' OR 1=1--", "anything-at-all")
        self.assertEqual(status, 401)

    def test_user_content_is_html_escaped(self) -> None:
        self.register()
        self.login()
        self.create_finding(title="<script>alert(1)</script>")
        _status, _headers, body = self.client.request("GET", "/")
        self.assertNotIn(b"<script>alert(1)</script>", body)
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", body)

    def test_user_cannot_delete_another_users_finding(self) -> None:
        self.register("first_user")
        self.login("first_user")
        self.create_finding()
        with connect(self.database) as database:
            finding_id = database.execute("SELECT id FROM findings").fetchone()["id"]
        self.logout()
        self.register("second_user")
        self.login("second_user")
        token = self.client.csrf("/")
        status, _headers, _body = self.client.request(
            "POST", f"/findings/{finding_id}/delete", {"csrf_token": token}
        )
        self.assertEqual(status, 404)
        with connect(self.database) as database:
            remaining = database.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        self.assertEqual(remaining, 1)

    def test_security_headers_are_present(self) -> None:
        _status, headers, _body = self.client.request("GET", "/auth/login")
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_login_rate_limit(self) -> None:
        self.register()
        for _ in range(5):
            self.login(password="wrong-password-value")
        status, _headers, _body = self.login(password="wrong-password-value")
        self.assertEqual(status, 429)


if __name__ == "__main__":
    unittest.main()
