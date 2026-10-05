from __future__ import annotations

import hashlib
import hmac
import html
import os
import re
import secrets
import time
from collections import defaultdict, deque
from http import HTTPStatus
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs

from .db import connect, init_db


USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
SEVERITIES = {"low", "medium", "high", "critical"}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${derived.hex()}"


def verify_password(stored: str, candidate: str) -> bool:
    try:
        algorithm, salt_hex, expected_hex = stored.split("$", 2)
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(
            candidate.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=32
        )
        return hmac.compare_digest(actual, bytes.fromhex(expected_hex))
    except (ValueError, TypeError):
        return False


class SecureFindingsApp:
    def __init__(self, database: str, secret_key: str, secure_cookie: bool = False):
        self.database = database
        self.secret_key = secret_key.encode()
        self.secure_cookie = secure_cookie
        self.sessions: dict[str, dict] = {}
        self.login_attempts: dict[str, deque[float]] = defaultdict(deque)
        init_db(database)

    def __call__(self, environ: dict, start_response: Callable):
        session_id, session = self._session(environ.get("HTTP_COOKIE", ""))
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        form = self._read_form(environ) if method == "POST" else {}
        user = self._current_user(session)
        try:
            status, body, extra_headers = self._route(method, path, form, session, user, environ)
        except RequestError as error:
            status = error.status
            body = self._page(error.title, f"<p>{html.escape(error.message)}</p>").encode()
            extra_headers = []
        if session.pop("_rotate", False):
            replacement = secrets.token_urlsafe(24)
            self.sessions[replacement] = session
            self.sessions.pop(session_id, None)
            session_id = replacement
        headers = [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
            ("Cache-Control", "no-store"),
            ("Set-Cookie", self._cookie(session_id)),
            *extra_headers,
        ]
        start_response(f"{status.value} {status.phrase}", headers)
        return [body]

    def _route(self, method: str, path: str, form: dict[str, str], session: dict, user, environ: dict):
        if method == "GET" and path == "/auth/register":
            return self._ok(self._auth_form("Register", "/auth/register", True, session))
        if method == "POST" and path == "/auth/register":
            self._check_csrf(form, session)
            return self._register(form)
        if method == "GET" and path == "/auth/login":
            return self._ok(self._auth_form("Sign in", "/auth/login", False, session))
        if method == "POST" and path == "/auth/login":
            self._check_csrf(form, session)
            return self._login(form, session, environ.get("REMOTE_ADDR", "unknown"))
        if method == "POST" and path == "/auth/logout":
            self._require_user(user)
            self._check_csrf(form, session)
            session.clear()
            session["_rotate"] = True
            return self._redirect("/auth/login")
        if method == "GET" and path == "/":
            self._require_user(user)
            return self._ok(self._findings_page(user, session))
        if method == "GET" and path == "/findings/new":
            self._require_user(user)
            return self._ok(self._finding_form(session))
        if method == "POST" and path == "/findings/new":
            self._require_user(user)
            self._check_csrf(form, session)
            return self._create_finding(form, user)
        delete_match = re.fullmatch(r"/findings/(\d+)/delete", path)
        if method == "POST" and delete_match:
            self._require_user(user)
            self._check_csrf(form, session)
            return self._delete_finding(int(delete_match.group(1)), user)
        raise RequestError(HTTPStatus.NOT_FOUND, "Not found", "The requested page does not exist.")

    def _register(self, form: dict[str, str]):
        username = form.get("username", "").strip()
        password = form.get("password", "")
        if not USERNAME_RE.fullmatch(username):
            raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid username", "Use 3–32 letters, numbers, dots, dashes, or underscores.")
        if not 12 <= len(password) <= 128:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid password", "Use between 12 and 128 characters.")
        try:
            with connect(self.database) as database:
                database.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, hash_password(password)),
                )
        except Exception as exc:
            if "UNIQUE constraint failed" not in str(exc):
                raise
            raise RequestError(HTTPStatus.CONFLICT, "Username unavailable", "Choose a different username.") from exc
        return self._redirect("/auth/login")

    def _login(self, form: dict[str, str], session: dict, identity: str):
        if self._rate_limited(identity):
            raise RequestError(HTTPStatus.TOO_MANY_REQUESTS, "Too many attempts", "Wait one minute and try again.")
        username = form.get("username", "").strip()
        with connect(self.database) as database:
            user = database.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE",
                (username,),
            ).fetchone()
        if user is None or not verify_password(user["password_hash"], form.get("password", "")):
            raise RequestError(HTTPStatus.UNAUTHORIZED, "Sign-in failed", "Invalid username or password.")
        csrf = session.get("csrf_token")
        session.clear()
        session.update({"user_id": user["id"], "csrf_token": csrf or secrets.token_urlsafe(32), "_rotate": True})
        return self._redirect("/")

    def _create_finding(self, form: dict[str, str], user):
        title = form.get("title", "").strip()
        severity = form.get("severity", "").lower()
        details = form.get("details", "").strip()
        if not 1 <= len(title) <= 100 or severity not in SEVERITIES or not 1 <= len(details) <= 2000:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid finding", "Check the title, severity, and details.")
        with connect(self.database) as database:
            database.execute(
                "INSERT INTO findings (owner_id, title, severity, details) VALUES (?, ?, ?, ?)",
                (user["id"], title, severity, details),
            )
        return self._redirect("/")

    def _delete_finding(self, finding_id: int, user):
        with connect(self.database) as database:
            result = database.execute(
                "DELETE FROM findings WHERE id = ? AND owner_id = ?", (finding_id, user["id"])
            )
        if result.rowcount == 0:
            raise RequestError(HTTPStatus.NOT_FOUND, "Finding not found", "The finding does not exist or belongs to another user.")
        return self._redirect("/")

    def _current_user(self, session: dict):
        if not session.get("user_id"):
            return None
        with connect(self.database) as database:
            return database.execute("SELECT id, username FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    def _findings_page(self, user, session: dict) -> str:
        with connect(self.database) as database:
            findings = database.execute(
                "SELECT id, title, severity, details FROM findings WHERE owner_id = ? ORDER BY id DESC",
                (user["id"],),
            ).fetchall()
        cards = "".join(
            f"<article class='card'><small>{html.escape(row['severity'].upper())}</small>"
            f"<h2>{html.escape(row['title'])}</h2><p>{html.escape(row['details'])}</p>"
            f"<form method='post' action='/findings/{row['id']}/delete'>"
            f"{self._csrf_input(session)}<button class='danger'>Delete</button></form></article>"
            for row in findings
        ) or "<div class='card'><p>No findings yet.</p></div>"
        content = (
            f"<h1>My findings</h1><p>Signed in as {html.escape(user['username'])}.</p>"
            f"<p><a class='button' href='/findings/new'>New finding</a></p>{cards}"
        )
        return self._page("My findings", content, user=user, session=session)

    def _auth_form(self, title: str, action: str, registering: bool, session: dict) -> str:
        note = "<p>Use at least 12 characters.</p>" if registering else ""
        content = (
            f"<div class='card'><h1>{title}</h1>{note}<form method='post' action='{action}'>"
            f"{self._csrf_input(session)}<label>Username<input name='username' required></label>"
            f"<label>Password<input type='password' name='password' required></label>"
            f"<button>{title}</button></form></div>"
        )
        return self._page(title, content)

    def _finding_form(self, session: dict) -> str:
        content = (
            "<div class='card'><h1>New finding</h1><form method='post'>"
            f"{self._csrf_input(session)}<label>Title<input name='title' maxlength='100' required></label>"
            "<label>Severity<select name='severity'><option>low</option><option>medium</option>"
            "<option>high</option><option>critical</option></select></label>"
            "<label>Details<textarea name='details' maxlength='2000' required></textarea></label>"
            "<button>Save finding</button></form></div>"
        )
        return self._page("New finding", content, session=session)

    def _page(self, title: str, content: str, user=None, session: dict | None = None) -> str:
        logout = ""
        if user and session is not None:
            logout = f"<form class='inline' method='post' action='/auth/logout'>{self._csrf_input(session)}<button>Sign out</button></form>"
        return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{html.escape(title)} · Secure Findings</title><style>
        :root{{color-scheme:dark;font-family:system-ui;background:#0b1220;color:#e5edf7}}body{{margin:0}}nav,main{{width:min(850px,calc(100% - 32px));margin:auto}}nav{{display:flex;justify-content:space-between;align-items:center;padding:22px 0}}a{{color:#7dd3fc}}.card{{background:#121d30;border:1px solid #263854;border-radius:12px;padding:22px;margin:16px 0}}input,textarea,select{{box-sizing:border-box;width:100%;margin:6px 0 16px;padding:11px;background:#0b1220;color:inherit;border:1px solid #405575;border-radius:7px}}textarea{{min-height:130px}}button,.button{{display:inline-block;width:auto;padding:10px 16px;border:0;border-radius:7px;background:#38bdf8;color:#07111f;font-weight:700;text-decoration:none}}.danger{{background:#fb7185}}.inline{{display:inline}}</style></head><body><nav><strong>Secure Findings</strong><div><a href='/'>Home</a> {logout}</div></nav><main>{content}</main></body></html>"""

    def _session(self, cookie_header: str) -> tuple[str, dict]:
        token = ""
        for part in cookie_header.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "session_id" and self._valid_signed(value):
                token = value.split(".", 1)[0]
        if not token or token not in self.sessions:
            token = secrets.token_urlsafe(24)
            self.sessions[token] = {"csrf_token": secrets.token_urlsafe(32)}
        else:
            self.sessions[token].setdefault("csrf_token", secrets.token_urlsafe(32))
        return token, self.sessions[token]

    def _signed(self, token: str) -> str:
        signature = hmac.new(self.secret_key, token.encode(), hashlib.sha256).hexdigest()
        return f"{token}.{signature}"

    def _valid_signed(self, value: str) -> bool:
        token, separator, _signature = value.partition(".")
        return bool(separator) and hmac.compare_digest(self._signed(token), value)

    def _cookie(self, token: str) -> str:
        secure = "; Secure" if self.secure_cookie else ""
        return f"session_id={self._signed(token)}; Path=/; HttpOnly; SameSite=Lax{secure}"

    def _read_form(self, environ: dict) -> dict[str, str]:
        try:
            length = min(int(environ.get("CONTENT_LENGTH") or 0), 32 * 1024)
        except ValueError:
            length = 0
        raw = environ["wsgi.input"].read(length).decode("utf-8", errors="replace")
        return {key: values[-1] for key, values in parse_qs(raw, keep_blank_values=True).items()}

    def _check_csrf(self, form: dict[str, str], session: dict) -> None:
        if not hmac.compare_digest(form.get("csrf_token", ""), session.get("csrf_token", "")):
            raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid request", "The CSRF token is missing or invalid.")

    @staticmethod
    def _require_user(user) -> None:
        if user is None:
            raise RequestError(HTTPStatus.UNAUTHORIZED, "Sign in required", "Sign in to continue.")

    def _rate_limited(self, identity: str) -> bool:
        now = time.monotonic()
        attempts = self.login_attempts[identity]
        while attempts and attempts[0] <= now - 60:
            attempts.popleft()
        if len(attempts) >= 5:
            return True
        attempts.append(now)
        return False

    @staticmethod
    def _csrf_input(session: dict) -> str:
        return f"<input type='hidden' name='csrf_token' value='{html.escape(session['csrf_token'])}'>"

    @staticmethod
    def _ok(text: str):
        return HTTPStatus.OK, text.encode(), []

    @staticmethod
    def _redirect(location: str):
        return HTTPStatus.SEE_OTHER, b"", [("Location", location)]


class RequestError(Exception):
    def __init__(self, status: HTTPStatus, title: str, message: str):
        super().__init__(message)
        self.status = status
        self.title = title
        self.message = message


def create_app(database: str | None = None, secret_key: str | None = None) -> SecureFindingsApp:
    return SecureFindingsApp(
        database=database or os.environ.get("DATABASE", str(Path("instance") / "secure_web_lab.sqlite3")),
        secret_key=secret_key or os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        secure_cookie=os.environ.get("COOKIE_SECURE", "0") == "1",
    )
