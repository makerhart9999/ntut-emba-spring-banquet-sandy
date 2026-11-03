#!/usr/bin/env python3
"""Small same-origin web app for the NTUT EMBA spring banquet."""
from __future__ import annotations

import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DATABASE_PATH", str(ROOT / "data" / "spring_banquet.sqlite3")))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
PORT = int(os.environ.get("PORT", "8000"))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
SESSION_TTL = 12 * 60 * 60
SESSIONS: dict[str, tuple[str, float]] = {}
LOGIN_FAILURES: dict[str, list[float]] = {}

ROLES = {"師長", "貴賓", "在校生"}
COHORTS = {"113", "114", "115", "其他"}
CLASSES = {"經管", "工管", "北資財", "桃資財", "華南", "上海", "泰國", "雙聯", "其他"}
MEALS = {"葷食", "素食"}


def connect_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""CREATE TABLE IF NOT EXISTS attendees (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL,
        cohort TEXT NOT NULL DEFAULT '', class_name TEXT NOT NULL DEFAULT '',
        meal TEXT NOT NULL, created_at TEXT NOT NULL
    )""")
    db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('registration_open','true')")
    db.commit()
    return db


@contextmanager
def database():
    db = connect_db()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def mask_name(value: str) -> str:
    chars = list(value.strip())
    return chars[0] + "O" + "".join(chars[2:]) if len(chars) > 1 else (chars[0] if chars else "")


def valid_entry(data: object) -> dict[str, str]:
    if not isinstance(data, dict):
        raise ValueError("請提供有效的報名資料。")
    name = str(data.get("name", "")).strip()
    role = str(data.get("role", ""))
    meal = str(data.get("meal", ""))
    cohort = str(data.get("cohort", ""))
    class_name = str(data.get("className", ""))
    if not name or len(name) > 30:
        raise ValueError("姓名必須為 1 至 30 個字。")
    if role not in ROLES or meal not in MEALS:
        raise ValueError("身分或餐食選項無效。")
    if role == "在校生":
        if cohort not in COHORTS or class_name not in CLASSES:
            raise ValueError("在校生請選擇有效的屆別與班別。")
    else:
        cohort, class_name = "", ""
    return {"name": name, "role": role, "cohort": cohort, "className": class_name, "meal": meal}


class Handler(SimpleHTTPRequestHandler):
    server_version = "BanquetSite/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        # Avoid logging private query or form data.
        super().log_message(fmt, *args)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        super().end_headers()

    def send_json(self, status: int, payload: object, headers: dict[str, str] | None = None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 100_000:
                raise ValueError
            return json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            raise ValueError("無法讀取資料，請重新確認後送出。")

    def cookies(self):
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except Exception:
            pass
        return jar

    def session(self):
        token = self.cookies().get("banquet_session")
        if not token:
            return None
        entry = SESSIONS.get(token.value)
        if not entry or entry[1] < time.time():
            SESSIONS.pop(token.value, None)
            return None
        return token.value, entry[0]

    def require_admin(self, csrf=False):
        session = self.session()
        if not session:
            self.send_json(401, {"error": "請先登入管理後台。"})
            return False
        if csrf and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), session[1]):
            self.send_json(403, {"error": "安全驗證已失效，請重新整理頁面。"})
            return False
        return True

    def attendee_dict(self, row: sqlite3.Row, public=False):
        name = mask_name(row["name"]) if public else row["name"]
        return {"id": row["id"], "name": name, "role": row["role"], "cohort": row["cohort"],
                "className": row["class_name"], "meal": row["meal"], "createdAt": row["created_at"]}

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/status":
            with database() as db:
                count = db.execute("SELECT COUNT(*) FROM attendees").fetchone()[0]
                opened = db.execute("SELECT value FROM settings WHERE key='registration_open'").fetchone()[0] == "true"
            return self.send_json(200, {"open": opened, "count": count})
        if path == "/api/attendees":
            with database() as db:
                rows = db.execute("SELECT * FROM attendees ORDER BY CASE role WHEN '師長' THEN 0 WHEN '貴賓' THEN 1 ELSE 2 END, cohort, class_name, created_at").fetchall()
            return self.send_json(200, [self.attendee_dict(row, public=True) for row in rows])
        if path == "/api/admin/session":
            session = self.session()
            return self.send_json(200, {"authenticated": True, "csrf": session[1]}) if session else self.send_json(401, {"authenticated": False})
        if path == "/api/admin/attendees":
            if not self.require_admin():
                return
            with database() as db:
                rows = db.execute("SELECT * FROM attendees ORDER BY created_at DESC").fetchall()
            return self.send_json(200, [self.attendee_dict(row) for row in rows])
        allowed = {"/", "/index.html", "/admin.html", "/spring-banquet-poster.jpg", "/hero-background.jpg"}
        if path not in allowed:
            return self.send_json(404, {"error": "找不到此頁面。"})
        if path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/admin/login":
            ip = self.client_address[0]
            now = time.time()
            failures = [t for t in LOGIN_FAILURES.get(ip, []) if now - t < 900]
            LOGIN_FAILURES[ip] = failures
            if len(failures) >= 8:
                return self.send_json(429, {"error": "登入嘗試次數過多，請稍後再試。"})
            try:
                data = self.read_json()
            except ValueError as ex:
                return self.send_json(400, {"error": str(ex)})
            password = str(data.get("password", "")) if isinstance(data, dict) else ""
            if not ADMIN_PASSWORD or not hmac.compare_digest(password, ADMIN_PASSWORD):
                LOGIN_FAILURES[ip].append(now)
                return self.send_json(401, {"error": "管理密碼不正確。"})
            LOGIN_FAILURES.pop(ip, None)
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
            SESSIONS[token] = (csrf, now + SESSION_TTL)
            cookie = f"banquet_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}" + ("; Secure" if COOKIE_SECURE else "")
            return self.send_json(200, {"authenticated": True, "csrf": csrf}, {"Set-Cookie": cookie})
        if path == "/api/admin/logout":
            if not self.require_admin(csrf=True):
                return
            session = self.session()
            if session:
                SESSIONS.pop(session[0], None)
            return self.send_json(200, {"ok": True}, {"Set-Cookie": "banquet_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"})
        if path == "/api/attendees":
            try:
                data = valid_entry(self.read_json())
            except ValueError as ex:
                return self.send_json(400, {"error": str(ex)})
            with database() as db:
                opened = db.execute("SELECT value FROM settings WHERE key='registration_open'").fetchone()[0] == "true"
                if not opened:
                    return self.send_json(403, {"error": "報名作業目前已關閉。"})
                attendee_id = secrets.token_urlsafe(12)
                created = datetime.now(timezone.utc).isoformat(timespec="seconds")
                db.execute("INSERT INTO attendees(id,name,role,cohort,class_name,meal,created_at) VALUES(?,?,?,?,?,?,?)",
                           (attendee_id, data["name"], data["role"], data["cohort"], data["className"], data["meal"], created))
            return self.send_json(201, {"ok": True})
        return self.send_json(404, {"error": "找不到此 API。"})

    def do_PATCH(self):
        path = urlparse(self.path).path
        if path == "/api/admin/settings/registration":
            if not self.require_admin(csrf=True):
                return
            try:
                data = self.read_json()
                opened = bool(data["open"])
            except (ValueError, KeyError, TypeError):
                return self.send_json(400, {"error": "報名狀態資料無效。"})
            with database() as db:
                db.execute("UPDATE settings SET value=? WHERE key='registration_open'", ("true" if opened else "false",))
            return self.send_json(200, {"open": opened})
        prefix = "/api/admin/attendees/"
        if path.startswith(prefix):
            if not self.require_admin(csrf=True):
                return
            attendee_id = path[len(prefix):]
            try:
                data = valid_entry(self.read_json())
            except ValueError as ex:
                return self.send_json(400, {"error": str(ex)})
            with database() as db:
                cur = db.execute("UPDATE attendees SET name=?,role=?,cohort=?,class_name=?,meal=? WHERE id=?",
                                 (data["name"], data["role"], data["cohort"], data["className"], data["meal"], attendee_id))
                if cur.rowcount == 0:
                    return self.send_json(404, {"error": "找不到此報名資料。"})
            return self.send_json(200, {"ok": True})
        return self.send_json(404, {"error": "找不到此 API。"})

    def do_DELETE(self):
        prefix = "/api/admin/attendees/"
        path = urlparse(self.path).path
        if not path.startswith(prefix):
            return self.send_json(404, {"error": "找不到此 API。"})
        if not self.require_admin(csrf=True):
            return
        attendee_id = path[len(prefix):]
        with database() as db:
            cur = db.execute("DELETE FROM attendees WHERE id=?", (attendee_id,))
            if cur.rowcount == 0:
                return self.send_json(404, {"error": "找不到此報名資料。"})
        self.send_json(200, {"ok": True})


def main():
    if len(ADMIN_PASSWORD) < 12:
        raise SystemExit("請設定 ADMIN_PASSWORD（至少 12 個字元）後再啟動網站。")
    connect_db().close()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Banquet site listening on port {PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()

