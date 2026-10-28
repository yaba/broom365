"""Broom365 accounts (who may open the tool): username + password, two roles. No Flask, plain DB functions.

  admin   everything: Settings, creating accounts, deleting the database.
  reader  sees the findings and can run inventories and checks.

The first start creates `admin` with no password; whoever signs in first must set one before anything else (min length 10).
Passwords are stored as scrypt hashes. Repeated failures lock the account for a few minutes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from werkzeug.security import check_password_hash, generate_password_hash

ROLES = ("admin", "reader")
MIN_PASSWORD = 10
MAX_FAILURES = 5
LOCK_MINUTES = 5
_USERNAME = re.compile(r"^[a-z0-9][a-z0-9._@-]{2,63}$")
# Hash used to spend the same time on an unknown username as on a wrong password.
_DUMMY_HASH = generate_password_hash("not-a-real-password")


@dataclass(frozen=True)
class Account:
    id: int
    username: str
    role: str
    must_change_password: bool
    has_password: bool
    last_login_at: str | None = None
    created_at: str | None = None

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def _iso(now: datetime) -> str:
    return now.astimezone(timezone.utc).isoformat()


def _account(r: Any) -> Account:
    return Account(int(r["id"]), r["username"], r["role"], bool(r["must_change_password"]), bool(r["password_hash"]),
                   r["last_login_at"], r["created_at"])


def ensure_admin(conn: Any, now: datetime | None = None) -> bool:
    """Create the first admin (no password yet) when there are no accounts. Returns True if it was created."""
    if conn.execute("SELECT COUNT(*) FROM app_users").fetchone()[0]:
        return False
    conn.execute("INSERT INTO app_users (username, password_hash, role, must_change_password, created_at) VALUES ('admin', NULL, 'admin', 1, ?)",
                 (_iso(now or datetime.now(timezone.utc)),))
    conn.commit()
    return True


def validate_password(password: str, username: str = "") -> str | None:
    """Why this password is not acceptable, or None."""
    if len(password) < MIN_PASSWORD:
        return f"The password must have at least {MIN_PASSWORD} characters."
    if username and password.lower() == username.lower():
        return "The password must not be the username."
    if password.strip() != password or not password.strip():
        return "The password must not start or end with a space."
    return None


def validate_username(username: str) -> str | None:
    if not _USERNAME.match(username):
        return "Use 3-64 lower-case letters, digits, dots, dashes, underscores or @, starting with a letter or digit."
    return None


def get(conn: Any, account_id: int) -> Account | None:
    r = conn.execute("SELECT * FROM app_users WHERE id = ?", (account_id,)).fetchone()
    return _account(r) if r else None


def list_accounts(conn: Any) -> list[Account]:
    return [_account(r) for r in conn.execute("SELECT * FROM app_users ORDER BY username")]


def authenticate(conn: Any, username: str, password: str, now: datetime | None = None) -> tuple[Account | None, str | None]:
    """Check credentials. Returns (account, None) or (None, reason shown to the user).

    The reason never says whether the username exists. An account with no password yet accepts an empty password (the first admin).
    """
    now = now or datetime.now(timezone.utc)
    username = username.strip().lower()
    r = conn.execute("SELECT * FROM app_users WHERE username = ?", (username,)).fetchone()
    if r is None:
        check_password_hash(_DUMMY_HASH, password)
        return None, "Wrong username or password."
    if r["locked_until"] and r["locked_until"] > _iso(now):
        return None, f"Too many failed attempts. Try again in {LOCK_MINUTES} minutes."
    stored = r["password_hash"]
    ok = (password == "") if not stored else check_password_hash(stored, password)
    if not ok:
        failures = int(r["failed_logins"]) + 1
        locked = _iso(now + timedelta(minutes=LOCK_MINUTES)) if failures >= MAX_FAILURES else None
        conn.execute("UPDATE app_users SET failed_logins = ?, locked_until = ? WHERE id = ?", (0 if locked else failures, locked, r["id"]))
        conn.commit()
        return None, "Wrong username or password."
    conn.execute("UPDATE app_users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE id = ?", (_iso(now), r["id"]))
    conn.commit()
    return _account(conn.execute("SELECT * FROM app_users WHERE id = ?", (r["id"],)).fetchone()), None


def set_password(conn: Any, account_id: int, password: str, must_change: bool = False) -> None:
    conn.execute("UPDATE app_users SET password_hash = ?, must_change_password = ?, failed_logins = 0, locked_until = NULL WHERE id = ?",
                 (generate_password_hash(password), int(must_change), account_id))
    conn.commit()


def create(conn: Any, username: str, password: str, role: str, now: datetime | None = None) -> str | None:
    """Add an account whose temporary password must be changed at first sign-in. Returns an error text or None."""
    username = username.strip().lower()
    if err := validate_username(username) or validate_password(password, username):
        return err
    if role not in ROLES:
        return "Unknown role."
    if conn.execute("SELECT 1 FROM app_users WHERE username = ?", (username,)).fetchone():
        return "That username already exists."
    conn.execute("INSERT INTO app_users (username, password_hash, role, must_change_password, created_at) VALUES (?,?,?,1,?)",
                 (username, generate_password_hash(password), role, _iso(now or datetime.now(timezone.utc))))
    conn.commit()
    return None


def _admins(conn: Any) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM app_users WHERE role = 'admin'").fetchone()[0])


def set_role(conn: Any, account_id: int, role: str) -> str | None:
    acc = get(conn, account_id)
    if acc is None or role not in ROLES:
        return "Unknown account or role."
    if acc.is_admin and role != "admin" and _admins(conn) <= 1:
        return "There must always be at least one admin."
    conn.execute("UPDATE app_users SET role = ? WHERE id = ?", (role, account_id))
    conn.commit()
    return None


def delete(conn: Any, account_id: int) -> str | None:
    acc = get(conn, account_id)
    if acc is None:
        return "Unknown account."
    if acc.is_admin and _admins(conn) <= 1:
        return "There must always be at least one admin."
    conn.execute("DELETE FROM app_users WHERE id = ?", (account_id,))
    conn.commit()
    return None
