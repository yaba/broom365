"""Database helpers: per-request connection, schema init, settings store. SQLite or SQL Server, as chosen in the installer (or by DATABASE_URL)."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Callable

from flask import Flask, current_app, g

from .database import MssqlConnection, is_mssql, open_connection

SCHEMA_PATH = Path(__file__).parent / "models" / "schema.sql"


# Columns added after the first release: (table, column, DDL type). CREATE TABLE IF NOT EXISTS does not add them.
# SQLite only: a SQL Server database is created from the current schema.sql.
_ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("groups", "group_types", "TEXT"),
    ("groups", "parent_count", "INTEGER"),
    ("intune_apps", "scanned_at", "TEXT"),
    ("intune_scripts", "scanned_at", "TEXT"),
    ("guests", "scanned_at", "TEXT"),
)


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring a database created by an older version up to date (idempotent)."""
    for table, column, ddl in _ADDED_COLUMNS:
        if column not in {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
    # The flag cache restricts object types in a CHECK that SQLite cannot alter: rebuild it (the next run recomputes it).
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'flagged_objects'").fetchone()
    if row and "'update'" not in row[0]:
        conn.execute("DROP TABLE IF EXISTS flags")
        conn.execute("DROP TABLE flagged_objects")
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))


# Not touched by reset_database: who may sign in, and the saved Entra connection.
KEEP_TABLES = ("app_users", "app_config")


def reset_database(conn: Any) -> None:
    """Delete every table (data, flags, saved settings and scope patterns) and recreate an empty schema.

    The accounts and the saved Entra connection are kept, otherwise nobody could sign in afterwards.

    Works on the given connection, so no file locking is involved. Nothing in the tenant is touched.
    """
    conn.commit()
    if isinstance(conn, MssqlConnection):
        conn.drop_all(keep=KEEP_TABLES)
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        return
    conn.execute("PRAGMA foreign_keys = OFF")
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").fetchall():
        if name in KEEP_TABLES:
            continue
        conn.execute(f'DROP TABLE IF EXISTS "{name}"')
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    _migrate(conn)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()


def connection_factory(app: Flask | None = None) -> Callable[[], Any]:
    """A function that opens a new connection to this app's database (usable from a background thread)."""
    cfg = (app or current_app).config
    url, path = cfg.get("DATABASE_URL", ""), cfg["DATABASE_PATH"]
    return lambda: open_connection(url, path)


def get_db() -> Any:
    """Return the connection for the current request, opening it on first use."""
    if "db" not in g:
        g.db = connection_factory()()
    return g.db


def _close_db(_exc: BaseException | None = None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db(app: Flask) -> None:
    """Create the database (file or SQL Server tables) and apply schema.sql (idempotent)."""
    url = app.config.get("DATABASE_URL", "")
    if is_mssql(url):
        conn = open_connection(url, "")
        try:
            conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        finally:
            conn.close()
    else:
        path = Path(app.config["DATABASE_PATH"])
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as conn:
            conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
            _migrate(conn)
    app.teardown_appcontext(_close_db)


def get_setting(key: str, default: Any) -> Any:
    """Read a JSON-encoded setting, returning `default` if unset."""
    row = get_db().execute("SELECT value FROM settings WHERE name = ?", (key,)).fetchone()
    return default if row is None else json.loads(row["value"])


def set_setting(key: str, value: Any) -> None:
    """Persist a JSON-encoded setting."""
    db = get_db()
    db.execute(
        "INSERT INTO settings (name, value) VALUES (?, ?) "
        "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
        (key, json.dumps(value)),
    )
    db.commit()
