"""The installer: what Broom365 serves until it knows where its data lives (first start), or when the saved database settings stop working.

It asks for the database (SQL Server, or the local SQLite file) and the encryption key, tests the connection, saves `bootstrap.json`,
starts the real application in the same process and asks for the first admin password. Everything after that (the Microsoft 365
connection and its permissions) is done inside the application, see `broom365/connect`.

Until the installation is finished the page is open to whoever can reach the server, like any installer: do it right after starting.
"""
from __future__ import annotations

import hmac
import secrets
from pathlib import Path
from typing import Any, Callable

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from werkzeug.wrappers import Response

from .. import bootstrap
from ..database import open_connection
from ..services import accounts

_FIELDS = ("storage", "server", "port", "database", "user", "encryption", "extra", "key")


def create_setup_app(on_done: Callable[[], None], error: str | None = None, repair: bool = False) -> Flask:
    """The installer as a small Flask app. `on_done` starts the real application once the settings are saved (it may raise).

    `repair` means settings exist but do not work: the page says why, keeps the saved key and does not ask for an admin password.
    """
    app = Flask("broom365")                      # templates and static files of the package
    app.secret_key = secrets.token_hex(32)       # only for this page's CSRF token; the real app has its own

    saved_key = bootstrap.load().get("key", "")

    @app.route("/", methods=["GET", "POST"])
    def index() -> Response | str | tuple[str, int]:
        values: dict[str, str] = {"storage": "mssql", "port": "1433", "encryption": "trust"}
        problems: list[str] = [error] if error else []
        if request.method == "POST":
            _check_csrf()
            values = {k: request.form.get(k, "").strip() for k in _FIELDS}
            problems = _install(values, request.form.get("admin_password", ""), request.form.get("admin_password2", ""))
            if not problems:
                return redirect("/")
        values.setdefault("key", "")
        if not values.get("key"):
            values["key"] = saved_key if repair and saved_key else bootstrap.new_key()
        session["csrf"] = session.get("csrf") or secrets.token_urlsafe(32)
        return render_template("install.html", values=values, problems=problems, repair=repair, csrf=session["csrf"],
                               where=str(bootstrap.path()), modes=bootstrap.ENCRYPTION_MODES, sqlite_file=str(bootstrap.data_path()),
                               min_key=bootstrap.MIN_KEY), (400 if problems and request.method == "POST" else 200)

    @app.post("/test")
    def test_connection() -> Response:
        """Try the database settings of the form without saving anything; the answer is shown next to the button."""
        _check_csrf()
        v = {k: request.form.get(k, "").strip() for k in _FIELDS}
        if problems := _database_problems(v):
            return jsonify(ok=False, message=" ".join(problems))
        try:
            detail = _test(_database_url(v))
        except Exception as exc:  # noqa: BLE001 - shown to the person installing
            return jsonify(ok=False, message=bootstrap.explain_db_error(exc))
        return jsonify(ok=True, message="The connection works" + (f": {detail}." if isinstance(detail, str) and detail else "."))

    @app.route("/<path:_any>")
    def anything_else(_any: str) -> Response:
        return redirect(url_for("index"))

    def _check_csrf() -> None:
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        stored = str(session.get("csrf", ""))
        if not stored or not hmac.compare_digest(sent, stored):
            abort(400, "Missing or invalid CSRF token")

    def _install(v: dict[str, str], password: str, again: str) -> list[str]:
        problems = _database_problems(v)
        if len(v["key"]) < bootstrap.MIN_KEY:
            problems.append(f"The encryption key must have at least {bootstrap.MIN_KEY} characters.")
        if not repair:
            if password != again:
                problems.append("The two admin passwords are different.")
            elif bad := accounts.validate_password(password, "admin"):
                problems.append(bad)
        if problems:
            return problems

        url = _database_url(v)
        try:
            _test(url)
        except Exception as exc:  # noqa: BLE001 - any driver or file-system failure is shown to the person installing
            return [bootstrap.explain_db_error(exc)]
        bootstrap.save(url, v["key"])
        bootstrap.use_key(v["key"])
        try:
            on_done()
            if not repair:
                _first_admin(url, password)
        except Exception as exc:  # noqa: BLE001
            return [f"The settings were saved, but the application could not start: {bootstrap.explain_db_error(exc)}"]
        return []

    def _database_url(v: dict[str, str]) -> str:
        """The database URL for the form ("" = the SQLite file). The password is read from the request, never kept."""
        if v["storage"] == "sqlite":
            return ""
        return bootstrap.build_database_url(v["server"], v["port"], v["database"], v["user"], request.form.get("db_password", ""),
                                            v["encryption"], v["extra"])

    return app


def _database_problems(v: dict[str, str]) -> list[str]:
    """What is missing or wrong in the database part of the form."""
    problems: list[str] = []
    if v["storage"] != "sqlite":
        if not v["server"]:
            problems.append("Enter the SQL Server name or address.")
        if v["port"] and not (v["port"].isdigit() and 0 < int(v["port"]) < 65536):
            problems.append("The port must be a number between 1 and 65535.")
        if not v["database"]:
            problems.append("Enter the name of the database (it must already exist).")
        if not v["user"] and bootstrap.needs_user(v["extra"]):
            problems.append("Enter the SQL Server user name.")
    return problems


def _test(url: str) -> str:
    """Open the database (SQL Server: connect and query; SQLite: the folder must be writable). Returns a short description."""
    if url:
        conn = open_connection(url, "")
        try:
            row = conn.execute("SELECT DB_NAME(), CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(50))").fetchone()
        finally:
            conn.close()
        return f"database {row[0]} on SQL Server {row[1]}" if row else ""
    folder = bootstrap.data_path().parent
    folder.mkdir(parents=True, exist_ok=True)
    probe = Path(folder) / ".write-test"
    probe.write_text("ok")
    probe.unlink()
    return f"the folder {folder} can be written"


def _first_admin(url: str, password: str) -> None:
    """Give the new installation its admin account with the chosen password (an existing database keeps its own accounts)."""
    conn: Any = open_connection(url, str(bootstrap.data_path()))
    try:
        accounts.ensure_admin(conn)
        row = conn.execute("SELECT id, password_hash FROM app_users WHERE username = 'admin'").fetchone()
        if row is not None and not row["password_hash"]:
            accounts.set_password(conn, int(row["id"]), password, must_change=False)
    finally:
        conn.close()
