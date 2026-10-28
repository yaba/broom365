"""Broom365 application factory."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from flask import Flask
from flask_session import Session

from .config import DEMO_PERMISSIONS, Config
from .db import connection_factory, init_db


def _demo_config() -> Config:
    return Config(tenant_id="demo", client_id="demo", client_secret="demo", redirect_uri="http://localhost/demo",
                  secret_key="demo-only", database_path=Path("instance/demo.sqlite"),
                  database_url=os.environ.get("DATABASE_URL", ""))


def create_app(config: Config | None = None) -> Flask:
    """Build and configure the Flask app. Pass a Config in tests; otherwise read the env.

    BROOM_DEMO=1 serves a synthetic tenant with no sign-in (see demo.py).
    """
    demo = os.environ.get("BROOM_DEMO") == "1"
    cfg = config or (_demo_config() if demo else Config.from_env())
    if config is None and not demo:
        from . import bootstrap
        bootstrap.use_saved_key()      # the key the installer saved (BROOM_KEY in the environment still wins)
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SECRET_KEY=cfg.secret_key or "pending",   # replaced below by SECRET_KEY from the environment or the database
        DATABASE_PATH=str(cfg.database_path),
        DATABASE_URL=cfg.database_url,
        BROOM_CONFIG=cfg,
        DEMO=demo,
        # Server-side sessions: the MSAL token cache is far larger than a cookie allows.
        SESSION_TYPE="filesystem",
        SESSION_FILE_DIR=str(cfg.database_path.parent / "sessions"),
        SESSION_PERMANENT=False,
        SESSION_USE_SIGNER=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_HTTPONLY=True,
    )
    init_db(app)
    _prepare_accounts(app, cfg)
    Session(app)
    if demo:
        _seed_demo(connection_factory(app))

    from .accounts import bp as accounts_bp
    from .apps import bp as apps_bp
    from .auth import bp as auth_bp
    from .connect import bp as connect_bp
    from .dashboard import bp as dashboard_bp
    from .export import bp as export_bp
    from .groups import bp as groups_bp
    from .security import register_csrf
    from .settings import bp as settings_bp
    from .templating import register_filters
    from .users import bp as users_bp

    register_filters(app)
    register_csrf(app)
    for bp in (auth_bp, connect_bp, accounts_bp, dashboard_bp, groups_bp, apps_bp, users_bp, settings_bp, export_bp):
        app.register_blueprint(bp)
    return app


def _prepare_accounts(app: Flask, cfg: Config) -> None:
    """Session signing key (environment, else generated once and kept in the database) and the first admin account."""
    from .database import open_connection
    from .services import accounts, appconfig

    conn = open_connection(app.config["DATABASE_URL"], app.config["DATABASE_PATH"])
    try:
        app.config["SECRET_KEY"] = cfg.secret_key or appconfig.session_key(conn)
        if not app.config["DEMO"]:
            accounts.ensure_admin(conn)
    finally:
        conn.close()


def _seed_demo(connect: Callable[[], Any]) -> None:
    """Populate the demo database through the real sync pipeline if it has no data yet."""
    from .demo import DemoExchange, DemoGraph
    from .services.sync import run_inventory, run_scan

    conn = connect()
    try:
        if conn.execute("SELECT COUNT(*) FROM sync_runs").fetchone()[0] == 0:
            run_inventory(conn, DemoGraph(), DEMO_PERMISSIONS, exchange=DemoExchange())  # type: ignore[arg-type]
            # Leave win10-app-deployment* and Sales* unscanned so the scope feature has something to show.
            run_scan(conn, DemoGraph(), DEMO_PERMISSIONS,  # type: ignore[arg-type]
                     "*\n!win10-app-deployment*\n!Sales*", "*", intune_patterns="*", script_patterns="*", guest_patterns="*", dl_patterns="*", mailbox_patterns="*",
                     kinds=("groups", "apps", "intune", "scripts", "guests", "dls", "mailbox_types", "mailboxes"), exchange=DemoExchange())  # type: ignore[arg-type]
    finally:
        conn.close()
