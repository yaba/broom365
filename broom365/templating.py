"""Jinja filters shared by all pages."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from flask import Flask, current_app

from . import links
from .services._time import days_between, parse_graph_dt
from .runtime import credentials


def _as_dt(value: Any) -> datetime | None:
    return parse_graph_dt(value) if isinstance(value, str) else value


def fmt_date(value: Any) -> str:
    """'YYYY-MM-DD' for a datetime or ISO string; an em dash when unknown."""
    dt = _as_dt(value)
    return "—" if dt is None else f"{dt:%Y-%m-%d}"


def days_ago(value: Any) -> str:
    """'N days ago' for a datetime or ISO string; empty when unknown."""
    dt = _as_dt(value)
    return "" if dt is None else f"{days_between(dt, datetime.now(timezone.utc))} days ago"


def _tenant() -> str:
    return credentials().tenant_id


def register_filters(app: Flask) -> None:
    g = app.jinja_env.globals
    from .auth import current_account
    g["current_account"] = current_account
    g["group_links"] = lambda gid: links.group_links(gid, _tenant())
    g["app_links"] = lambda oid, app_id: links.app_links(oid, app_id, _tenant())
    g["enterprise_app_links"] = lambda sp_id, app_id: links.enterprise_app_link(sp_id, app_id, _tenant())
    g["user_links"] = lambda uid: links.user_links(uid, _tenant())
    g["intune_app_links"] = lambda aid: links.intune_app_links(aid, _tenant())
    app.jinja_env.filters["fmt_date"] = fmt_date
    app.jinja_env.filters["days_ago"] = days_ago
