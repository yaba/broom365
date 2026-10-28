"""User detail page (users that hold a directory role)."""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, abort, render_template

from ..auth import login_required
from ..db import get_db
from ..services import repository as repo
from ..services.extended_signals import evaluate_user

bp = Blueprint("users", __name__, url_prefix="/users")


@bp.get("/<oid>")
@login_required
def detail(oid: str) -> str:
    """Roles, last sign-in and flags explained."""
    conn = get_db()
    facts = repo.load_user_facts(conn, oid)
    if not facts:
        abort(404)
    user = conn.execute("SELECT * FROM users WHERE id = ?", (oid,)).fetchone()
    assessment = evaluate_user(facts[0], repo.load_thresholds(conn), datetime.now(timezone.utc))
    return render_template("user.html", u=user, facts=facts[0], a=assessment)
