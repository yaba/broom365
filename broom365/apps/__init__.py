"""App (registration) detail page."""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, abort, render_template

from ..auth import login_required
from ..db import get_db
from ..services import repository as repo
from ..services.extended_signals import credential_status, evaluate_app

bp = Blueprint("apps", __name__, url_prefix="/apps")


@bp.get("/<oid>")
@login_required
def detail(oid: str) -> str:
    """Owners, credentials with status, permissions (high-risk highlighted), last sign-in and flags."""
    conn = get_db()
    app = conn.execute("SELECT * FROM applications WHERE id = ?", (oid,)).fetchone()
    if app is None:
        abort(404)
    now = datetime.now(timezone.utc)
    t = repo.load_thresholds(conn)
    facts = repo.load_app_facts(conn, oid)
    assessment = evaluate_app(facts[0], t, now) if facts else None
    sp = conn.execute("SELECT * FROM service_principals WHERE app_id = ?", (app["app_id"],)).fetchone()
    owners = conn.execute("SELECT * FROM app_owners WHERE application_id = ? ORDER BY display_name COLLATE NOCASE",
                          (oid,)).fetchall()
    risky = {s.lower() for s in t.high_risk_scopes}
    broad = {s.lower() for s in t.broad_read_scopes} - risky
    credentials = [
        {"c": c, "status": credential_status(c, now, t.expiring_days)}
        for c in sorted(facts[0].credentials if facts else _inventory_credentials(conn, oid),
                        key=lambda c: c.end_at or now)]
    permissions = [{"p": p, "risky": p.scope.lower() in risky, "broad": p.scope.lower() in broad}
                   for p in sorted(facts[0].permissions if facts else [], key=lambda p: (p.kind, p.scope))]
    assigned_groups = conn.execute(
        "SELECT DISTINCT g.id, g.display_name FROM group_app_assignments a JOIN groups g ON g.id = a.group_id "
        "JOIN service_principals sp ON sp.id = a.resource_sp_id WHERE sp.app_id = ? ORDER BY g.display_name COLLATE NOCASE",
        (app["app_id"],)).fetchall()
    return render_template("app.html", app=app, facts=facts[0] if facts else None, a=assessment, sp=sp, owners=owners,
                           credentials=credentials, permissions=permissions, assigned_groups=assigned_groups)


def _inventory_credentials(conn, oid: str):  # type: ignore[no-untyped-def]
    """Credentials of an unscanned app (they arrive with the inventory, so they can still be shown)."""
    from ..models.types import Credential
    from ..services._time import parse_graph_dt
    return [Credential(r["key_id"], r["kind"], r["display_name"], parse_graph_dt(r["end_at"]))
            for r in conn.execute("SELECT * FROM app_credentials WHERE application_id = ?", (oid,))]
