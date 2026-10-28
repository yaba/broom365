"""Group detail page."""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, abort, render_template

from ..auth import login_required
from ..db import get_db
from ..services import repository as repo
from ..services.correlate import evaluate_group
from ..services.usage import NOT_CHECKED

bp = Blueprint("groups", __name__, url_prefix="/groups")


@bp.get("/<oid>")
@login_required
def detail(oid: str) -> str:
    """Metadata, owners, app assignments (with target state) and every flag explained."""
    conn = get_db()
    group = conn.execute("SELECT * FROM groups WHERE id = ?", (oid,)).fetchone()
    if group is None:
        abort(404)
    facts = repo.load_group_facts(conn, oid)
    assessment = evaluate_group(facts[0], repo.load_thresholds(conn), datetime.now(timezone.utc)) if facts else None
    owners = conn.execute("SELECT * FROM group_owners WHERE group_id = ? ORDER BY display_name COLLATE NOCASE", (oid,)).fetchall()
    assignments = conn.execute(
        "SELECT a.*, sp.id AS sp_id, sp.account_enabled AS sp_enabled, d.deleted_at AS deleted_at, app.id AS app_object_id "
        "FROM group_app_assignments a LEFT JOIN service_principals sp ON sp.id = a.resource_sp_id "
        "LEFT JOIN deleted_service_principals d ON d.id = a.resource_sp_id "
        "LEFT JOIN applications app ON app.app_id = sp.app_id WHERE a.group_id = ?", (oid,)).fetchall()
    roles = [r[0] for r in conn.execute(
        "SELECT DISTINCT role_name FROM role_assignments WHERE principal_id = ? AND principal_type = 'group'", (oid,))]
    return render_template("group.html", g=group, facts=facts[0] if facts else None, a=assessment,
                           owners=owners, assignments=assignments, roles=roles,
                           coverage=repo.usage_coverage(conn, oid), not_checked=NOT_CHECKED,
                           is_m365="Unified" in (group["group_types"] or "").split(","))
