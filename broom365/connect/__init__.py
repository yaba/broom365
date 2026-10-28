"""Connect Broom365 to a Microsoft 365 tenant: enter the Entra app details, check the permissions, warn about what is missing.

The step after the installer (and the page an admin lands on until the connection exists). The same values stay editable in Settings.
"""
from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from werkzeug.wrappers import Response

from ..auth import _admin_consent_url, _tokens, admin_required
from ..db import get_db
from ..runtime import credentials
from ..services import appconfig

bp = Blueprint("connect", __name__)


def _page(problems: list[str] | None = None, form: dict[str, str] | None = None) -> str:
    creds = credentials()
    check = None
    if creds.complete and not problems:
        state = _tokens().state(force=True)      # a fresh token, so permissions granted a minute ago show up
        report = state.report
        check = {"error": state.error, "report": report, "consent": _admin_consent_url(report.missing_scopes, app_only=True)}
    return render_template("connect.html", creds=creds, problems=problems or [], check=check,
                           form=form or {"tenant_id": creds.tenant_id, "client_id": creds.client_id},
                           secret_unreadable=creds.secret_unreadable)


@bp.get("/connect")
@admin_required
def show() -> str:
    return _page()


@bp.post("/connect")
@admin_required
def save() -> Response | tuple[str, int] | str:
    """Store the connection and check it straight away."""
    tenant, client = request.form.get("tenant_id", "").strip(), request.form.get("client_id", "").strip()
    secret = request.form.get("client_secret", "").strip()
    problems = appconfig.validate_connection(tenant, client, secret, bool(credentials().client_secret))
    if problems:
        return _page(problems, {"tenant_id": tenant, "client_id": client}), 400
    appconfig.save_credentials(get_db(), tenant, client, secret or None)
    g.pop("creds", None)                          # the connection just changed: read it again
    flash("Connection saved.")
    return _page()
