"""Settings page: connection status, thresholds, high-risk scopes, signal availability, re-sync."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from werkzeug.wrappers import Response

from ..auth import admin_required, exchange_client, granted_scopes, graph_token_provider, refresh_granted_scopes
from ..config import DEFAULT_BROAD_READ_SCOPES, DEFAULT_HIGH_RISK_SCOPES, DEFAULT_THRESHOLDS
from ..db import get_db, reset_database
from ..runtime import credentials, effective_config
from ..services import appconfig
from ..services import repository as repo
from ..services import sync_runner
from ..services.graph import GraphClient
from ..services.permissions import REQUIREMENTS, check_permissions
from ..services.validate import missing_permissions, run_probes
from ..services.sync import recompute_flags

bp = Blueprint("settings", __name__)

THRESHOLD_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("stale_days_group", "Stale group (days)", "STALE: no member/owner change for longer than this."),
    ("stale_days_app", "Stale app (days)", "STALE_APP and LIKELY_ABANDONED_APP: no sign-in for longer than this."),
    ("expiring_days", "Expiring secret (days)", "EXPIRING_SECRET: credential ends within this many days."),
    ("dormant_days_user", "Dormant privileged user (days)", "DORMANT_PRIVILEGED_USER: no sign-in for longer than this."),
    ("danger_no_signin_days", "High-risk permission without use (days)",
     "RISK_WITHOUT_USAGE: high-risk permission and no sign-in for longer than this."),
    ("stale_days_script", "Old Intune script (days)", "STALE_SCRIPT: a script or remediation not modified for longer than this."),
    ("idle_days_script", "Idle remediation (days)", "IDLE_REMEDIATION: an assigned remediation that has not run on any device for longer than this."),
    ("stale_days_guest", "Stale guest (days)", "STALE_GUEST: an external user with no sign-in for longer than this (or invited longer ago and never signed in)."),
    ("pending_days_guest", "Pending invitation (days)", "PENDING_GUEST: an external invitation that was never accepted after this long."),
    ("stale_days_mailbox", "Idle shared mailbox (days)", "MAILBOX_NO_ACTIVITY: no sign-in to a shared, room or equipment mailbox for longer than this (and no mail in the last 89 days)."),
    ("eos_warning_days", "Feature update ending (days)", "UPDATE_FEATURE_ENDING: a feature update profile whose Windows version stops being serviced within this many days."),
    ("stale_days_expedite", "Old expedite profile (days)", "UPDATE_STALE_EXPEDITE: a quality update (expedite) profile not modified for longer than this; it covers a single release."),
    ("stale_days_member", "Stale internal user (days)", "STALE_MEMBER: an enabled internal account with no sign-in for longer than this (or created longer ago and never signed in)."),
)

SIGNAL_INFO: dict[str, str] = {
    "group_audit_activity": "Audit-log member/owner changes. Without it STALE falls back to the group's creation date.",
    "sp_sign_in_activity": "Service principal sign-in report (beta). Without it: no STALE_APP, LIKELY_ABANDONED_APP or RISK_WITHOUT_USAGE.",
    "user_sign_in_activity": "User sign-in activity (beta; needs Entra ID P1/P2). Without it: no DORMANT_PRIVILEGED_USER.",
    "policy_binding": "Conditional Access policies referencing groups. Without it UNKNOWN_USE is less certain.",
    "role_assignments": "Directory role assignments. Without it: no PRIVILEGED_ORPHAN_GROUP or DORMANT_PRIVILEGED_USER.",
    "delegated_permissions": "Tenant-wide delegated permission grants. Without it: delegated permissions are not shown.",
    "app_permissions": "Application permissions per app. Without it: application permissions are not shown.",
    "intune_app_relationships": "Dependency / supersedence links of unassigned Intune apps. Without it UNASSIGNED_APP cannot tell a needed dependency from an unused app.",
    "intune_script_runs": "Run results of Intune scripts and remediations. Without it: no FAILING_SCRIPT or IDLE_REMEDIATION.",
    "intune_shell_scripts": "Intune macOS shell scripts assigned to groups. Without it a group used only there looks unused.",
    "intune_remediations": "Intune remediations assigned to groups. Without it a group used only there looks unused.",
    "guest_memberships": "Groups and Teams each guest belongs to (checked on demand). Without it a guest finding cannot say what access is still open.",
    "members": "Internal (member) users with their licences. Without it the Internal users tab is empty.",
    "member_sign_in_activity": "Internal-user sign-in activity (beta; needs Entra ID P1/P2). Without it: no STALE_MEMBER; disabled-but-licensed accounts are still found.",
    "license_skus": "Licence names (subscribedSkus). Without it licences show as ids and the free-licence list cannot apply.",
    "exchange_distribution_lists": "Exchange distribution lists (needs Exchange.ManageAsApp and an Entra role). Without it the Distribution lists tab is empty.",
    "exchange_transport_rules": "Exchange transport rules, to see which lists a rule mentions. Without it a list used by a rule could look unused.",
    "exchange_members": "Member counts of distribution lists, read on demand.",
    "exchange_traffic": "Message trace (mail addressed to a list, last 89 days), read on demand.",
    "exchange_mailboxes": "Shared, room and equipment mailboxes, read on demand. Without them disabled accounts cannot be told apart from shared mailboxes.",
    "exchange_mailbox_stats": "Last sign-in and item count of a mailbox (Get-MailboxStatistics), read when you check a mailbox.",
    "exchange_mailbox_permissions": "Full Access and Send As holders of a mailbox, read when you check a mailbox.",
    "exchange_accepted_domains": "The tenant's own mail domains, to recognise which addresses in a mail flow rule are internal.",
    "intune_feature_updates": "Intune feature update profiles (beta). Without it the Updates tab misses them and a group used only there looks unused.",
    "intune_quality_updates": "Intune quality update (expedite) profiles (beta). Without it the Updates tab misses them and a group used only there looks unused.",
    "intune_driver_updates": "Intune driver update profiles (beta). Without it the Updates tab misses them and a group used only there looks unused.",
    "guests": "External (guest) users. Without it the Guests tab is empty.",
    "guest_sign_in_activity": "Guest sign-in activity (beta; needs Entra ID P1/P2). Without it: no STALE_GUEST; pending invitations are still found.",
    "deleted_items": "Soft-deleted service principals, used to date 'app was deleted'. Without it the date is omitted.",
    "group_owners": "Group owners. Without it NO_OWNER is not evaluated.",
    "group_members": "Group member counts. Without it EMPTY_GROUP and UNKNOWN_USE are not evaluated.",
    "group_app_assignments": "Group-to-app assignments. Without it ORPHANED_APP_ASSIGNMENT is not evaluated.",
}

_SCOPE_RE = re.compile(r"^[A-Za-z0-9._]+$")


def parse_form(form: Any) -> tuple[dict[str, Any], list[str]]:
    """Validate the settings form. Returns (values, errors); values only holds valid entries."""
    values: dict[str, Any] = {}
    errors: list[str] = []
    for key, label, _ in THRESHOLD_FIELDS:
        raw = str(form.get(key, "")).strip()
        if raw.isdigit() and 1 <= int(raw) <= 3650:
            values[key] = int(raw)
        else:
            errors.append(f"{label}: enter a whole number of days between 1 and 3650.")
    for field, label in (("high_risk_scopes", "High-risk permissions"), ("broad_read_scopes", "Broad read permissions")):
        if field not in form and field != "high_risk_scopes":
            continue  # older forms and API clients may omit the second list: leave it unchanged
        scopes: list[str] = []
        for line in str(form.get(field, "")).splitlines():
            line = line.strip()
            if not line:
                continue
            if not _SCOPE_RE.match(line):
                errors.append(f"{label}: '{line}' is not a valid permission name.")
            elif line.lower() not in {x.lower() for x in scopes}:
                scopes.append(line)
        values[field] = scopes
    return values, errors


def _save(values: dict[str, Any]) -> None:
    import json
    conn = get_db()
    for key, value in values.items():
        conn.execute("INSERT INTO settings (name, value) VALUES (?, ?) "
                     "ON CONFLICT(name) DO UPDATE SET value = excluded.value", (key, json.dumps(value)))
    conn.commit()


def _page(form_values: dict[str, Any] | None = None, errors: list[str] | None = None,
          validation: dict[str, Any] | None = None) -> str:
    conn = get_db()
    cfg = effective_config()
    demo = current_app.config["DEMO"]
    granted = granted_scopes()
    app_only = cfg.auth_mode == "app"
    report = check_permissions(granted, app_only=app_only)
    requirements = tuple(r for r in REQUIREMENTS if not (app_only and r.scope == "User.Read")
                         and not (not app_only and r.scope == "Exchange.ManageAsApp"))
    t = repo.load_thresholds(conn)
    current = {k: getattr(t, k) for k, _, _ in THRESHOLD_FIELDS}
    known = {r["signal"]: r for r in conn.execute("SELECT * FROM signal_availability")}
    signals = [{"name": n, "info": i, "row": known.get(n)} for n, i in SIGNAL_INFO.items()]
    signals.sort(key=lambda s: (s["row"] is None or bool(s["row"]["available"]), s["name"]))
    return render_template(
        "settings.html", cfg=cfg, demo=demo, creds=credentials(), encrypted=appconfig.encryption_enabled(), user=session.get("user", {}), report=report, requirements=requirements, mode=cfg.auth_mode,
        granted={s.lower() for s in granted}, fields=THRESHOLD_FIELDS, values=form_values or current,
        scopes_text="\n".join((form_values or {}).get("high_risk_scopes", t.high_risk_scopes)),
        broad_text="\n".join((form_values or {}).get("broad_read_scopes", t.broad_read_scopes)),
        default_broad=DEFAULT_BROAD_READ_SCOPES,
        errors=errors or [], signals=signals, inventory=repo.last_run(conn, "inventory"), scan=repo.last_run(conn, "scan"),
        counts=repo.scan_counts(conn), syncing=sync_runner.is_running(), defaults=DEFAULT_THRESHOLDS, validation=validation,
        default_scopes=DEFAULT_HIGH_RISK_SCOPES)


@bp.get("/settings")
@admin_required
def show() -> str:
    return _page()


@bp.post("/settings")
@admin_required
def save() -> Response | tuple[str, int]:
    """Validate, store, then recompute flags from stored data (no Graph calls)."""
    values, errors = parse_form(request.form)
    if errors:
        return _page({**values, **{k: request.form.get(k, "") for k, _, _ in THRESHOLD_FIELDS if k not in values}},
                     errors), 400
    _save(values)
    conn = get_db()
    if repo.last_run(conn, "inventory"):
        n = recompute_flags(conn, repo.load_thresholds(conn), datetime.now(timezone.utc))
        flash(f"Settings saved. Flags recomputed from stored data: {n} object(s) flagged.")
    else:
        flash("Settings saved.")
    return redirect(url_for("settings.show"))


@bp.post("/settings/validate")
@admin_required
def validate() -> Response | str:
    """Re-read the granted permissions and probe every data source once, naming exactly what is missing."""
    if current_app.config["DEMO"]:
        flash("Validation needs a real tenant connection; demo mode has none.")
        return redirect(url_for("settings.show"))
    granted, token_error = refresh_granted_scopes()
    perm_type = "Application" if current_app.config["BROOM_CONFIG"].auth_mode == "app" else "Delegated"
    results = [] if token_error else run_probes(GraphClient(graph_token_provider()), granted, perm_type, exchange=exchange_client())
    return _page(validation={"results": results, "granted": sorted(granted), "token_error": token_error,
                             "missing": missing_permissions(results), "at": datetime.now(timezone.utc),
                             "perm_type": perm_type})


RESET_WORD = "DELETE"


@bp.post("/settings/reset")
@admin_required
def reset() -> Response:
    """Delete the local database (all synced data, flags and saved settings). The tenant is not touched."""
    if sync_runner.is_running():
        flash("A sync is running. Wait for it to finish, then try again.")
    elif request.form.get("confirm", "").strip() != RESET_WORD:
        flash(f"Nothing was deleted: type {RESET_WORD} to confirm.")
    else:
        reset_database(get_db())
        flash("Database deleted. Run Refresh inventory to start again.")
    return redirect(url_for("settings.show"))


_GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_DOMAIN = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


@bp.post("/settings/connection")
@admin_required
def save_connection() -> Response:
    """Save the Entra app connection (tenant ID, client ID, client secret). A blank secret keeps the stored one."""
    tenant = request.form.get("tenant_id", "").strip()
    client = request.form.get("client_id", "").strip()
    secret = request.form.get("client_secret", "").strip()
    problems = []
    if not (_GUID.match(tenant) or _DOMAIN.match(tenant)):
        problems.append("Tenant ID must be a GUID or a domain such as contoso.onmicrosoft.com.")
    if not _GUID.match(client):
        problems.append("Client ID must be a GUID (Application (client) ID of the app registration).")
    if not secret and not credentials().client_secret:
        problems.append("Enter the client secret (its Value, not its ID).")
    if problems:
        for m in problems:
            flash(m)
        return redirect(url_for("settings.show"))  # type: ignore[return-value]
    appconfig.save_credentials(get_db(), tenant, client, secret or None)
    flash("Connection saved. Press Validate permissions to test it.")
    return redirect(url_for("settings.show"))  # type: ignore[return-value]
