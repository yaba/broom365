"""CSV exports: one file with every flagged object (`/export`), and one file per tab (`/export/<tab>`).

The per-tab files carry the columns that make sense for that kind of object (company domain for guests, member count
for groups, run results for scripts...) plus the risk, flags and plain-language explanations. They contain every row of the
tab, not just what the on-page filters currently show. Every cell is made safe against spreadsheet formula injection,
because names come from the tenant and are not trusted.
"""
from __future__ import annotations

import csv
import io
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable

from flask import Blueprint, Response, abort, current_app

from .. import links
from ..auth import login_required
from ..db import get_db
from ..services import repository as repo
from ..services.guests import guest_domain
from ..services.usage import describe
from ..runtime import credentials

bp = Blueprint("export", __name__)

COLUMNS = ("object_type", "object_id", "display_name", "risk_level", "flag_count", "flags", "explanations",
           "inventory_at", "last_scan_at", "exported_at")
_RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
Rows = tuple[tuple[str, ...], list[list[Any]]]


def safe_cell(value: object) -> str:
    """Neutralise spreadsheet formula injection: names come from the tenant and are not trusted."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _csv_response(columns: tuple[str, ...], rows: list[list[Any]], name: str) -> Response:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([safe_cell(v) for v in row])
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return Response("﻿" + out.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=broom365-{name}-{day}.csv"})


# ----------------------------------------------------------------- everything ---
@bp.get("/export")
@login_required
def export_csv() -> Response:
    """Download all flagged objects of every type (one row per object, highest risk first)."""
    conn = get_db()
    flags: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    for r in conn.execute("SELECT object_type, object_id, flag, explanation FROM flags ORDER BY id"):
        flags[(r["object_type"], r["object_id"])].append((r["flag"], r["explanation"]))
    inventory, scan = repo.last_run(conn, "inventory"), repo.last_run(conn, "scan")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = sorted(conn.execute("SELECT * FROM flagged_objects"),
                  key=lambda o: (_RISK_ORDER[o["risk_level"]], o["object_type"], (o["display_name"] or "").lower()))
    data = []
    for o in rows:
        found = flags[(o["object_type"], o["object_id"])]
        data.append([o["object_type"], o["object_id"], o["display_name"], o["risk_level"], len(found),
                     "; ".join(f for f, _ in found), " | ".join(e for _, e in found),
                     inventory["finished_at"] if inventory else "", scan["finished_at"] if scan else "", now])
    return _csv_response(COLUMNS, data, "flagged")


# --------------------------------------------------------------------- per tab ---
def _verdicts(conn: Any, otype: str) -> dict[str, tuple[str, int, str, str]]:
    """object id -> (risk, number of flags, flags, explanations) for one object type."""
    found: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for r in conn.execute("SELECT object_id, flag, explanation FROM flags WHERE object_type = ? ORDER BY id", (otype,)):
        found[r["object_id"]].append((r["flag"], r["explanation"]))
    return {o["object_id"]: (o["risk_level"], len(found[o["object_id"]]), "; ".join(f for f, _ in found[o["object_id"]]),
                             " | ".join(e for _, e in found[o["object_id"]]))
            for o in conn.execute("SELECT * FROM flagged_objects WHERE object_type = ?", (otype,))}


def _sorted(rows: list[list[Any]], risk_col: int, name_col: int) -> list[list[Any]]:
    return sorted(rows, key=lambda r: (_RISK_ORDER.get(r[risk_col], 3), str(r[name_col] or "").lower()))


def _first(items: list[tuple[str, str]]) -> str:
    return items[0][1] if items else ""


def _groups(conn: Any, tenant: str) -> Rows:
    verdicts = _verdicts(conn, "group")
    refs: dict[str, list[str]] = defaultdict(list)
    for u in conn.execute("SELECT * FROM group_usages ORDER BY object_name COLLATE NOCASE"):
        refs[u["group_id"]].append(f"{u['kind']} {describe(u['source'], repr(u['object_name'] or u['object_id']), u['mode'], u['detail'])}")
    for p in conn.execute("SELECT * FROM group_parents ORDER BY parent_name COLLATE NOCASE"):
        refs[p["group_id"]].append(f"member of group '{p['parent_name'] or p['parent_id']}'")
    rows = []
    for g in conn.execute("SELECT * FROM groups"):
        if g["id"] not in verdicts:
            continue
        kind = ", ".join(x for x in ("Microsoft 365" if "Unified" in (g["group_types"] or "").split(",") else "",
                                      "dynamic" if g["membership_rule"] else "assigned",
                                      "security" if g["security_enabled"] else "", "mail-enabled" if g["mail_enabled"] else "") if x)
        risk, n, flags, expl = verdicts[g["id"]]
        owners = conn.execute("SELECT COUNT(*) FROM group_owners WHERE group_id = ?", (g["id"],)).fetchone()[0]
        rows.append([g["id"], g["display_name"], risk, n, flags, expl, g["member_count"],
                     g["owner_count"] if g["owner_count"] is not None else owners, kind, "yes" if g["has_license_assignment"] else "no",
                     g["created_at"], g["last_membership_change_at"], g["scanned_at"], " ; ".join(refs.get(g["id"], [])),
                     _first(links.group_links(g["id"], tenant))])
    cols = ("group_id", "display_name", "risk_level", "flag_count", "flags", "explanations", "members", "owners", "group_type",
            "has_license", "created_at", "last_membership_change_at", "checked_at", "referenced_by", "intune_link")
    return cols, _sorted(rows, 2, 1)


def _apps(conn: Any, tenant: str) -> Rows:
    verdicts = _verdicts(conn, "app")
    now = datetime.now(timezone.utc).isoformat()[:19]
    rows = []
    for a in conn.execute("SELECT * FROM applications"):
        if a["id"] not in verdicts:
            continue
        last = conn.execute("SELECT s.last_sign_in_at FROM sign_in_activity s JOIN service_principals p ON p.id = s.object_id "
                            "WHERE p.app_id = ? AND s.object_type = 'servicePrincipal'", (a["app_id"],)).fetchone()
        secrets = conn.execute("SELECT COUNT(*), SUM(CASE WHEN substr(end_at, 1, 19) < ? THEN 1 ELSE 0 END) FROM app_credentials WHERE application_id = ?",
                               (now, a["id"])).fetchone()
        perms = conn.execute("SELECT COUNT(*) FROM permission_grants g JOIN service_principals p ON p.id = g.sp_id WHERE p.app_id = ?",
                             (a["app_id"],)).fetchone()[0]
        risk, n, flags, expl = verdicts[a["id"]]
        rows.append([a["id"], a["app_id"], a["display_name"], risk, n, flags, expl, a["created_at"], a["owner_count"],
                     last[0] if last else None, secrets[0], secrets[1] or 0, perms, a["scanned_at"],
                     _first(links.app_links(a["id"], a["app_id"], tenant))])
    cols = ("app_object_id", "client_id", "display_name", "risk_level", "flag_count", "flags", "explanations", "created_at",
            "owners", "last_sign_in_at", "secrets", "secrets_expired", "permissions", "checked_at", "entra_link")
    return cols, _sorted(rows, 3, 2)


def _users(conn: Any, tenant: str) -> Rows:
    """Every user that holds a directory role (the tab lists them all, flagged or not)."""
    verdicts = _verdicts(conn, "user")
    rows = []
    for u in conn.execute("SELECT * FROM users"):
        roles = ", ".join(sorted({r[0] or "Unnamed role" for r in conn.execute(
            "SELECT role_name FROM role_assignments WHERE principal_id = ? AND principal_type = 'user'", (u["id"],))}))
        last = conn.execute("SELECT last_sign_in_at FROM sign_in_activity WHERE object_id = ? AND object_type = 'user'", (u["id"],)).fetchone()
        risk, n, flags, expl = verdicts.get(u["id"], ("LOW", 0, "", ""))
        rows.append([u["id"], u["display_name"], u["user_principal_name"], "External" if u["user_type"] == "Guest" else "Internal",
                     {1: "yes", 0: "no"}.get(u["account_enabled"], "unknown"), roles, risk, n, flags, expl,
                     last[0] if last else None, _first(links.user_links(u["id"], tenant))])
    cols = ("user_id", "display_name", "user_principal_name", "account_type", "account_enabled", "roles", "risk_level", "flag_count",
            "flags", "explanations", "last_sign_in_at", "entra_link")
    return cols, _sorted(rows, 6, 1)


def _targets(conn: Any, table: str, owner: str, oid: str, with_intent: bool) -> str:
    out = []
    for a in conn.execute(f"SELECT a.*, g.display_name AS gname FROM {table} a LEFT JOIN groups g ON g.id = a.group_id AND a.target = 'group' "
                          f"WHERE a.{owner} = ? ORDER BY a.mode, g.display_name COLLATE NOCASE", (oid,)):
        who = {"all_users": "all licensed users", "all_devices": "all devices"}.get(a["target"]) or f"group '{a['gname'] or a['group_id'][:8]}'"
        intent = f", {a['intent']}" if with_intent and a["mode"] == "include" and a["intent"] else ""
        out.append(f"excluded: {who}" if a["mode"] == "exclude" else f"{who}{' (' + intent[2:] + ')' if intent else ''}")
    return " ; ".join(out)


def _intune_apps(conn: Any, tenant: str) -> Rows:
    verdicts = _verdicts(conn, "intune_app")
    rows = []
    for a in conn.execute("SELECT * FROM intune_apps"):
        if a["id"] not in verdicts:
            continue
        risk, n, flags, expl = verdicts[a["id"]]
        rows.append([a["id"], a["display_name"], a["app_type"], a["publisher"], risk, n, flags, expl, a["created_at"], a["modified_at"],
                     "yes" if a["scanned_at"] else "no", _targets(conn, "intune_app_assignments", "app_id", a["id"], True),
                     _first(links.intune_app_links(a["id"], tenant))])
    cols = ("app_id", "display_name", "app_type", "publisher", "risk_level", "flag_count", "flags", "explanations", "created_at",
            "modified_at", "relations_checked", "assignments", "intune_link")
    return cols, _sorted(rows, 4, 1)


def _scripts(conn: Any, tenant: str) -> Rows:
    import json
    verdicts = _verdicts(conn, "intune_script")
    labels = {"powershell": "PowerShell script", "shell": "macOS shell script", "remediation": "Remediation"}
    rows = []
    for s in conn.execute("SELECT * FROM intune_scripts"):
        if s["id"] not in verdicts:
            continue
        run = json.loads(s["run_json"]) if s["run_json"] else {}
        ok = (run.get("successDeviceCount") or 0) + (run.get("successUserCount") or 0) if run else None
        bad = (run.get("errorDeviceCount") or 0) + (run.get("errorUserCount") or 0) if run else None
        risk, n, flags, expl = verdicts[s["id"]]
        rows.append([s["id"], s["display_name"], labels.get(s["kind"], s["kind"]), risk, n, flags, expl, s["created_at"], s["modified_at"],
                     "yes" if s["scanned_at"] else "no", ok, bad, run.get("lastScriptRunDateTime") if run else None,
                     _targets(conn, "intune_script_assignments", "script_id", s["id"], False)])
    cols = ("script_id", "display_name", "kind", "risk_level", "flag_count", "flags", "explanations", "created_at", "modified_at",
            "run_results_checked", "runs_succeeded", "runs_failed", "last_run", "assignments")
    return cols, _sorted(rows, 3, 1)


def _guests(conn: Any, tenant: str) -> Rows:
    verdicts = _verdicts(conn, "guest")
    member: dict[str, list[str]] = defaultdict(list)
    assigned: dict[str, int] = defaultdict(int)
    for m in conn.execute("SELECT m.*, g.id AS known, g.membership_rule AS member_rule FROM guest_memberships m LEFT JOIN groups g ON g.id = m.group_id "
                          "ORDER BY CASE WHEN g.membership_rule IS NOT NULL THEN 1 ELSE 0 END, CASE WHEN m.kind <> 'team' THEN 1 ELSE 0 END, m.group_name COLLATE NOCASE"):
        dynamic = m["known"] is not None and m["member_rule"] is not None
        assigned[m["guest_id"]] += 0 if dynamic else 1
        member[m["guest_id"]].append((m["group_name"] or m["group_id"]) + (" (Team)" if m["kind"] == "team" else "") + (" (dynamic)" if dynamic else ""))
    rows = []
    for g in conn.execute("SELECT * FROM guests"):
        if g["id"] not in verdicts:
            continue
        risk, n, flags, expl = verdicts[g["id"]]
        checked = g["scanned_at"] is not None
        rows.append([g["id"], g["display_name"], g["mail"], guest_domain(g["mail"], g["user_principal_name"]), g["user_principal_name"],
                     {1: "yes", 0: "no"}.get(g["account_enabled"], "unknown"), g["external_state"], g["created_at"], g["last_sign_in_at"],
                     risk, n, flags, expl, "yes" if checked else "no", len(member[g["id"]]) if checked else None,
                     assigned[g["id"]] if checked else None, " ; ".join(member[g["id"]]) if checked else None,
                     _first(links.user_links(g["id"], tenant))])
    cols = ("guest_id", "display_name", "mail", "company_domain", "user_principal_name", "account_enabled", "invitation_state",
            "created_at", "last_sign_in_at", "risk_level", "flag_count", "flags", "explanations", "memberships_checked",
            "member_of_count", "member_of_assigned", "member_of", "entra_link")
    return cols, _sorted(rows, 9, 1)


def _members(conn: Any, tenant: str) -> Rows:
    import json
    verdicts = _verdicts(conn, "member")
    rows = []
    for m in conn.execute("SELECT * FROM members"):
        if m["id"] not in verdicts:
            continue
        risk, n, flags, expl = verdicts[m["id"]]
        rows.append([m["id"], m["display_name"], m["user_principal_name"], m["mail"], {1: "yes", 0: "no"}.get(m["account_enabled"], "unknown"),
                     "yes" if m["on_prem_synced"] else "no", ", ".join(json.loads(m["licences"] or "[]")), m["created_at"], m["last_sign_in_at"],
                     risk, n, flags, expl, _first(links.user_links(m["id"], tenant))])
    cols = ("user_id", "display_name", "user_principal_name", "mail", "account_enabled", "synced_from_ad", "licences", "created_at",
            "last_sign_in_at", "risk_level", "flag_count", "flags", "explanations", "entra_link")
    return cols, _sorted(rows, 9, 1)


def _dls(conn: Any, tenant: str) -> Rows:
    import json
    verdicts = _verdicts(conn, "dl")
    refs: dict[str, list[str]] = defaultdict(list)
    for r in conn.execute("SELECT * FROM dl_rule_refs ORDER BY rule_name"):
        if r["rule_name"] not in refs[r["dl_id"]]:
            refs[r["dl_id"]].append(r["rule_name"])
    rows = []
    for d in conn.execute("SELECT * FROM distribution_lists"):
        if d["id"] not in verdicts:
            continue
        owners = json.loads(d["owners"] or "[]")
        risk, n, flags, expl = verdicts[d["id"]]
        checked = d["scanned_at"] is not None
        rows.append([d["id"], d["display_name"], d["address"], d["kind"], len(owners), "; ".join(owners), "yes" if d["synced"] else "no",
                     "yes" if d["hidden"] else "no", d["created_at"], d["changed_at"], "yes" if checked else "no",
                     d["member_count"] if checked else None, d["last_mail_at"] if checked and d["traffic_known"] else None,
                     "; ".join(refs.get(d["id"], [])), risk, n, flags, expl, _first(links.group_links(d["id"], tenant))])
    cols = ("list_id", "display_name", "address", "kind", "owner_count", "owners", "synced_from_ad", "hidden", "created_at", "changed_at",
            "checked", "members", "last_mail_seen", "transport_rules", "risk_level", "flag_count", "flags", "explanations", "entra_link")
    return cols, _sorted(rows, 14, 1)


def _mailboxes(conn: Any, tenant: str) -> Rows:
    import json
    verdicts = _verdicts(conn, "mailbox")
    people: dict[str, list[str]] = defaultdict(list)
    for r in conn.execute("SELECT * FROM mailbox_delegates ORDER BY trustee"):
        people[(r["mailbox_id"], r["kind"])].append(r["trustee"])
    rows = []
    for m in conn.execute("SELECT * FROM mailboxes"):
        if m["id"] not in verdicts:
            continue
        risk, n, flags, expl = verdicts[m["id"]]
        checked = m["scanned_at"] is not None
        rows.append([m["id"], m["display_name"], m["address"], m["mailbox_type"], m["created_at"], "yes" if checked else "no",
                     m["last_logon_at"] if checked and m["logon_known"] else None, m["item_count"] if checked else None,
                     m["last_mail_at"] if checked and m["traffic_known"] else None,
                     "; ".join(people.get((m["id"], "full_access"), [])) if checked and m["delegates_known"] else None,
                     "; ".join(people.get((m["id"], "send_as"), [])) if checked and m["delegates_known"] else None,
                     "; ".join(json.loads(m["send_on_behalf"] or "[]")), risk, n, flags, expl, _first(links.user_links(m["id"], tenant))])
    cols = ("mailbox_id", "display_name", "address", "type", "created_at", "checked", "last_sign_in", "items", "last_mail_seen", "full_access",
            "send_as", "send_on_behalf", "risk_level", "flag_count", "flags", "explanations", "entra_link")
    return cols, _sorted(rows, 12, 1)


def _rules(conn: Any, tenant: str) -> Rows:
    import json
    verdicts = _verdicts(conn, "rule")
    rows = []
    for r in conn.execute("SELECT * FROM transport_rules"):
        if r["name"] not in verdicts:
            continue
        risk, n, flags, expl = verdicts[r["name"]]
        rows.append([r["name"], r["state"], r["mode"], r["priority"], r["changed_at"], r["expiry_at"], "; ".join(json.loads(r["addresses"] or "[]")),
                     risk, n, flags, expl])
    cols = ("rule", "state", "mode", "priority", "changed_at", "expiry_at", "addresses", "risk_level", "flag_count", "flags", "explanations")
    return cols, _sorted(rows, 7, 0)


def _updates(conn: Any, tenant: str) -> Rows:
    from ..services import repository as repo
    from ..services.updates import KIND_SHORT, summarize, targets_text
    verdicts = _verdicts(conn, "update")
    rows = []
    for p in repo.load_update_policy_facts(conn):
        if p.id not in verdicts:
            continue
        risk, n, flags, expl = verdicts[p.id]
        rows.append([p.id, p.display_name, KIND_SHORT[p.kind], summarize(p), targets_text(p), "; ".join(p.overlaps), p.created_at, p.modified_at,
                     risk, n, flags, expl])
    cols = ("policy_id", "display_name", "kind", "settings", "assigned_to", "overlaps_with", "created_at", "modified_at", "risk_level",
            "flag_count", "flags", "explanations")
    return cols, _sorted(rows, 8, 1)


BUILDERS: dict[str, Callable[[Any, str], Rows]] = {
    "groups": _groups, "apps": _apps, "users": _users, "intune": _intune_apps, "scripts": _scripts, "updates": _updates, "guests": _guests,
    "members": _members, "dls": _dls, "mailboxes": _mailboxes, "rules": _rules}


@bp.get("/export/<tab>")
@login_required
def export_tab(tab: str) -> Response:
    """Download one tab as CSV: groups, apps, users, intune, scripts or guests (all of its rows, not the on-page filter)."""
    builder = BUILDERS.get(tab)
    if builder is None:
        abort(404)
    columns, rows = builder(get_db(), credentials().tenant_id)
    return _csv_response(columns, rows, tab)
