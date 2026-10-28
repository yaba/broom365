"""Dashboard blueprint: summary cards, one tab per object type (groups, apps, users), sync endpoints."""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from flask import Blueprint, current_app, jsonify, render_template, request
from werkzeug.wrappers import Response

from ..auth import exchange_client, granted_scopes, graph_token_provider, login_required
from ..config import DEMO_PERMISSIONS
from ..db import connection_factory, get_db
from ..runtime import credentials
from ..models.types import RiskLevel
from ..services import repository as repo
from ..services import sync_runner
from ..services.extended_signals import evaluate_user
from ..services._time import days_between, parse_graph_dt
from ..services.graph import GraphClient
from ..services.sync import run_analysis, run_counts, run_scan
from ..services.updates import KIND_SHORT, summarize, targets_text

bp = Blueprint("dashboard", __name__)

TABS: tuple[tuple[str, str], ...] = (("groups", "Groups"), ("apps", "Apps"), ("users", "Users"), ("intune", "Intune apps"),
                                      ("scripts", "Scripts"), ("updates", "Updates"), ("guests", "Guests"),
                                      ("members", "Internal users"),
                                      ("dls", "Distribution lists"),
                                      ("mailboxes", "Shared mailboxes"),
                                      ("rules", "Mail flow rules"))
_TYPE = repo.TAB_TYPES

# What analysing each tab reads (shown before the first analysis, so nobody starts something they did not mean to).
_READS: dict[str, str] = {
    "groups": "the groups, who uses each one (Conditional Access policies and Intune assignments) and the directory roles, then the owners, members "
              "and audit activity of the groups you select below (privileged groups are always included)",
    "apps": "the app registrations with their secrets and age, each app's sign-in activity and the delegated permissions. Owners and application "
            "permissions are read per app afterwards, with Check apps",
    "users": "who holds a directory role, and their last sign-in",
    "intune": "the Intune apps and who each one is assigned to",
    "scripts": "the PowerShell scripts, macOS shell scripts and remediations, and who each one is assigned to",
    "updates": "the Windows update rings and update profiles of Intune, and who each one is assigned to",
    "guests": "the external (guest) users and their last sign-in",
    "members": "the internal users with their licences and last sign-in",
    "dls": "the Exchange distribution lists, and the mail flow rules that come with them",
    "rules": "the Exchange mail flow rules, and the distribution lists that come with them",
    "mailboxes": "the list of shared, room and equipment mailboxes from Exchange (about 40 seconds on a large tenant)",
}

CARDS: tuple[tuple[str, str, str | None], ...] = (
    # (label, key, flag code counted; None = scanned-groups card)
    ("Groups scanned", "groups", None),
    ("Orphaned app assignments", "orphaned", "ORPHANED_APP_ASSIGNMENT"),
    ("Apps with expired secrets", "expired", "EXPIRED_SECRET"),
    ("Dangerous-permission apps", "dangerous", "DANGEROUS_PERMISSION"),
    ("Privileged orphan groups", "priv_orphans", "PRIVILEGED_ORPHAN_GROUP"),
    ("Dormant privileged users", "dormant", "DORMANT_PRIVILEGED_USER"),
    ("Uninstall-only Intune apps", "uninstall_only", "UNINSTALL_ONLY_APP"),
    ("Unassigned Intune apps", "unassigned_apps", "UNASSIGNED_APP"),
    ("Likely obsolete scripts", "obsolete_scripts", "LIKELY_OBSOLETE_SCRIPT"),
    ("Stale guests", "stale_guests", "STALE_GUEST"),
    ("Pending invitations", "pending_guests", "PENDING_GUEST"),
    ("Stale internal users", "stale_members", "STALE_MEMBER"),
    ("Disabled with licences", "disabled_licensed", "DISABLED_LICENSED_MEMBER"),
    ("Leftover disabled accounts", "disabled_members", "DISABLED_MEMBER"),
    ("Likely unused lists", "unused_dls", "LIKELY_UNUSED_DL"),
    ("Likely unused mailboxes", "unused_mailboxes", "LIKELY_UNUSED_MAILBOX"),
    ("Mailboxes nobody can open", "closed_mailboxes", "MAILBOX_NO_DELEGATES"),
    ("Rules with dead references", "dead_rules", "RULE_DEAD_REFERENCE"),
)


# Which of the CARDS belong to which tab (they become that tab's summary strip).
_TAB_CARDS: dict[str, tuple[str, ...]] = {
    "groups": ("groups", "orphaned", "priv_orphans"),
    "users": ("dormant",),
    "intune": ("uninstall_only", "unassigned_apps"),
    "scripts": ("obsolete_scripts",),
    "guests": ("stale_guests", "pending_guests"),
    "members": ("stale_members", "disabled_licensed", "disabled_members"),
    "dls": ("unused_dls",),
    "mailboxes": ("unused_mailboxes", "closed_mailboxes"),
    "rules": ("dead_rules",),
}


def _flags_by_object(conn: sqlite3.Connection) -> dict[tuple[str, str], list[sqlite3.Row]]:
    flags: dict[tuple[str, str], list[sqlite3.Row]] = defaultdict(list)
    for r in conn.execute("SELECT * FROM flags ORDER BY id"):
        flags[(r["object_type"], r["object_id"])].append(r)
    return flags


def _sorted(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=lambda r: (-RiskLevel(r["risk"]).rank, (r["name"] or "").lower()))


def _flagged_rows(conn: sqlite3.Connection, flags: dict[tuple[str, str], list[sqlite3.Row]], otype: str) -> list[dict[str, Any]]:
    """Groups and apps: the flagged objects of one type (unflagged objects are not listed)."""
    return _sorted([{"id": o["object_id"], "name": o["display_name"], "risk": o["risk_level"],
                     "flags": flags[(otype, o["object_id"])], "extra": None}
                    for o in conn.execute("SELECT * FROM flagged_objects WHERE object_type = ?", (otype,))])


def _tiles(tab: str, data: dict[str, Any], counts: dict[str, int], app_stats: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The summary strip of a tab: big numbers that double as filters. `value` None means 'not checked yet', never zero."""
    if tab == "updates" and app_stats:
        s = app_stats
        kinds = " · ".join(f"{s['kinds'][k]} {name}" for k, name in (("ring", "rings"), ("feature", "feature"), ("quality", "expedite"), ("driver", "driver"))
                         if s["kinds"].get(k))
        return [
            {"label": "Update policies", "value": s["total"], "hint": kinds or "none read yet", "tag": "", "tone": ""},
            {"label": "With findings", "value": s["flagged"], "hint": "candidates for review", "tag": "flagged", "tone": "bad" if s["flagged"] else ""},
            {"label": "Assigned to nobody", "value": s["unassigned"], "hint": "change nothing today", "tag": "unassigned", "tone": "bad" if s["unassigned"] else ""},
            {"label": "Overlapping", "value": s["overlap"], "hint": "same devices, same kind of policy", "tag": "overlap", "tone": "bad" if s["overlap"] else ""},
            {"label": "Rings without deadline", "value": s["nodeadline"], "hint": "quality or feature", "tag": "nodeadline", "tone": "bad" if s["nodeadline"] else ""},
            {"label": "Version out of support", "value": s["ending"], "hint": "ended or ending soon", "tag": "ending", "tone": "bad" if s["ending"] else ""},
        ]
    if tab == "apps" and app_stats:
        s = app_stats

        def checked(n: int, label: str) -> dict[str, Any]:
            if not s["checked"]:
                return {"value": None, "hint": "check apps to find out", "label": label}
            return {"value": n, "hint": f"of {s['checked']} checked", "label": label}

        return [
            {"label": "App registrations", "value": s["total"], "hint": f"{s['checked']} checked in depth", "tag": "", "tone": ""},
            {"label": "Expired secrets", "value": s["expired"], "hint": "apps with an expired secret or certificate", "tag": "expired",
             "tone": "bad" if s["expired"] else ""},
            {**checked(s["no_owner"], "Apps with no owner"), "tag": "noowner", "tone": "bad" if s["no_owner"] else ""},
            {"label": "Older than a year", "value": s["old"], "hint": "created over 365 days ago", "tag": "old", "tone": ""},
            {"label": "Younger than a month", "value": s["young"], "hint": "created in the last 30 days", "tag": "young", "tone": ""},
            {**checked(s["risky"], "High-risk Graph permissions"), "tag": "risky", "tone": "bad" if s["risky"] else ""},
        ]
    labels = {key: label for label, key, _ in CARDS}
    codes = {key: code for _, key, code in CARDS}
    out = []
    for key in _TAB_CARDS.get(tab, ()):
        if key == "groups":
            out.append({"label": "Groups checked", "value": counts["groups_scanned"], "hint": f"of {counts['groups_total']} inventoried", "tag": "", "tone": ""})
            continue
        n = data["counts"].get(key, 0)
        out.append({"label": labels[key], "value": n, "hint": "", "flag": codes[key], "tone": "bad" if n else ""})
    return out


def _app_rows(conn: sqlite3.Connection, flags: dict[tuple[str, str], list[sqlite3.Row]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Every app registration (flagged or not) with the facts that matter, plus the numbers for the summary strip.

    Secrets and age come with the inventory; owners and permissions only exist for apps that were checked in depth,
    so for the others they are reported as 'not checked', never as zero.
    """
    now = datetime.now(timezone.utc)
    t = repo.load_thresholds(conn)
    risky_scopes = {s.lower() for s in t.high_risk_scopes}
    ends: dict[str, list[datetime | None]] = defaultdict(list)
    for r in conn.execute("SELECT application_id, end_at FROM app_credentials"):
        ends[r["application_id"]].append(parse_graph_dt(r["end_at"]))
    sp_by_app = {r["app_id"]: r["id"] for r in conn.execute("SELECT id, app_id FROM service_principals")}
    scopes: dict[str, set[str]] = defaultdict(set)
    for r in conn.execute("SELECT sp_id, scope FROM permission_grants"):
        scopes[r["sp_id"]].add(r["scope"])
    risk = {o["object_id"]: o["risk_level"] for o in conn.execute("SELECT * FROM flagged_objects WHERE object_type = 'app'")}
    rows = []
    stats = {"total": 0, "checked": 0, "expired": 0, "no_owner": 0, "old": 0, "young": 0, "risky": 0}
    for a in conn.execute("SELECT * FROM applications"):
        created = parse_graph_dt(a["created_at"])
        age = days_between(created, now) if created else None
        cred = ends.get(a["id"], [])
        expired = sum(1 for e in cred if e is not None and e < now)
        expiring = sum(1 for e in cred if e is not None and now <= e <= now + timedelta(days=t.expiring_days))
        checked = a["scanned_at"] is not None
        owners = a["owner_count"] if checked else None
        high = sorted(s for s in scopes.get(sp_by_app.get(a["app_id"], ""), ()) if s.lower() in risky_scopes) if checked else None
        tags = [tag for tag, on in (("expired", expired > 0), ("noowner", owners == 0), ("old", age is not None and age > 365),
                                    ("young", age is not None and age <= 30), ("risky", bool(high)), ("unchecked", not checked)) if on]
        stats["total"] += 1
        stats["checked"] += checked
        stats["expired"] += expired > 0
        stats["no_owner"] += owners == 0
        stats["old"] += "old" in tags
        stats["young"] += "young" in tags
        stats["risky"] += bool(high)
        rows.append({"id": a["id"], "name": a["display_name"] or a["app_id"], "risk": risk.get(a["id"], "NONE"),
                     "flags": flags[("app", a["id"])], "tags": " ".join(tags),
                     "extra": {"created": created, "age": age, "secrets": len(cred), "expired": expired, "expiring": expiring,
                               "owners": owners, "checked": checked, "high": high}})
    rows.sort(key=lambda r: (-(RiskLevel(r["risk"]).rank if r["risk"] != "NONE" else -1), (r["name"] or "").lower()))
    return rows, stats


_UPDATE_TAGS = {"UPDATE_UNASSIGNED": "unassigned", "UPDATE_OVERLAP": "overlap", "UPDATE_NO_DEADLINE": "nodeadline",
                "UPDATE_FEATURE_ENDING": "ending", "UPDATE_PAUSED": "paused", "UPDATE_EMPTY_TARGETS": "empty"}


def _update_rows(conn: sqlite3.Connection, flags: dict[tuple[str, str], list[sqlite3.Row]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Every update ring and update profile (flagged or not) with its settings and targets, plus the numbers for the summary strip."""
    risk = {o["object_id"]: o["risk_level"] for o in conn.execute("SELECT * FROM flagged_objects WHERE object_type = 'update'")}
    rows = []
    stats: dict[str, Any] = {"total": 0, "flagged": 0, "unassigned": 0, "overlap": 0, "nodeadline": 0, "ending": 0, "kinds": defaultdict(int)}
    for p in repo.load_update_policy_facts(conn):
        found = flags[("update", p.id)]
        tags = [p.kind] + (["flagged"] if found else []) + sorted({_UPDATE_TAGS[f["flag"]] for f in found if f["flag"] in _UPDATE_TAGS})
        stats["total"] += 1
        stats["kinds"][p.kind] += 1
        stats["flagged"] += bool(found)
        for tag in ("unassigned", "overlap", "nodeadline", "ending"):
            stats[tag] += tag in tags
        rows.append({"id": p.id, "name": p.display_name, "risk": risk.get(p.id, "NONE"), "flags": found, "tags": " ".join(tags),
                     "extra": {"kind": KIND_SHORT[p.kind], "summary": summarize(p), "targets": targets_text(p), "modified": p.modified_at or p.created_at}})
    rows.sort(key=lambda r: (-(RiskLevel(r["risk"]).rank if r["risk"] != "NONE" else -1), (r["name"] or "").lower()))
    return rows, stats


def _user_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Users: every role-holding user is shown (flagged or not), because each privileged account deserves a look."""
    t, now = repo.load_thresholds(conn), datetime.now(timezone.utc)
    rows = []
    for u in repo.load_user_facts(conn):
        a = evaluate_user(u, t, now)
        rows.append({"id": u.id, "name": u.display_name, "risk": a.risk.value,
                     "flags": [{"flag": f.code.value, "explanation": f.explanation} for f in a.flags],
                     "extra": {"roles": ", ".join(u.role_names), "upn": u.user_principal_name, "enabled": u.account_enabled,
                               "external": u.user_type == "Guest",
                               "last": u.last_sign_in_at, "available": u.sign_in_available,
                               "notes": a.unavailable_signals}})
    return _sorted(rows)


def _dashboard_data(conn: sqlite3.Connection) -> dict[str, Any]:
    flags = _flags_by_object(conn)
    counts = {key: len({k for k, v in flags.items() if any(f["flag"] == code for f in v)})
              for _, key, code in CARDS if code}
    flagged_per_type = {name: conn.execute("SELECT COUNT(*) FROM flagged_objects WHERE object_type = ?", (_TYPE[name],)).fetchone()[0]
                        for name, _ in TABS}
    unavailable = [dict(r) for r in conn.execute(
        "SELECT signal, reason FROM signal_availability WHERE available = 0 ORDER BY signal")]
    return {"flags": flags, "counts": counts, "unavailable": unavailable, "tab_counts": flagged_per_type}


@bp.get("/")
@login_required
def index() -> str:
    conn = get_db()
    tab = request.args.get("tab", "groups")
    tab = tab if tab in _TYPE else "groups"
    inventory = repo.last_run(conn, "inventory")
    analysed = repo.analysed_map(conn)
    data = _dashboard_data(conn) if (inventory or analysed) else None
    tab_state = {"analysed_at": analysed.get(tab), "total": repo.tab_total(conn, tab, tab in analysed), "reads": _READS[tab],
                 "label": dict(TABS)[tab]}
    rows: list[dict[str, Any]] = []
    domains: list[tuple[str, int]] = []
    app_stats: dict[str, Any] | None = None
    if data and tab in analysed:
        if tab == "apps":
            rows, app_stats = _app_rows(conn, data["flags"])
        elif tab == "updates":
            rows, app_stats = _update_rows(conn, data["flags"])
        else:
            rows = _user_rows(conn) if tab == "users" else _flagged_rows(conn, data["flags"], _TYPE[tab])
    if tab == "scripts":
        kinds = {r[0]: r[1] for r in conn.execute("SELECT id, kind FROM intune_scripts")}
        labels = {"powershell": "PowerShell script", "shell": "macOS shell script", "remediation": "Remediation"}
        for r in rows:
            r["extra"] = {"kind": labels.get(kinds.get(r["id"], ""), "")}
    if tab == "guests":
        from ..services.guests import guest_domain
        known = {g["id"]: g for g in conn.execute("SELECT * FROM guests")}
        for r in rows:
            g = known.get(r["id"])
            r["extra"] = {"mail": (g["mail"] if g else None), "state": (g["external_state"] if g else None), "invited": (g["created_at"] if g else None),
                          "enabled": (None if g is None or g["account_enabled"] is None else bool(g["account_enabled"])),
                          "domain": guest_domain(g["mail"], g["user_principal_name"]) if g else None}
        from collections import Counter
        domains = Counter(r["extra"]["domain"] or "(unknown)" for r in rows).most_common(14)
    if tab == "members":
        known = {m["id"]: m for m in conn.execute("SELECT * FROM members")}
        for r in rows:
            m = known.get(r["id"])
            r["extra"] = {"mail": (m["mail"] or m["user_principal_name"]) if m else None, "synced": bool(m["on_prem_synced"]) if m else False,
                          "enabled": (None if m is None or m["account_enabled"] is None else bool(m["account_enabled"])),
                          "licences": [x for x in json.loads(m["licences"] or "[]")] if m else []}
    if tab == "mailboxes":
        known = {m["id"]: m for m in conn.execute("SELECT * FROM mailboxes")}
        for r in rows:
            m = known.get(r["id"])
            r["extra"] = {"address": m["address"] if m else None, "type": m["mailbox_type"] if m else None}
    if tab == "rules":
        known = {m["name"]: m for m in conn.execute("SELECT * FROM transport_rules")}
        for r in rows:
            m = known.get(r["id"])
            r["extra"] = {"state": m["state"] if m else None, "mode": m["mode"] if m else None, "priority": m["priority"] if m else None}
    if tab == "dls":
        known = {d["id"]: d for d in conn.execute("SELECT * FROM distribution_lists")}
        for r in rows:
            d = known.get(r["id"])
            r["extra"] = {"address": d["address"] if d else None, "kind": d["kind"] if d else None,
                          "synced": bool(d["synced"]) if d else False, "hidden": bool(d["hidden"]) if d else False}
    mailboxes = {"count": conn.execute("SELECT COUNT(*) FROM mailboxes").fetchone()[0],
                 "read_at": conn.execute("SELECT MAX(inventoried_at) FROM mailboxes").fetchone()[0],
                 "available": repo.signal_map(conn).get("exchange_mailboxes", False)}
    flag_codes = sorted({f["flag"] for r in rows for f in r["flags"]})
    return render_template(
        "dashboard.html", cards=CARDS, tabs=TABS, tab=tab, inventory=inventory, scan=repo.last_run(conn, "scan"),
        latest=repo.last_run(conn, usable_only=False), counts=repo.scan_counts(conn),
        patterns=repo.get_scope_patterns(conn), data=data, rows=rows,
        tiles=_tiles(tab, data, repo.scan_counts(conn), app_stats) if data and tab in analysed else [], flag_codes=flag_codes, domains=domains,
        mailboxes=mailboxes, analysed=analysed, tab_state=tab_state,
        syncing=sync_runner.is_running())


def _clients() -> tuple[Callable[[], Any], Callable[[], Any], list[str]]:
    """(Graph factory, Exchange factory, granted permissions) for the current mode. Must be called inside a request."""
    if current_app.config["DEMO"]:
        from ..demo import DemoExchange, DemoGraph
        return DemoGraph, DemoExchange, list(DEMO_PERMISSIONS)
    provider = graph_token_provider()
    tenant = credentials().tenant_id
    ex = exchange_client()
    return (lambda: GraphClient(provider)), (lambda: ex), granted_scopes()


@bp.post("/sync/inventory")
@login_required
def sync_inventory() -> Response:
    """The inventory: count the objects (a few cheap calls), in the background. Nothing is read in detail or evaluated."""
    make_graph, _make_exchange, scopes = _clients()
    started = sync_runner.start_job(connection_factory(), lambda conn: run_counts(conn, make_graph(), scopes))
    return jsonify(started=started)  # type: ignore[return-value]


@bp.post("/sync/analyse/<tab>")
@login_required
def sync_analyse(tab: str) -> Response:
    """Analyse one tab in the background: read what it needs and evaluate only that kind of object."""
    if tab not in _TYPE:
        return jsonify(error="unknown tab"), 404  # type: ignore[return-value]
    make_graph, make_exchange, scopes = _clients()
    started = sync_runner.start_job(connection_factory(), lambda conn: run_analysis(conn, make_graph(), scopes, tab, exchange=make_exchange()))
    return jsonify(started=started)  # type: ignore[return-value]


_PATTERN_ARG = {"groups": "group_patterns", "apps": "app_patterns", "intune": "intune_patterns", "scripts": "script_patterns",
                "guests": "guest_patterns", "dls": "dl_patterns", "mailboxes": "mailbox_patterns", "mailbox_types": ""}


@bp.post("/sync/scan/<kind>")
@login_required
def sync_scan(kind: str) -> Response:
    """Save this type's patterns and check only the matching objects (groups, apps, Intune apps, scripts, guests, lists).

    `mailboxes` takes no patterns: it reads the shared, room and equipment mailboxes.
    """
    if kind not in _PATTERN_ARG:
        return jsonify(error="unknown kind"), 404  # type: ignore[return-value]
    patterns = str((request.get_json(silent=True) or {}).get("patterns", ""))
    if kind == "groups":    # the groups tab has no separate "analyse": scanning reads the list and the usage first, then the selected groups
        repo.save_scope_patterns(get_db(), "groups", patterns)
        make_graph, make_exchange, scopes = _clients()
        started = sync_runner.start_job(connection_factory(), lambda conn: run_analysis(conn, make_graph(), scopes, "groups", group_patterns=patterns))
        return jsonify(started=started)  # type: ignore[return-value]
    if kind != "mailbox_types":
        repo.save_scope_patterns(get_db(), kind, patterns)  # type: ignore[arg-type]
    make_graph, make_exchange, scopes = _clients()
    args = {"group_patterns": "", "app_patterns": "", "intune_patterns": "", "script_patterns": "", "guest_patterns": "", "dl_patterns": "", "mailbox_patterns": ""}
    if _PATTERN_ARG[kind]:
        args[_PATTERN_ARG[kind]] = patterns
    started = sync_runner.start_job(
        connection_factory(),
        lambda conn: run_scan(conn, make_graph(), scopes, args["group_patterns"], args["app_patterns"], kinds=(kind,),
                              intune_patterns=args["intune_patterns"], script_patterns=args["script_patterns"],
                              guest_patterns=args["guest_patterns"], dl_patterns=args["dl_patterns"],
                              mailbox_patterns=args["mailbox_patterns"], exchange=make_exchange()))
    return jsonify(started=started)  # type: ignore[return-value]


@bp.get("/scope/preview")
@login_required
def scope_preview() -> Response:
    """Instant, local preview of how many inventoried objects a pattern set selects."""
    kind = request.args.get("kind", "groups")
    if kind not in _PATTERN_ARG or kind == "mailbox_types":
        return jsonify(error="unknown kind"), 400  # type: ignore[return-value]
    return jsonify(repo.preview_scope(get_db(), kind, request.args.get("patterns", "")))  # type: ignore[arg-type,return-value]


@bp.get("/sync/status")
@login_required
def sync_status() -> Response:
    """Latest run state, polled by the dashboard while a job runs."""
    row = get_db().execute(
        "SELECT kind, status, progress, finished_at, error FROM sync_runs ORDER BY id DESC LIMIT 1").fetchone()
    return jsonify(running=sync_runner.is_running(), **(dict(row) if row else {}))  # type: ignore[return-value]
