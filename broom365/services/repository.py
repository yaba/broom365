"""SQLite -> domain-type loaders, scope selection and flag persistence. Plain sqlite3, no Flask/Graph.

Used by sync.py (after inventory/scan) and by the blueprints (to render pages).
Only *scanned* groups/apps are turned into facts: an inventoried-only object has not been
evaluated, so it must never produce flags.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any, Iterable, Literal

from ..config import DEFAULT_BROAD_READ_SCOPES, DEFAULT_HIGH_RISK_SCOPES, DEFAULT_THRESHOLDS
from ..models.types import (
    AppFacts, Assessment, Credential, GroupAppAssignment, GroupFacts, GroupUsage, IntuneAppFacts, IntuneAssignment,
    Delegate, DistributionListFacts, GuestFacts, MailboxFacts, RuleFacts, GuestMembership, IntuneRelationship, IntuneScriptFacts, MemberFacts, Permission, Thresholds, UpdatePolicyFacts, UserFacts,
)
from ._time import parse_graph_dt
from .exchange_mail import classify_trustee
from .guests import guest_domain
from .scope import parse_patterns
from .usage import USAGE_SOURCES, describe

Kind = Literal["groups", "apps", "intune", "scripts", "guests", "dls", "mailboxes"]


def _bool(v: int | None) -> bool | None:
    return None if v is None else bool(v)


# --------------------------------------------------------------- run info ---
def last_run(conn: sqlite3.Connection, kind: str | None = None, usable_only: bool = True) -> sqlite3.Row | None:
    """Newest sync run (optionally of one kind); by default only success/partial ones."""
    sql, args = "SELECT * FROM sync_runs WHERE 1=1", []
    if kind:
        sql, args = sql + " AND kind = ?", [kind]
    if usable_only:
        sql += " AND status IN ('success','partial')"
    return conn.execute(sql + " ORDER BY id DESC LIMIT 1", args).fetchone()  # type: ignore[no-any-return]


def signal_map(conn: sqlite3.Connection) -> dict[str, bool]:
    """signal name -> currently available."""
    return {r[0]: bool(r[1]) for r in conn.execute("SELECT signal, available FROM signal_availability")}


def scan_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Inventoried vs scanned object counts, for the 'scanned N of M' indicators."""
    one = lambda sql: int(conn.execute(sql).fetchone()[0])  # noqa: E731
    return {"groups_total": one("SELECT COUNT(*) FROM groups"),
            "groups_scanned": one("SELECT COUNT(*) FROM groups WHERE scanned_at IS NOT NULL"),
            "apps_total": one("SELECT COUNT(*) FROM applications"),
            "apps_scanned": one("SELECT COUNT(*) FROM applications WHERE scanned_at IS NOT NULL"),
            "intune_total": one("SELECT COUNT(*) FROM intune_apps"),
            "intune_scanned": one("SELECT COUNT(*) FROM intune_apps WHERE scanned_at IS NOT NULL"),
            "scripts_total": one("SELECT COUNT(*) FROM intune_scripts"),
            "scripts_scanned": one("SELECT COUNT(*) FROM intune_scripts WHERE scanned_at IS NOT NULL"),
            "guests_total": one("SELECT COUNT(*) FROM guests"),
            "guests_scanned": one("SELECT COUNT(*) FROM guests WHERE scanned_at IS NOT NULL"),
            "dls_total": one("SELECT COUNT(*) FROM distribution_lists"),
            "dls_scanned": one("SELECT COUNT(*) FROM distribution_lists WHERE scanned_at IS NOT NULL"),
            "mailboxes_total": one("SELECT COUNT(*) FROM mailboxes"),
            "mailboxes_scanned": one("SELECT COUNT(*) FROM mailboxes WHERE scanned_at IS NOT NULL")}


# --------------------------------------------------------------- settings ---
def load_thresholds(conn: sqlite3.Connection) -> Thresholds:
    """Thresholds + high-risk scopes from the settings table, falling back to config defaults."""
    stored = {r[0]: json.loads(r[1]) for r in conn.execute("SELECT name, value FROM settings")}
    values: dict[str, Any] = {k: int(stored.get(k, d)) for k, d in DEFAULT_THRESHOLDS.items()}
    values["high_risk_scopes"] = tuple(stored.get("high_risk_scopes", DEFAULT_HIGH_RISK_SCOPES))
    values["broad_read_scopes"] = tuple(stored.get("broad_read_scopes", DEFAULT_BROAD_READ_SCOPES))
    return Thresholds(**values)


def get_scope_patterns(conn: sqlite3.Connection) -> dict[Kind, str]:
    """Saved scan-scope pattern text for groups and apps."""
    stored = {r[0]: json.loads(r[1]) for r in conn.execute(
        "SELECT name, value FROM settings WHERE name IN ('scope_groups','scope_apps','scope_intune','scope_scripts','scope_guests','scope_dls','scope_mailboxes')")}
    return {k: stored.get(f"scope_{k}", "") for k in ("groups", "apps", "intune", "scripts", "guests", "dls", "mailboxes")}  # type: ignore[misc]


def save_scope_patterns(conn: sqlite3.Connection, kind: Kind, patterns: str) -> None:
    """Remember the pattern text for one object type."""
    conn.execute("INSERT INTO settings (name, value) VALUES (?, ?) "
                 "ON CONFLICT(name) DO UPDATE SET value = excluded.value", (f"scope_{kind}", json.dumps(patterns)))
    conn.commit()


# ------------------------------------------------------------------ scope ---
_TABLE = {"groups": "groups", "apps": "applications", "intune": "intune_apps", "scripts": "intune_scripts", "guests": "guests", "dls": "distribution_lists", "mailboxes": "mailboxes"}


def _candidates(conn: sqlite3.Connection, kind: Kind) -> list[tuple[str, list[str | None], str, str | None]]:
    """(id, names to match against, name to show, scanned_at) for every inventoried object of a kind.

    A guest can be matched by display name, e-mail or company domain; everything else by display name.
    """
    if kind == "guests":
        return [(r["id"], [r["display_name"], r["mail"], guest_domain(r["mail"], r["user_principal_name"])],
                 r["display_name"] or r["mail"] or r["id"], r["scanned_at"]) for r in conn.execute("SELECT * FROM guests")]
    if kind == "dls":
        return [(r["id"], [r["display_name"], r["address"]], r["display_name"] or r["address"] or r["id"], r["scanned_at"])
                for r in conn.execute("SELECT * FROM distribution_lists")]
    if kind == "mailboxes":
        return [(r["id"], [r["display_name"], r["address"]], r["display_name"] or r["address"] or r["id"], r["scanned_at"])
                for r in conn.execute("SELECT * FROM mailboxes")]
    return [(r[0], [r[1]], r[1] or r[0], r[2]) for r in conn.execute(f"SELECT id, display_name, scanned_at FROM {_TABLE[kind]}")]


def select_scope_ids(conn: sqlite3.Connection, kind: Kind, patterns: str) -> list[str]:
    """Ids of inventoried objects whose name matches the patterns.

    Groups that hold a directory role are always included (privileged-orphan detection
    must not depend on the operator remembering to select them).
    """
    matcher = parse_patterns(patterns)
    ids = [oid for oid, names, _, _ in _candidates(conn, kind) if matcher.matches_any(names)]
    if kind == "groups":
        privileged = {r[0] for r in conn.execute(
            "SELECT DISTINCT principal_id FROM role_assignments WHERE principal_type = 'group'")}
        known = {r[0] for r in conn.execute("SELECT id FROM groups")}
        ids = sorted(set(ids) | (privileged & known))
    return ids


def preview_scope(conn: sqlite3.Connection, kind: Kind, patterns: str, sample: int = 8) -> dict[str, Any]:
    """Instant, local preview: how many inventoried objects the patterns select."""
    matcher = parse_patterns(patterns)
    cands = _candidates(conn, kind)
    rows = sorted((c for c in cands if matcher.matches_any(c[1])), key=lambda c: c[2].lower())
    ids = select_scope_ids(conn, kind, patterns)
    return {"total": len(cands), "matched": len(rows), "selected": len(ids),
            "already_scanned": sum(1 for r in rows if r[3]), "sample": [r[2] for r in rows[:sample]]}


# ---------------------------------------------------------------- loaders ---
def load_group_facts(conn: sqlite3.Connection, only_id: str | None = None) -> list[GroupFacts]:
    """GroupFacts for every *scanned* group (or just `only_id`), with app assignments (target state joined live) and roles."""
    assigns: dict[str, list[GroupAppAssignment]] = {}
    for r in conn.execute(
        "SELECT a.*, sp.id AS sp_id, sp.account_enabled AS sp_enabled, d.deleted_at AS deleted_at "
        "FROM group_app_assignments a LEFT JOIN service_principals sp ON sp.id = a.resource_sp_id "
        "LEFT JOIN deleted_service_principals d ON d.id = a.resource_sp_id"
        + (" WHERE a.group_id = ?" if only_id else ""), (only_id,) if only_id else ()
    ):
        exists = r["sp_id"] is not None
        assigns.setdefault(r["group_id"], []).append(GroupAppAssignment(
            r["resource_sp_id"], r["resource_display_name"], exists, _bool(r["sp_enabled"]) if exists else None,
            parse_graph_dt(r["assigned_at"]), parse_graph_dt(r["deleted_at"])))
    roles: dict[str, list[str]] = {}
    for r in conn.execute("SELECT principal_id, role_name FROM role_assignments WHERE principal_type = 'group'"):
        roles.setdefault(r[0], []).append(r[1] or "Unnamed role")
    where, args = (" WHERE group_id = ?", (only_id,)) if only_id else ("", ())
    usages: dict[str, list[GroupUsage]] = {}
    for r in conn.execute("SELECT * FROM group_usages" + where + " ORDER BY object_name COLLATE NOCASE", args):
        usages.setdefault(r["group_id"], []).append(GroupUsage(r["source"], r["kind"], r["object_name"] or r["object_id"],
                                                              r["mode"], r["detail"]))
    parents: dict[str, list[str]] = {}
    for r in conn.execute("SELECT * FROM group_parents" + where + " ORDER BY parent_name COLLATE NOCASE", args):
        parents.setdefault(r["group_id"], []).append(r["parent_name"] or r["parent_id"])
    sigs = signal_map(conn)
    unchecked = tuple(s.signal for s in USAGE_SOURCES if not sigs.get(s.signal, False))
    return [GroupFacts(
        id=r["id"], display_name=r["display_name"] or r["id"], created_at=parse_graph_dt(r["created_at"]),
        member_count=r["member_count"], owner_count=r["owner_count"],
        last_membership_change_at=parse_graph_dt(r["last_membership_change_at"]),
        has_license_assignment=_bool(r["has_license_assignment"]),
        app_assignments=tuple(assigns.get(r["id"], ())), directory_role_names=tuple(sorted(set(roles.get(r["id"], ())))),
        usages=tuple(usages.get(r["id"], ())),
        parent_group_names=None if r["parent_count"] is None else tuple(parents.get(r["id"], ())),
        unchecked_usage_sources=unchecked, is_m365="Unified" in (r["group_types"] or "").split(","),
    ) for r in conn.execute("SELECT * FROM groups WHERE scanned_at IS NOT NULL" + (" AND id = ?" if only_id else ""),
                            (only_id,) if only_id else ())]


def load_app_facts(conn: sqlite3.Connection, only_id: str | None = None) -> list[AppFacts]:
    """AppFacts for every *scanned* app registration (or just `only_id`): credentials, permissions (via its SP), sign-in."""
    sign_in_ok = signal_map(conn).get("sp_sign_in_activity", False)
    creds: dict[str, list[Credential]] = {}
    for r in conn.execute("SELECT * FROM app_credentials"):
        creds.setdefault(r["application_id"], []).append(
            Credential(r["key_id"], r["kind"], r["display_name"], parse_graph_dt(r["end_at"])))
    sp_by_app = {r["app_id"]: r["id"] for r in conn.execute("SELECT id, app_id FROM service_principals")}
    perms: dict[str, list[Permission]] = {}
    for r in conn.execute("SELECT * FROM permission_grants"):
        perms.setdefault(r["sp_id"], []).append(Permission(r["kind"], r["resource_name"], r["scope"]))
    activity = {r["object_id"]: parse_graph_dt(r["last_sign_in_at"]) for r in conn.execute(
        "SELECT object_id, last_sign_in_at FROM sign_in_activity WHERE object_type = 'servicePrincipal'")}
    apps: list[AppFacts] = []
    for r in conn.execute("SELECT * FROM applications WHERE scanned_at IS NOT NULL" + (" AND id = ?" if only_id else ""),
                          (only_id,) if only_id else ()):
        sp_id = sp_by_app.get(r["app_id"])
        apps.append(AppFacts(
            id=r["id"], app_id=r["app_id"], display_name=r["display_name"] or r["app_id"],
            credentials=tuple(creds.get(r["id"], ())), permissions=tuple(perms.get(sp_id, ())) if sp_id else (),
            owner_count=r["owner_count"], sign_in_available=sign_in_ok and sp_id in activity,
            last_sign_in_at=activity.get(sp_id) if sp_id else None))
    return apps


def load_user_facts(conn: sqlite3.Connection, only_id: str | None = None) -> list[UserFacts]:
    """UserFacts for synced (role-holding) users (or just `only_id`). Users are part of the inventory, not the scan."""
    roles: dict[str, list[str]] = {}
    for r in conn.execute("SELECT principal_id, role_name FROM role_assignments WHERE principal_type = 'user'"):
        roles.setdefault(r[0], []).append(r[1] or "Unnamed role")
    activity = {r["object_id"]: parse_graph_dt(r["last_sign_in_at"]) for r in conn.execute(
        "SELECT object_id, last_sign_in_at FROM sign_in_activity WHERE object_type = 'user'")}
    return [UserFacts(
        id=r["id"], display_name=r["display_name"] or r["user_principal_name"] or r["id"],
        user_principal_name=r["user_principal_name"], role_names=tuple(sorted(set(roles.get(r["id"], ())))),
        sign_in_available=r["id"] in activity, last_sign_in_at=activity.get(r["id"]),
        account_enabled=_bool(r["account_enabled"]), user_type=r["user_type"],
    ) for r in conn.execute("SELECT * FROM users" + (" WHERE id = ?" if only_id else ""), (only_id,) if only_id else ())]


def _assignments_by_owner(conn: sqlite3.Connection, table: str, owner_col: str, with_intent: bool) -> dict[str, list[IntuneAssignment]]:
    """Assignments of Intune apps / scripts, with each target group's name and (if scanned) member count."""
    intent = "a.intent" if with_intent else "''"
    out: dict[str, list[IntuneAssignment]] = {}
    for r in conn.execute(
        f"SELECT a.{owner_col} AS owner, a.target, a.mode, {intent} AS intent, a.group_id, "
        "g.display_name AS g_name, g.member_count AS g_members, g.scanned_at AS g_scanned "
        f"FROM {table} a LEFT JOIN groups g ON g.id = a.group_id AND a.target = 'group' ORDER BY g.display_name COLLATE NOCASE"
    ):
        out.setdefault(r["owner"], []).append(IntuneAssignment(
            r["target"], r["mode"], r["intent"], r["group_id"], r["g_name"],
            r["g_members"] if r["g_scanned"] is not None else None))
    return out


def load_intune_app_facts(conn: sqlite3.Connection) -> list[IntuneAppFacts]:
    """IntuneAppFacts for every inventoried Intune app. Relationships are only available for unassigned apps."""
    by_app = _assignments_by_owner(conn, "intune_app_assignments", "app_id", True)
    checked = signal_map(conn).get("intune_app_relationships", False)
    rels: dict[str, list[IntuneRelationship]] = {}
    for r in conn.execute(
        "SELECT r.*, o.id AS o_id, CASE WHEN EXISTS (SELECT 1 FROM intune_app_assignments x WHERE x.app_id = r.other_id AND x.mode = 'include') THEN 1 ELSE 0 END AS o_assigned "
        "FROM intune_app_relationships r LEFT JOIN intune_apps o ON o.id = r.other_id"
    ):
        rels.setdefault(r["app_id"], []).append(IntuneRelationship(
            r["kind"], r["role"], r["other_id"], r["other_name"], bool(r["o_assigned"]) if r["o_id"] else None, r["detail"]))
    return [IntuneAppFacts(
        id=r["id"], display_name=r["display_name"] or r["id"], app_type=r["app_type"], publisher=r["publisher"],
        created_at=parse_graph_dt(r["created_at"]), modified_at=parse_graph_dt(r["modified_at"]),
        assignments=tuple(by_app.get(r["id"], ())), scanned=r["scanned_at"] is not None,
        relationships=tuple(rels.get(r["id"], ())) if checked and r["scanned_at"] is not None else None)
        for r in conn.execute("SELECT * FROM intune_apps")]


def load_intune_script_facts(conn: sqlite3.Connection) -> list[IntuneScriptFacts]:
    """IntuneScriptFacts for every PowerShell script, macOS shell script and Remediation."""
    by_script = _assignments_by_owner(conn, "intune_script_assignments", "script_id", False)
    return [IntuneScriptFacts(
        id=r["id"], display_name=r["display_name"] or r["id"], kind=r["kind"], created_at=parse_graph_dt(r["created_at"]),
        modified_at=parse_graph_dt(r["modified_at"]), assignments=tuple(by_script.get(r["id"], ())),
        scanned=r["scanned_at"] is not None,
        run=json.loads(r["run_json"]) if r["run_json"] and r["scanned_at"] is not None else None)
        for r in conn.execute("SELECT * FROM intune_scripts")]


def load_update_policy_facts(conn: sqlite3.Connection) -> list[UpdatePolicyFacts]:
    """UpdatePolicyFacts for every update ring and update profile, with the other policies of the same kind that reach the same target."""
    by_policy = _assignments_by_owner(conn, "update_policy_assignments", "policy_id", False)
    rows = list(conn.execute("SELECT * FROM update_policies"))
    included = {r["id"]: {(a.target, a.group_id) for a in by_policy.get(r["id"], ()) if a.mode == "include"} for r in rows}
    excluded = {r["id"]: {(a.target, a.group_id) for a in by_policy.get(r["id"], ()) if a.mode == "exclude"} for r in rows}
    out = []
    for r in rows:
        shared = sorted({o["display_name"] or o["id"] for o in rows if o["id"] != r["id"] and o["kind"] == r["kind"]
                         and (included[r["id"]] & included[o["id"]]) - excluded[r["id"]] - excluded[o["id"]]}, key=str.lower)
        out.append(UpdatePolicyFacts(
            id=r["id"], kind=r["kind"], display_name=r["display_name"] or r["id"], created_at=parse_graph_dt(r["created_at"]),
            modified_at=parse_graph_dt(r["modified_at"]), assignments=tuple(by_policy.get(r["id"], ())),
            settings=json.loads(r["settings_json"] or "{}"), overlaps=tuple(shared)))
    return out


def load_guest_facts(conn: sqlite3.Connection) -> list[GuestFacts]:
    """GuestFacts for every inventoried external user; memberships only for guests that were checked."""
    checked = signal_map(conn).get("guest_memberships", False)
    members: dict[str, list[GuestMembership]] = {}
    for m in conn.execute("SELECT m.*, g.id AS known, g.membership_rule AS member_rule FROM guest_memberships m "
                          "LEFT JOIN groups g ON g.id = m.group_id"):
        members.setdefault(m["guest_id"], []).append(GuestMembership(
            m["group_id"], m["group_name"] or m["group_id"], m["kind"], None if m["known"] is None else m["member_rule"] is not None))
    return [GuestFacts(
        id=r["id"], display_name=r["display_name"] or r["user_principal_name"] or r["id"], mail=r["mail"],
        user_principal_name=r["user_principal_name"], account_enabled=_bool(r["account_enabled"]),
        created_at=parse_graph_dt(r["created_at"]), external_state=r["external_state"],
        state_changed_at=parse_graph_dt(r["state_changed_at"]), last_sign_in_at=parse_graph_dt(r["last_sign_in_at"]),
        sign_in_available=bool(r["sign_in_known"]),
        memberships=tuple(members.get(r["id"], ())) if checked and r["scanned_at"] is not None else None)
        for r in conn.execute("SELECT * FROM guests")]


def load_member_facts(conn: sqlite3.Connection) -> list[MemberFacts]:
    """MemberFacts for every inventoried internal user; mailbox types only if the Exchange mailboxes were read."""
    read = signal_map(conn).get("exchange_mailboxes", False)
    boxes = {r[0]: r[1] for r in conn.execute("SELECT id, mailbox_type FROM mailboxes")} if read else {}
    return [MemberFacts(
        id=r["id"], display_name=r["display_name"] or r["user_principal_name"] or r["id"], mail=r["mail"],
        user_principal_name=r["user_principal_name"], account_enabled=_bool(r["account_enabled"]),
        created_at=parse_graph_dt(r["created_at"]), on_prem_synced=bool(r["on_prem_synced"]),
        licences=tuple(json.loads(r["licences"] or "[]")), last_sign_in_at=parse_graph_dt(r["last_sign_in_at"]),
        sign_in_available=bool(r["sign_in_known"]), mailbox_type=boxes.get(r["id"]), mailboxes_read=read)
        for r in conn.execute("SELECT * FROM members")]


def load_dl_facts(conn: sqlite3.Connection) -> list[DistributionListFacts]:
    """DistributionListFacts for every inventoried list, with the transport rules that mention it."""
    rules_known = signal_map(conn).get("exchange_transport_rules", False)
    refs: dict[str, set[str]] = {}
    for r in conn.execute("SELECT dl_id, rule_name FROM dl_rule_refs"):
        refs.setdefault(r["dl_id"], set()).add(r["rule_name"])
    return [DistributionListFacts(
        id=r["id"], kind=r["kind"], display_name=r["display_name"] or r["address"] or r["id"], address=r["address"],
        created_at=parse_graph_dt(r["created_at"]), changed_at=parse_graph_dt(r["changed_at"]),
        owners=tuple(json.loads(r["owners"] or "[]")), synced=_bool(r["synced"]), hidden=_bool(r["hidden"]),
        rules=tuple(sorted(refs.get(r["id"], ()))), rules_known=rules_known, checked=r["scanned_at"] is not None,
        member_count=r["member_count"], last_mail_at=parse_graph_dt(r["last_mail_at"]), traffic_known=bool(r["traffic_known"]))
        for r in conn.execute("SELECT * FROM distribution_lists")]


def _account_states(conn: sqlite3.Connection) -> dict[str, bool | None]:
    """lower-case UPN / mail of every internal user -> account enabled (None if unknown)."""
    out: dict[str, bool | None] = {}
    for r in conn.execute("SELECT mail, user_principal_name, account_enabled FROM members"):
        for key in (r["mail"], r["user_principal_name"]):
            if key:
                out[key.lower()] = _bool(r["account_enabled"])
    return out


def load_mailbox_facts(conn: sqlite3.Connection) -> list[MailboxFacts]:
    """MailboxFacts for every mailbox read from Exchange, with who holds Full Access / Send As (state joined from the internal users)."""
    accounts = _account_states(conn)
    given: dict[str, dict[str, list[Delegate]]] = {}
    for r in conn.execute("SELECT mailbox_id, trustee, kind FROM mailbox_delegates ORDER BY trustee"):
        given.setdefault(r["mailbox_id"], {"full_access": [], "send_as": []})[r["kind"]].append(
            Delegate(r["trustee"], classify_trustee(r["trustee"], accounts)))
    out = []
    for r in conn.execute("SELECT * FROM mailboxes"):
        d = given.get(r["id"], {"full_access": [], "send_as": []})
        out.append(MailboxFacts(
            id=r["id"], mailbox_type=r["mailbox_type"], display_name=r["display_name"] or r["address"] or r["id"], address=r["address"],
            created_at=parse_graph_dt(r["created_at"]), checked=r["scanned_at"] is not None, last_logon_at=parse_graph_dt(r["last_logon_at"]),
            logon_known=bool(r["logon_known"]), item_count=r["item_count"], last_mail_at=parse_graph_dt(r["last_mail_at"]),
            traffic_known=bool(r["traffic_known"]), delegates_known=bool(r["delegates_known"]),
            full_access=tuple(d["full_access"]), send_as=tuple(d["send_as"])))
    return out


def load_rule_facts(conn: sqlite3.Connection, now: datetime | None = None) -> list[RuleFacts]:
    """RuleFacts for every mail flow rule. Dead references need the lists, the mailbox types, the users and the tenant's domains."""
    sig = signal_map(conn)
    row = conn.execute("SELECT value FROM settings WHERE name = 'accepted_domains'").fetchone()
    domains = set(json.loads(row[0])) if row else set()
    checked = bool(domains and sig.get("exchange_distribution_lists") and sig.get("exchange_mailboxes")
                   and conn.execute("SELECT COUNT(*) FROM members").fetchone()[0])
    known: set[str] = set()
    if checked:
        known.update(a.lower() for (a,) in conn.execute("SELECT address FROM distribution_lists WHERE address IS NOT NULL"))
        known.update(a.lower() for (a,) in conn.execute("SELECT address FROM mailboxes WHERE address IS NOT NULL"))
        known.update(_account_states(conn))
        for table in ("members", "groups"):
            for (blob,) in conn.execute(f"SELECT aliases FROM {table} WHERE aliases IS NOT NULL"):
                known.update(json.loads(blob or "[]"))
    out = []
    for r in conn.execute("SELECT * FROM transport_rules"):
        dead = tuple(a for a in json.loads(r["addresses"] or "[]") if checked and a.rsplit("@", 1)[-1] in domains and a not in known)
        out.append(RuleFacts(name=r["name"], state=r["state"] or "Enabled", mode=r["mode"] or "Enforce", priority=r["priority"],
                             changed_at=parse_graph_dt(r["changed_at"]), expiry_at=parse_graph_dt(r["expiry_at"]),
                             dead_references=dead, references_checked=checked))
    return out


# ------------------------------------------------------------------ flags ---
def save_assessments(conn: sqlite3.Connection, assessments: Iterable[Assessment]) -> int:
    """Replace the flag cache. Only objects with at least one flag are stored. Returns count."""
    conn.execute("DELETE FROM flagged_objects")  # cascades to flags
    n = 0
    for a in assessments:
        if not a.flags:
            continue
        n += 1
        conn.execute("INSERT INTO flagged_objects (object_type, object_id, display_name, risk_level) VALUES (?,?,?,?)",
                     (a.object_type, a.object_id, a.display_name, a.risk.value))
        conn.executemany(
            "INSERT INTO flags (object_type, object_id, flag, explanation, evidence) VALUES (?,?,?,?,?)",
            [(a.object_type, a.object_id, f.code.value, f.explanation, json.dumps(dict(f.evidence), default=str))
             for f in a.flags])
    conn.commit()
    return n


def usage_coverage(conn: sqlite3.Connection, group_id: str) -> list[dict[str, Any]]:
    """For one group: every place Broom365 looks for use, with what it found or why it could not look.

    Each row: {label, status: 'found' | 'none' | 'unchecked', items: [str], reason: str | None}.
    'none' only ever means "looked, nothing there"; 'unchecked' means "could not look".
    """
    sigs = signal_map(conn)
    reasons = {r["signal"]: r["reason"] for r in conn.execute("SELECT signal, reason FROM signal_availability")}
    g = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
    scanned = g is not None and g["scanned_at"] is not None

    def row(label: str, items: list[str], checked: bool, reason: str | None = None) -> dict[str, Any]:
        status = "unchecked" if not checked else ("found" if items else "none")
        return {"label": label, "status": status, "items": items, "reason": None if checked else reason}

    rows: list[dict[str, Any]] = []
    by_source: dict[str, list[str]] = {}
    for r in conn.execute("SELECT * FROM group_usages WHERE group_id = ? ORDER BY object_name COLLATE NOCASE", (group_id,)):
        by_source.setdefault(r["source"], []).append(describe(r["source"], r["object_name"] or r["object_id"], r["mode"], r["detail"]))
    for s in USAGE_SOURCES:
        ok = sigs.get(s.signal, False)
        why = reasons.get(s.signal) or f"not read yet; refresh the inventory (needs {s.permission})"
        rows.append(row(s.label, by_source.get(s.signal, []), ok, why))
    rows.append(row("Group-based licensing", ["a licence is assigned to this group"] if g and g["has_license_assignment"] else [],
                    g is not None and g["has_license_assignment"] is not None, "not read"))
    roles = [r[0] or "Unnamed role" for r in conn.execute(
        "SELECT DISTINCT role_name FROM role_assignments WHERE principal_id = ? AND principal_type = 'group'", (group_id,))]
    rows.append(row("Entra directory roles", roles, sigs.get("role_assignments", False), reasons.get("role_assignments")))
    apps = [r[0] or r[1] for r in conn.execute(
        "SELECT resource_display_name, resource_sp_id FROM group_app_assignments WHERE group_id = ?", (group_id,))]
    rows.append(row("Application assignments (Entra enterprise apps)", apps,
                    scanned and sigs.get("group_app_assignments", True), "group not scanned yet" if not scanned else reasons.get("group_app_assignments")))
    parents = [r[0] or r[1] for r in conn.execute("SELECT parent_name, parent_id FROM group_parents WHERE group_id = ?", (group_id,))]
    nested_ok = scanned and g["parent_count"] is not None
    rows.append(row("Member of other groups (nesting)", parents, bool(nested_ok),
                    "group not scanned yet" if not scanned else reasons.get("group_nesting", "not read")))
    return rows
