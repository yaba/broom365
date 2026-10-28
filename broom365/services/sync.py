"""Graph -> SQLite, in two phases, then correlation.

INVENTORY (`run_inventory`): cheap, bulk calls. Stores names/metadata for every group,
    app registration and service principal, plus tenant-wide delegated grants, role
    assignments, Conditional Access bindings, deleted SPs and sign-in activity.
SCAN (`run_scan`): expensive per-object calls (owners, member counts, group->app
    assignments, audit activity, application permissions) for the objects selected by
    the scope patterns only. Scans accumulate: earlier scanned objects keep their data.

Only scanned groups/apps (and role-holding users) are evaluated; an inventoried-only
object produces no flags. Optional signals are wrapped in `Signals.guard`: if Graph
refuses (scope missing, 403, beta down) the signal is recorded as unavailable with a
reason and the run continues as 'partial'.

Scope notes (v1): apps are app *registrations* of this tenant; only active role
assignments are read (not PIM-eligible); calls are sequential ($batch is a later optimisation).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, TypeVar

from ..models.types import Assessment, Thresholds
from . import repository as repo
from .correlate import evaluate_group
from .extended_signals import evaluate_app, evaluate_user
from .exchange import ExchangeClient
from .exchange_lists import evaluate_distribution_list
from .exchange_mail import evaluate_mailbox, evaluate_rule, extract_addresses, full_access_trustees, send_as_trustees
from .guests import evaluate_guest
from .intune import evaluate_intune_app, evaluate_intune_script
from .members import evaluate_member
from .graph import GraphClient, GraphError, Json, SignalUnavailable
from .permissions import check_permissions
from ._time import parse_graph_dt
from .updates import evaluate_update_policy
from .usage import SCRIPT_KINDS, UPDATE_KINDS, UPDATE_RING_TYPE, USAGE_SOURCES

T = TypeVar("T")
Progress = Callable[[str], None]

# Optional signals whose absence is tolerated, and the scope each one needs.
SIGNAL_SCOPES: dict[str, str] = {
    "group_audit_activity": "AuditLog.Read.All",
    "sp_sign_in_activity": "AuditLog.Read.All",
    "user_sign_in_activity": "AuditLog.Read.All",
    "role_assignments": "RoleManagement.Read.Directory",
    "guest_sign_in_activity": "AuditLog.Read.All",
    "member_sign_in_activity": "AuditLog.Read.All",
    **{sig: "Exchange.ManageAsApp" for sig in ("exchange_distribution_lists", "exchange_transport_rules", "exchange_members",
                                              "exchange_traffic", "exchange_mailboxes", "exchange_mailbox_stats",
                                              "exchange_mailbox_permissions", "exchange_accepted_domains")},
    **{s.signal: s.permission for s in USAGE_SOURCES},  # Conditional Access + Intune
    "intune_app_relationships": "DeviceManagementApps.Read.All",
    "intune_script_runs": "DeviceManagementConfiguration.Read.All",
}
KEEP_RUNS = 50
GROUP_AUDIT_PREFIXES = ("Add member", "Remove member", "Add owner", "Remove owner")
_PRINCIPAL_TYPES = {"#microsoft.graph.user": "user", "#microsoft.graph.group": "group",
                    "#microsoft.graph.servicePrincipal": "servicePrincipal"}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _odata_dt(dt: datetime) -> str:
    """UTC datetime as an OData filter literal: 2026-04-28T19:00:00Z (no offset, no microseconds)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _int(v: bool | int | None) -> int | None:
    return None if v is None else int(bool(v))


class Signals:
    """Tracks which optional signals are usable during one run, and why not."""

    def __init__(self, missing_scopes: Iterable[str]) -> None:
        missing = set(missing_scopes)
        self.unavailable: dict[str, str] = {
            sig: f"missing scope {scope}" for sig, scope in SIGNAL_SCOPES.items() if scope in missing}
        self.seen: set[str] = set(self.unavailable)

    def ok(self, name: str) -> bool:
        return name not in self.unavailable

    def guard(self, name: str, fn: Callable[[], T], default: T) -> T:
        """Run `fn` unless `name` is already unavailable; on a Graph failure record why and return `default`."""
        self.seen.add(name)
        if not self.ok(name):
            return default
        try:
            return fn()
        except SignalUnavailable as exc:
            self.unavailable[name] = f"Graph returned {exc.status} (permission denied or not licensed): {exc.message}"
        except GraphError as exc:
            self.unavailable[name] = f"Graph returned {exc.status} ({exc.url.split('?')[0]}): {exc.message}"
        return default

    def persist(self, conn: sqlite3.Connection, now: datetime) -> None:
        """Upsert the signals this run touched (others keep their last known state)."""
        conn.executemany(
            "INSERT INTO signal_availability (signal, available, reason, checked_at) VALUES (?,?,?,?) "
            "ON CONFLICT(signal) DO UPDATE SET available = excluded.available, reason = excluded.reason, "
            "checked_at = excluded.checked_at",
            [(s, int(self.ok(s)), self.unavailable.get(s), _iso(now)) for s in sorted(self.seen)])


# ------------------------------------------------------------- run harness --
Body = Callable[[Progress, Signals], dict[str, Any]]


def _execute(conn: sqlite3.Connection, kind: str, granted_scopes: Iterable[str], now: datetime,
             progress: Progress | None, body: Body) -> int:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    run_id = conn.execute("INSERT INTO sync_runs (kind, started_at, status) VALUES (?, ?, 'running')",
                          (kind, _iso(now))).lastrowid
    assert run_id is not None
    conn.commit()

    def say(msg: str) -> None:
        conn.execute("UPDATE sync_runs SET progress = ? WHERE id = ?", (msg, run_id))
        conn.commit()
        if progress:
            progress(msg)

    missing = set(check_permissions(granted_scopes).missing_scopes)
    if "exchange.manageasapp" not in {g.lower() for g in granted_scopes}:
        missing.add("Exchange.ManageAsApp")  # check_permissions skips it outside app-only mode, but the signals depend on it
    signals = Signals(missing)
    try:
        detail = body(say, signals)
        signals.persist(conn, now)
        conn.execute("UPDATE sync_runs SET status = ?, finished_at = ?, progress = 'Done', detail = ? WHERE id = ?",
                     ("partial" if signals.unavailable else "success", _iso(datetime.now(timezone.utc)),
                      json.dumps(detail), run_id))
        conn.execute("DELETE FROM sync_runs WHERE id NOT IN (SELECT id FROM sync_runs ORDER BY id DESC LIMIT ?)",
                     (KEEP_RUNS,))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        conn.execute("UPDATE sync_runs SET status = 'failed', finished_at = ?, error = ? WHERE id = ?",
                     (_iso(datetime.now(timezone.utc)), f"{type(exc).__name__}: {exc}", run_id))
        conn.commit()
        raise
    return int(run_id)


def recompute_flags(conn: sqlite3.Connection, t: Thresholds, now: datetime) -> int:
    """Re-run correlation over stored data (also used when thresholds change, without Graph calls)."""
    assessments: list[Assessment] = []
    assessments += [evaluate_group(g, t, now) for g in repo.load_group_facts(conn)]
    assessments += [evaluate_app(a, t, now) for a in repo.load_app_facts(conn)]
    assessments += [evaluate_user(u, t, now) for u in repo.load_user_facts(conn)]
    assessments += [evaluate_intune_app(a, now) for a in repo.load_intune_app_facts(conn)]
    assessments += [evaluate_intune_script(s, t, now) for s in repo.load_intune_script_facts(conn)]
    assessments += [evaluate_update_policy(p, t, now) for p in repo.load_update_policy_facts(conn)]
    assessments += [evaluate_guest(g, t, now) for g in repo.load_guest_facts(conn)]
    assessments += [evaluate_member(m, t, now) for m in repo.load_member_facts(conn)]
    assessments += [evaluate_distribution_list(d, now) for d in repo.load_dl_facts(conn)]
    assessments += [evaluate_mailbox(m, t, now) for m in repo.load_mailbox_facts(conn)]
    assessments += [evaluate_rule(r, now) for r in repo.load_rule_facts(conn, now)]
    return repo.save_assessments(conn, assessments)


# --------------------------------------------------------------- inventory --
def run_inventory(conn: sqlite3.Connection, graph: GraphClient, granted_scopes: Iterable[str],
                  thresholds: Thresholds | None = None, now: datetime | None = None,
                  progress: Progress | None = None, exchange: ExchangeClient | None = None) -> int:
    """Refresh the cheap, tenant-wide metadata. Scan data on existing objects is preserved.

    `exchange` (optional) adds the distribution lists and transport rules, which are two single reads.
    """
    now = now or datetime.now(timezone.utc)

    def body(say: Progress, signals: Signals) -> dict[str, Any]:
        stamp = _iso(now)
        say("Reading service principals")
        sps = {sp["id"]: sp for sp in graph.list_service_principals()}
        _upsert_service_principals(conn, sps, stamp)
        say("Reading applications")
        app_sp_ids = _upsert_applications(conn, graph, sps, stamp)
        say("Reading deleted items and delegated permissions")
        _reload_deleted_and_delegated(conn, graph, signals, sps, app_sp_ids)
        say("Reading directory roles and privileged users")
        _reload_roles_and_users(conn, graph, signals)
        say("Reading sign-in activity")
        _reload_sp_sign_ins(conn, graph, signals, sps, app_sp_ids)
        say("Reading external (guest) users")
        n_guests = _reload_guests(conn, graph, signals, stamp)
        say("Reading internal users and licences")
        n_members = _reload_members(conn, graph, signals, stamp)
        say("Reading Exchange distribution lists and transport rules")
        n_lists = _reload_exchange(conn, exchange, signals, stamp)
        say("Reading Conditional Access and Intune assignments")
        n_usages = _reload_usages(conn, graph, signals, stamp)
        say("Reading groups")
        n_groups = _upsert_groups(conn, graph, stamp, say)
        say("Computing flags")
        signals.persist(conn, now)  # flags read signal availability, so this run's state must be stored first
        flagged = recompute_flags(conn, thresholds or repo.load_thresholds(conn), now)
        return {"groups": n_groups, "applications": len(app_sp_ids), "group_references": n_usages, "guests": n_guests, "members": n_members, "distribution_lists": n_lists, "flagged": flagged}

    return _execute(conn, "inventory", granted_scopes, now, progress, body)


def _upsert_service_principals(conn: sqlite3.Connection, sps: dict[str, Json], stamp: str) -> None:
    conn.executemany(
        "INSERT INTO service_principals (id, app_id, display_name, account_enabled, sp_type, app_owner_tenant_id, "
        "inventoried_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET app_id = excluded.app_id, "
        "display_name = excluded.display_name, account_enabled = excluded.account_enabled, sp_type = excluded.sp_type, "
        "app_owner_tenant_id = excluded.app_owner_tenant_id, inventoried_at = excluded.inventoried_at",
        [(sp["id"], sp["appId"], sp.get("displayName"), _int(sp.get("accountEnabled")),
          sp.get("servicePrincipalType"), sp.get("appOwnerOrganizationId"), stamp) for sp in sps.values()])
    conn.execute("DELETE FROM service_principals WHERE inventoried_at <> ?", (stamp,))
    conn.commit()


def _upsert_applications(conn: sqlite3.Connection, graph: GraphClient, sps: dict[str, Json], stamp: str) -> set[str]:
    """Upsert app registrations + credentials (they arrive with the list). Returns tenant-app SP ids."""
    sp_by_app = {sp["appId"]: sp["id"] for sp in sps.values()}
    app_sp_ids: set[str] = set()
    for app in graph.list_applications():
        conn.execute(
            "INSERT INTO applications (id, app_id, display_name, created_at, inventoried_at) VALUES (?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET app_id = excluded.app_id, display_name = excluded.display_name, "
            "created_at = excluded.created_at, inventoried_at = excluded.inventoried_at",
            (app["id"], app["appId"], app.get("displayName"), app.get("createdDateTime"), stamp))
        conn.execute("DELETE FROM app_credentials WHERE application_id = ?", (app["id"],))
        conn.executemany(
            "INSERT OR IGNORE INTO app_credentials (application_id, key_id, kind, display_name, start_at, end_at) "
            "VALUES (?,?,?,?,?,?)",
            [(app["id"], c["keyId"], kind, c.get("displayName"), c.get("startDateTime"), c.get("endDateTime"))
             for kind, field in (("password", "passwordCredentials"), ("key", "keyCredentials"))
             for c in app.get(field) or []])
        if app["appId"] in sp_by_app:
            app_sp_ids.add(sp_by_app[app["appId"]])
    conn.execute("DELETE FROM applications WHERE inventoried_at <> ?", (stamp,))
    conn.commit()
    return app_sp_ids


def _reload_deleted_and_delegated(conn: sqlite3.Connection, graph: GraphClient, signals: Signals,
                                  sps: dict[str, Json], app_sp_ids: set[str]) -> None:
    deleted = signals.guard("deleted_items", lambda: list(graph.list_deleted_service_principals()), [])
    conn.execute("DELETE FROM deleted_service_principals")
    conn.executemany("INSERT OR REPLACE INTO deleted_service_principals (id, deleted_at) VALUES (?,?)",
                     [(d["id"], d.get("deletedDateTime")) for d in deleted])
    grants = signals.guard("delegated_permissions", lambda: list(graph.list_oauth2_permission_grants()), [])
    conn.execute("DELETE FROM permission_grants WHERE kind = 'delegated'")
    rows = []
    for g in grants:
        if g["clientId"] not in app_sp_ids:
            continue
        res = sps.get(g["resourceId"], {})
        rows += [(g["id"], g["clientId"], "delegated", g["resourceId"], res.get("displayName"), scope,
                  g.get("consentType")) for scope in (g.get("scope") or "").split()]
    conn.executemany("INSERT OR IGNORE INTO permission_grants (id, sp_id, kind, resource_sp_id, resource_name, scope, "
                     "consent_type) VALUES (?,?,?,?,?,?,?)", rows)
    conn.commit()


def _reload_roles_and_users(conn: sqlite3.Connection, graph: GraphClient, signals: Signals) -> None:
    """Role assignments, plus user rows and sign-in activity for users that hold a role (batched, 15 users per call)."""
    conn.execute("DELETE FROM role_assignments")
    conn.execute("DELETE FROM users")
    conn.execute("DELETE FROM sign_in_activity")
    items, role_names = signals.guard(
        "role_assignments",
        lambda: (list(graph.list_role_assignments()), {d["id"]: d.get("displayName") for d in graph.list_role_definitions()}),
        ([], {}))
    rows, user_ids = [], set()
    for ra in items:
        ptype = _PRINCIPAL_TYPES.get((ra.get("principal") or {}).get("@odata.type", ""))
        if ptype is None:
            continue
        rows.append((ra["id"], ra["principalId"], ptype, ra["roleDefinitionId"],
                     role_names.get(ra["roleDefinitionId"]), ra.get("directoryScopeId")))
        if ptype == "user":
            user_ids.add(ra["principalId"])
    conn.executemany("INSERT OR IGNORE INTO role_assignments (id, principal_id, principal_type, role_definition_id, "
                     "role_name, directory_scope_id) VALUES (?,?,?,?,?,?)", rows)
    ids = sorted(user_ids)
    for start in range(0, len(ids), graph.USER_BATCH):
        chunk = ids[start:start + graph.USER_BATCH]
        users = signals.guard("user_sign_in_activity", lambda: graph.users_by_ids(chunk, True), None)
        with_activity = users is not None
        if users is None:  # sign-in activity unreadable: still load names, report the signal as unavailable
            users = graph.users_by_ids(chunk, False)
        for user in users:
            conn.execute("INSERT OR IGNORE INTO users (id, display_name, user_principal_name, account_enabled, user_type) "
                         "VALUES (?,?,?,?,?)", (user["id"], user.get("displayName"), user.get("userPrincipalName"),
                                                _int(user.get("accountEnabled")), user.get("userType")))
            if with_activity:  # no `signInActivity` on a user means "no sign-in on record"
                _insert_activity(conn, user["id"], "user", user.get("signInActivity") or {})
    conn.commit()


def _reload_sp_sign_ins(conn: sqlite3.Connection, graph: GraphClient, signals: Signals,
                        sps: dict[str, Json], app_sp_ids: set[str]) -> None:
    """Bulk SP activity report; app SPs absent from it get a row with no date ('no sign-in on record')."""
    report = signals.guard("sp_sign_in_activity", lambda: list(graph.list_sp_sign_in_activities()), [])
    if not signals.ok("sp_sign_in_activity"):
        return
    by_app = {r.get("appId"): r for r in report}
    for sp_id in app_sp_ids:
        entry = by_app.get(sps[sp_id]["appId"], {})
        _insert_activity(conn, sp_id, "servicePrincipal", entry.get("lastSignInActivity") or {})
    conn.commit()


def _reload_guests(conn: sqlite3.Connection, graph: GraphClient, signals: Signals, stamp: str) -> int:
    """Upsert the guest users: one paged list, with sign-in activity when it can be read (else names and dates only).

    Memberships read on demand survive a re-inventory.

    If the list itself cannot be read, what is stored is kept.
    """
    def fetch() -> tuple[list[Json], bool]:
        users = signals.guard("guest_sign_in_activity", lambda: list(graph.list_guests(True)), None)
        if users is not None:
            return users, True
        return list(graph.list_guests(False)), False

    res = signals.guard("guests", fetch, None)
    if res is None:
        return 0
    users, with_sign_in = res
    conn.executemany(
        "INSERT INTO guests (id, display_name, mail, user_principal_name, account_enabled, created_at, external_state, "
        "state_changed_at, last_sign_in_at, sign_in_known, inventoried_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name, mail = excluded.mail, "
        "user_principal_name = excluded.user_principal_name, account_enabled = excluded.account_enabled, "
        "created_at = excluded.created_at, external_state = excluded.external_state, state_changed_at = excluded.state_changed_at, "
        "last_sign_in_at = excluded.last_sign_in_at, sign_in_known = excluded.sign_in_known, inventoried_at = excluded.inventoried_at",
        [(u["id"], u.get("displayName"), u.get("mail"), u.get("userPrincipalName"), _int(u.get("accountEnabled")),
          u.get("createdDateTime"), u.get("externalUserState"), u.get("externalUserStateChangeDateTime"),
          max((d for d in ((u.get("signInActivity") or {}).get(k) for k in
                            ("lastSignInDateTime", "lastNonInteractiveSignInDateTime", "lastSuccessfulSignInDateTime")) if d), default=None),
          int(with_sign_in), stamp) for u in users])
    conn.execute("DELETE FROM guests WHERE inventoried_at <> ?", (stamp,))  # left the tenant; their memberships go too
    conn.commit()
    return len(users)


_RULE_FIELDS_SKIPPED = {"Description", "Comments", "Name", "Identity", "DistinguishedName", "Guid", "ImmutableId"}


def _reload_exchange(conn: sqlite3.Connection, exchange: ExchangeClient | None, signals: Signals, stamp: str) -> int:
    """Upsert the distribution lists (one read, plus dynamic ones) and which transport rules mention them (one read).

    Members and mail traffic are per-list reads and stay on demand. If the lists cannot be read, what is stored is kept.
    """
    if exchange is None:
        return 0
    res = signals.guard("exchange_distribution_lists", lambda: (exchange.distribution_groups(), exchange.dynamic_distribution_groups()), None)
    if res is None:
        return 0
    static, dynamic = res
    rows = []
    for kind, items in (("distribution", static), ("dynamic", dynamic)):
        for d in items:
            oid = d.get("ExternalDirectoryObjectId") or d.get("Guid")
            if not oid:
                continue
            k = "security" if d.get("RecipientTypeDetails") == "MailUniversalSecurityGroup" else kind
            owners = [str(o) for o in (d.get("ManagedBy") or [])]
            rows.append((str(oid), k, d.get("DisplayName"), d.get("PrimarySmtpAddress"), d.get("WhenCreated"), d.get("WhenChanged"),
                         json.dumps(owners), _int(d.get("HiddenFromAddressListsEnabled")), _int(d.get("IsDirSynced")), stamp))
    conn.executemany(
        "INSERT INTO distribution_lists (id, kind, display_name, address, created_at, changed_at, owners, hidden, synced, inventoried_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, display_name = excluded.display_name, "
        "address = excluded.address, created_at = excluded.created_at, changed_at = excluded.changed_at, owners = excluded.owners, "
        "hidden = excluded.hidden, synced = excluded.synced, inventoried_at = excluded.inventoried_at", rows)
    conn.execute("DELETE FROM distribution_lists WHERE inventoried_at <> ?", (stamp,))   # gone from Exchange; cascades to rule refs
    rules = signals.guard("exchange_transport_rules", lambda: exchange.transport_rules(), None)
    conn.execute("DELETE FROM dl_rule_refs")
    if rules is not None:
        by_address = {str(r[3]).lower(): r[0] for r in rows if r[3]}
        for rule in rules:
            for field, value in rule.items():
                if field in _RULE_FIELDS_SKIPPED or not value:
                    continue
                text = json.dumps(value).lower()
                for address, dl_id in by_address.items():
                    if address in text:
                        conn.execute("INSERT OR IGNORE INTO dl_rule_refs (dl_id, rule_name, field) VALUES (?,?,?)",
                                     (dl_id, str(rule.get("Name") or rule.get("Identity") or "(unnamed rule)"), field))
        _store_rules(conn, rules, stamp)
    domains = signals.guard("exchange_accepted_domains", lambda: exchange.accepted_domains(), None)
    if domains is not None:
        conn.execute("INSERT INTO settings (name, value) VALUES ('accepted_domains', ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                     (json.dumps(sorted(set(domains))),))
    conn.commit()
    return len(rows)


def _aliases(obj: Json) -> list[str]:
    """Every e-mail address of a user or group (primary and aliases), lower case, without the smtp: prefix."""
    found = {str(a).split(":", 1)[1].lower() for a in (obj.get("proxyAddresses") or []) if str(a).lower().startswith("smtp:")}
    if obj.get("mail"):
        found.add(str(obj["mail"]).lower())
    return sorted(found)


def _store_rules(conn: sqlite3.Connection, rules: list[Json], stamp: str) -> None:
    """Upsert the mail flow rules (name, state, mode, priority, dates and every address they mention) and drop the ones that are gone."""
    rows = []
    for rule in rules:
        name = str(rule.get("Name") or rule.get("Identity") or "(unnamed rule)")
        rows.append((name, rule.get("State"), rule.get("Mode"), rule.get("Priority"), rule.get("WhenChanged"), rule.get("ExpiryDate"),
                     json.dumps(extract_addresses(rule)), stamp))
    conn.executemany(
        "INSERT INTO transport_rules (name, state, mode, priority, changed_at, expiry_at, addresses, inventoried_at) VALUES (?,?,?,?,?,?,?,?) "
        "ON CONFLICT(name) DO UPDATE SET state = excluded.state, mode = excluded.mode, priority = excluded.priority, "
        "changed_at = excluded.changed_at, expiry_at = excluded.expiry_at, addresses = excluded.addresses, inventoried_at = excluded.inventoried_at",
        rows)
    conn.execute("DELETE FROM transport_rules WHERE inventoried_at <> ?", (stamp,))


def _newest_sign_in(u: Json) -> str | None:
    a = u.get("signInActivity") or {}
    return max((d for d in (a.get(k) for k in ("lastSignInDateTime", "lastNonInteractiveSignInDateTime", "lastSuccessfulSignInDateTime")) if d),
               default=None)


def _reload_members(conn: sqlite3.Connection, graph: GraphClient, signals: Signals, stamp: str) -> int:
    """Upsert the internal users: one paged list with licences and (when readable) sign-in activity.

    Licence names come from one extra list (subscribedSkus); if it cannot be read the licences are kept as ids.
    If the user list itself cannot be read, what is stored is kept.
    """
    skus = signals.guard("license_skus", lambda: {s["skuId"]: s["skuPartNumber"] for s in graph.list_skus()}, {})

    def fetch() -> tuple[list[Json], bool]:
        users = signals.guard("member_sign_in_activity", lambda: list(graph.list_members(True)), None)
        if users is not None:
            return users, True
        return list(graph.list_members(False)), False

    res = signals.guard("members", fetch, None)
    if res is None:
        return 0
    users, with_sign_in = res
    conn.executemany(
        "INSERT INTO members (id, display_name, mail, user_principal_name, account_enabled, created_at, on_prem_synced, licences, "
        "last_sign_in_at, sign_in_known, aliases, inventoried_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name, mail = excluded.mail, "
        "user_principal_name = excluded.user_principal_name, account_enabled = excluded.account_enabled, created_at = excluded.created_at, "
        "on_prem_synced = excluded.on_prem_synced, licences = excluded.licences, last_sign_in_at = excluded.last_sign_in_at, "
        "sign_in_known = excluded.sign_in_known, aliases = excluded.aliases, inventoried_at = excluded.inventoried_at",
        [(u["id"], u.get("displayName"), u.get("mail"), u.get("userPrincipalName"), _int(u.get("accountEnabled")), u.get("createdDateTime"),
          int(bool(u.get("onPremisesSyncEnabled"))),
          json.dumps(sorted(skus.get(l["skuId"], l["skuId"]) for l in u.get("assignedLicenses") or [])),
          _newest_sign_in(u), int(with_sign_in), json.dumps(_aliases(u)), stamp) for u in users])
    conn.execute("DELETE FROM members WHERE inventoried_at <> ?", (stamp,))
    conn.commit()
    return len(users)


def _insert_activity(conn: sqlite3.Connection, object_id: str, kind: str, a: Json) -> None:
    interactive, non_interactive = a.get("lastSignInDateTime"), a.get("lastNonInteractiveSignInDateTime")
    latest = max((d for d in (interactive, non_interactive, a.get("lastSuccessfulSignInDateTime")) if d), default=None)
    conn.execute("INSERT OR REPLACE INTO sign_in_activity (object_id, object_type, last_sign_in_at, "
                 "last_interactive_at, last_non_interactive_at) VALUES (?,?,?,?,?)",
                 (object_id, kind, latest, interactive, non_interactive))


def _reload_usages(conn: sqlite3.Connection, graph: GraphClient, signals: Signals, stamp: str) -> int:
    """Collect every place that references a group (Conditional Access, Intune assignments) in bulk.

    Each source is its own signal: one that cannot be read is recorded as unavailable and contributes no rows,
    so its absence is reported as "not checked" rather than "not used".
    """
    rows: list[tuple[str, str, str, str, str, str, str | None]] = []
    policies = signals.guard("policy_binding", lambda: list(graph.list_conditional_access_policies()), [])
    for p in policies:
        users = (p.get("conditions") or {}).get("users") or {}
        for mode, key in (("include", "includeGroups"), ("exclude", "excludeGroups")):
            for gid in users.get(key) or []:
                rows.append((gid, "policy_binding", "Conditional Access policy", p["id"],
                             p.get("displayName") or p["id"], mode, p.get("state")))
    for src in USAGE_SOURCES:
        if not src.path:
            continue
        items = signals.guard(src.signal, lambda: list(graph.list_with_assignments(src.api, src.path)), [])
        if src.signal == "intune_apps" and signals.ok(src.signal):
            _store_intune_apps(conn, items, stamp)
        if src.signal in SCRIPT_KINDS and signals.ok(src.signal):
            _store_intune_scripts(conn, SCRIPT_KINDS[src.signal], items, stamp)
        if src.signal in UPDATE_KINDS and signals.ok(src.signal):
            _store_update_policies(conn, UPDATE_KINDS[src.signal], items, stamp)
        if src.signal == "intune_device_config" and signals.ok(src.signal):
            _store_update_policies(conn, "ring", [i for i in items if str(i.get("@odata.type", "")).endswith(UPDATE_RING_TYPE)], stamp)
        for item in items:
            name = item.get("displayName") or item.get("name") or item["id"]
            for a in item.get("assignments") or []:
                target = a.get("target") or {}
                kind = str(target.get("@odata.type", "")).lower()
                if not target.get("groupId") or "groupassignmenttarget" not in kind:
                    continue
                rows.append((target["groupId"], src.signal, src.kind, item["id"], name,
                             "exclude" if "exclusion" in kind else "assigned", a.get("intent")))
    conn.execute("DELETE FROM group_usages")
    conn.executemany("INSERT OR IGNORE INTO group_usages (group_id, source, kind, object_id, object_name, mode, detail) "
                     "VALUES (?,?,?,?,?,?,?)", rows)
    conn.commit()
    return len(rows)


_INTUNE_TARGETS = {  # Graph target type -> (target, mode)
    "groupassignmenttarget": ("group", "include"),
    "exclusiongroupassignmenttarget": ("group", "exclude"),
    "alllicensedusersassignmenttarget": ("all_users", "include"),
    "alldevicesassignmenttarget": ("all_devices", "include"),
}


def _store_intune_apps(conn: sqlite3.Connection, items: list[Json], stamp: str) -> None:
    """Upsert Intune apps and replace their assignment targets. Relationships and `scanned_at` survive a re-inventory."""
    for item in items:
        conn.execute(
            "INSERT INTO intune_apps (id, display_name, app_type, publisher, created_at, modified_at, inventoried_at) "
            "VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name, "
            "app_type = excluded.app_type, publisher = excluded.publisher, created_at = excluded.created_at, "
            "modified_at = excluded.modified_at, inventoried_at = excluded.inventoried_at",
            (item["id"], item.get("displayName"), str(item.get("@odata.type", "")).rsplit(".", 1)[-1] or None,
             item.get("publisher"), item.get("createdDateTime"), item.get("lastModifiedDateTime"), stamp))
        conn.execute("DELETE FROM intune_app_assignments WHERE app_id = ?", (item["id"],))
        for a in item.get("assignments") or []:
            target = a.get("target") or {}
            kind = _INTUNE_TARGETS.get(str(target.get("@odata.type", "")).rsplit(".", 1)[-1].lower())
            if kind is None or (kind[0] == "group" and not target.get("groupId")):
                continue
            conn.execute("INSERT OR IGNORE INTO intune_app_assignments (app_id, target, group_id, mode, intent) VALUES (?,?,?,?,?)",
                         (item["id"], kind[0], target.get("groupId") or "", kind[1], a.get("intent") or ""))
    conn.execute("DELETE FROM intune_apps WHERE inventoried_at <> ?", (stamp,))  # gone from the tenant; cascades


def _store_intune_scripts(conn: sqlite3.Connection, kind: str, items: list[Json], stamp: str) -> None:
    """Upsert the scripts of one kind and replace their assignment targets. Run results and `scanned_at` survive."""
    for item in items:
        conn.execute(
            "INSERT INTO intune_scripts (id, kind, display_name, created_at, modified_at, inventoried_at) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, display_name = excluded.display_name, "
            "created_at = excluded.created_at, modified_at = excluded.modified_at, inventoried_at = excluded.inventoried_at",
            (item["id"], kind, item.get("displayName"), item.get("createdDateTime"), item.get("lastModifiedDateTime"), stamp))
        conn.execute("DELETE FROM intune_script_assignments WHERE script_id = ?", (item["id"],))
        for a in item.get("assignments") or []:
            target = a.get("target") or {}
            tk = _INTUNE_TARGETS.get(str(target.get("@odata.type", "")).rsplit(".", 1)[-1].lower())
            if tk is None or (tk[0] == "group" and not target.get("groupId")):
                continue
            conn.execute("INSERT OR IGNORE INTO intune_script_assignments (script_id, target, group_id, mode) VALUES (?,?,?,?)",
                         (item["id"], tk[0], target.get("groupId") or "", tk[1]))
    conn.execute("DELETE FROM intune_scripts WHERE kind = ? AND inventoried_at <> ?", (kind, stamp))


_POLICY_BASE_KEYS = ("assignments", "id", "displayName", "description", "createdDateTime", "lastModifiedDateTime", "roleScopeTagIds", "version")


def _store_update_policies(conn: sqlite3.Connection, kind: str, items: list[Json], stamp: str) -> None:
    """Upsert the update policies of one kind (keeping their Graph properties) and replace their assignment targets."""
    for item in items:
        settings = {k: v for k, v in item.items() if not k.startswith("@") and k not in _POLICY_BASE_KEYS}
        conn.execute(
            "INSERT INTO update_policies (id, kind, display_name, created_at, modified_at, settings_json, inventoried_at) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, display_name = excluded.display_name, created_at = excluded.created_at, "
            "modified_at = excluded.modified_at, settings_json = excluded.settings_json, inventoried_at = excluded.inventoried_at",
            (item["id"], kind, item.get("displayName"), item.get("createdDateTime"), item.get("lastModifiedDateTime"),
             json.dumps(settings), stamp))
        conn.execute("DELETE FROM update_policy_assignments WHERE policy_id = ?", (item["id"],))
        for a in item.get("assignments") or []:
            target = a.get("target") or {}
            tk = _INTUNE_TARGETS.get(str(target.get("@odata.type", "")).rsplit(".", 1)[-1].lower())
            if tk is None or (tk[0] == "group" and not target.get("groupId")):
                continue
            conn.execute("INSERT OR IGNORE INTO update_policy_assignments (policy_id, target, group_id, mode) VALUES (?,?,?,?)",
                         (item["id"], tk[0], target.get("groupId") or "", tk[1]))
    conn.execute("DELETE FROM update_policies WHERE kind = ? AND inventoried_at <> ?", (kind, stamp))


def _skip_404(fn: Callable[[], T], default: T) -> T:
    """An object deleted between listing and detail read is not an outage of the whole signal."""
    try:
        return fn()
    except GraphError as exc:
        if exc.status == 404:
            return default
        raise


def _upsert_groups(conn: sqlite3.Connection, graph: GraphClient, stamp: str, say: Progress) -> int:
    """Upsert every group's inventory fields (one paged list; no per-group calls)."""
    n = 0
    for g in graph.list_groups():
        n += 1
        if n % 500 == 0:
            say(f"Reading groups ({n} so far)")
        conn.execute(
            "INSERT INTO groups (id, display_name, description, created_at, membership_rule, mail_enabled, "
            "security_enabled, has_license_assignment, group_types, aliases, inventoried_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name, description = excluded.description, "
            "created_at = excluded.created_at, membership_rule = excluded.membership_rule, "
            "mail_enabled = excluded.mail_enabled, security_enabled = excluded.security_enabled, "
            "has_license_assignment = excluded.has_license_assignment, group_types = excluded.group_types, "
            "aliases = excluded.aliases, inventoried_at = excluded.inventoried_at",
            (g["id"], g.get("displayName"), g.get("description"), g.get("createdDateTime"), g.get("membershipRule"),
             _int(g.get("mailEnabled")), _int(g.get("securityEnabled")), int(bool(g.get("assignedLicenses"))),
             ",".join(g.get("groupTypes") or []), json.dumps(_aliases(g)), stamp))
    conn.execute("DELETE FROM groups WHERE inventoried_at <> ?", (stamp,))
    conn.commit()
    return n


# -------------------------------------------------------------------- scan --
def run_scan(conn: sqlite3.Connection, graph: GraphClient, granted_scopes: Iterable[str],
             group_patterns: str, app_patterns: str, thresholds: Thresholds | None = None,
             now: datetime | None = None, progress: Progress | None = None,
             kinds: Iterable[str] = ("groups", "apps", "intune", "scripts", "guests"),
             intune_patterns: str = "", script_patterns: str = "", guest_patterns: str = "", dl_patterns: str = "",
             mailbox_patterns: str = "", exchange: ExchangeClient | None = None) -> int:
    """Check, on demand, the objects selected by the patterns (see scope.py). Requires an inventory first.

    groups -> owners, members, nesting, audit; apps -> owners and application permissions;
    intune -> dependency / supersedence links of Intune apps; scripts -> run results of Intune scripts;
    guests -> the groups and Teams each guest belongs to (matched by name, e-mail or company domain);
    dls -> member count and mail traffic (message trace, up to 89 days) of Exchange distribution lists (name or address);
    mailbox_types -> the list of shared, room and equipment mailboxes (no patterns; tells disabled-by-design accounts from leftovers);
    mailboxes -> last sign-in, mail traffic and Full Access / Send As permissions of the selected mailboxes (name or address).
    The last three need `exchange`; `dls`, `mailbox_types` and `mailboxes` are never part of the default kinds.
    `kinds` limits which object types are touched: scanning apps never scans groups, and vice versa.

    Groups holding a directory role are always scanned. Already-scanned objects outside the
    patterns keep their previous data.
    """
    now = now or datetime.now(timezone.utc)
    t = thresholds or repo.load_thresholds(conn)

    def body(say: Progress, signals: Signals) -> dict[str, Any]:
        wanted = set(kinds)
        group_ids = repo.select_scope_ids(conn, "groups", group_patterns) if "groups" in wanted else []
        app_ids = repo.select_scope_ids(conn, "apps", app_patterns) if "apps" in wanted else []
        intune_ids = repo.select_scope_ids(conn, "intune", intune_patterns) if "intune" in wanted else []
        script_ids = repo.select_scope_ids(conn, "scripts", script_patterns) if "scripts" in wanted else []
        guest_ids = repo.select_scope_ids(conn, "guests", guest_patterns) if "guests" in wanted else []
        stamp = _iso(now)
        _scan_groups(conn, graph, signals, group_ids, t, stamp, say)
        _scan_apps(conn, graph, signals, app_ids, stamp, say)
        _scan_intune_apps(conn, graph, signals, intune_ids, stamp, say)
        _scan_scripts(conn, graph, signals, script_ids, stamp, say)
        _scan_guests(conn, graph, signals, guest_ids, stamp, say)
        dl_ids = repo.select_scope_ids(conn, "dls", dl_patterns) if "dls" in wanted else []
        mailbox_ids: list[str] = []
        if exchange is not None:
            _scan_distribution_lists(conn, exchange, signals, dl_ids, now, stamp, say)
            if "mailbox_types" in wanted:
                _read_mailbox_types(conn, exchange, signals, stamp, say)
            mailbox_ids = repo.select_scope_ids(conn, "mailboxes", mailbox_patterns) if "mailboxes" in wanted else []   # after the list is read
            _scan_mailbox_details(conn, exchange, signals, mailbox_ids, now, stamp, say)
        say("Computing flags")
        signals.persist(conn, now)  # flags read signal availability, so this run's state must be stored first
        flagged = recompute_flags(conn, t, now)
        return {"groups_scanned": len(group_ids), "apps_scanned": len(app_ids), "intune_apps_checked": len(intune_ids),
                "scripts_checked": len(script_ids), "guests_checked": len(guest_ids), "lists_checked": len(dl_ids), "mailboxes_checked": len(mailbox_ids), "flagged": flagged}

    return _execute(conn, "scan", granted_scopes, now, progress, body)


def _scan_groups(conn: sqlite3.Connection, graph: GraphClient, signals: Signals, ids: list[str],
                 t: Thresholds, stamp: str, say: Progress) -> None:
    if not ids:
        return
    say(f"Reading audit activity for {len(ids)} group(s)")
    last_change = _latest_membership_changes(graph, signals, datetime.fromisoformat(stamp), t.stale_days_group, set(ids))
    for i, gid in enumerate(ids, 1):
        say(f"Scanning groups ({i}/{len(ids)})")
        owners = signals.guard("group_owners", lambda: graph.group_owners(gid), None)
        members = signals.guard("group_members", lambda: graph.group_member_count(gid), None)
        assigned = signals.guard("group_app_assignments", lambda: graph.group_app_role_assignments(gid), [])
        parents = signals.guard("group_nesting", lambda: graph.group_member_of(gid), None)
        conn.execute("UPDATE groups SET scanned_at = ?, member_count = ?, owner_count = ?, parent_count = ?, "
                     "last_membership_change_at = ? WHERE id = ?",
                     (stamp, members, None if owners is None else len(owners),
                      None if parents is None else len(parents), last_change.get(gid), gid))
        conn.execute("DELETE FROM group_parents WHERE group_id = ?", (gid,))
        conn.executemany("INSERT OR IGNORE INTO group_parents (group_id, parent_id, parent_name) VALUES (?,?,?)",
                         [(gid, p["id"], p.get("displayName")) for p in parents or []])
        conn.execute("DELETE FROM group_owners WHERE group_id = ?", (gid,))
        conn.execute("DELETE FROM group_app_assignments WHERE group_id = ?", (gid,))
        conn.executemany("INSERT OR IGNORE INTO group_owners (group_id, owner_id, owner_type, display_name) VALUES (?,?,?,?)",
                         [(gid, o["id"], _PRINCIPAL_TYPES.get(o.get("@odata.type", ""), "user"), o.get("displayName"))
                          for o in owners or []])
        conn.executemany(
            "INSERT OR IGNORE INTO group_app_assignments (id, group_id, resource_sp_id, resource_display_name, "
            "app_role_id, assigned_at) VALUES (?,?,?,?,?,?)",
            [(a["id"], gid, a["resourceId"], a.get("resourceDisplayName"), a.get("appRoleId"), a.get("createdDateTime"))
             for a in assigned])
    conn.commit()


def _scan_apps(conn: sqlite3.Connection, graph: GraphClient, signals: Signals, ids: list[str],
               stamp: str, say: Progress) -> None:
    role_names: dict[str, dict[str, str]] = {}

    def roles_of(resource_id: str) -> dict[str, str]:
        if resource_id not in role_names:
            data = signals.guard("app_permissions", lambda: graph.get_service_principal_roles(resource_id), {})
            role_names[resource_id] = {r["id"]: r["value"] for r in data.get("appRoles", []) if r.get("value")}
        return role_names[resource_id]

    for i, app_id in enumerate(ids, 1):
        say(f"Scanning apps ({i}/{len(ids)})")
        owners = graph.application_owners(app_id)
        conn.execute("UPDATE applications SET scanned_at = ?, owner_count = ? WHERE id = ?", (stamp, len(owners), app_id))
        conn.execute("DELETE FROM app_owners WHERE application_id = ?", (app_id,))
        conn.executemany("INSERT OR IGNORE INTO app_owners (application_id, owner_id, display_name) VALUES (?,?,?)",
                         [(app_id, o["id"], o.get("displayName")) for o in owners])
        sp = conn.execute("SELECT s.id FROM service_principals s JOIN applications a ON a.app_id = s.app_id "
                          "WHERE a.id = ?", (app_id,)).fetchone()
        if sp is None:
            continue
        assigned = signals.guard("app_permissions", lambda: graph.sp_app_role_assignments(sp["id"]), [])
        conn.execute("DELETE FROM permission_grants WHERE sp_id = ? AND kind = 'application'", (sp["id"],))
        conn.executemany(
            "INSERT OR IGNORE INTO permission_grants (id, sp_id, kind, resource_sp_id, resource_name, scope, consent_type) "
            "VALUES (?,?,?,?,?,?,?)",
            [(a["id"], sp["id"], "application", a["resourceId"], a.get("resourceDisplayName"),
              roles_of(a["resourceId"]).get(a["appRoleId"], f"role:{a['appRoleId']}"), None) for a in assigned])
    conn.commit()


AUDIT_MAX_DAYS = 29    # directory audit logs keep about 30 days; asking for older data is a 400
AUDIT_FALLBACK_DAYS = 6  # tenants without Entra ID P1/P2 keep about 7 days


def _latest_membership_changes(graph: GraphClient, signals: Signals, now: datetime, window_days: int,
                               only_ids: set[str]) -> dict[str, str]:
    """group id -> newest member/owner change timestamp seen in the audit log (empty if unavailable).

    The window is clamped to what the audit log retains (`AUDIT_MAX_DAYS`); if Graph still says the start is too old,
    the shorter retention of tenants without P1/P2 is tried. A group with no event in the window is NOT known to be
    unchanged for longer: callers must treat "no event" as "unknown", not as "stale".
    """
    def fetch(days: int) -> list[Json]:
        return list(graph.list_group_membership_audits(_odata_dt(now - timedelta(days=days))))

    def events_in_window() -> list[Json]:
        try:
            return fetch(min(window_days, AUDIT_MAX_DAYS))
        except GraphError as exc:
            if exc.status == 400 and "minimum allowed time" in exc.message.lower():
                return fetch(AUDIT_FALLBACK_DAYS)
            raise

    events = signals.guard("group_audit_activity", events_in_window, [])
    latest: dict[str, str] = {}
    for e in events:
        if not str(e.get("activityDisplayName", "")).startswith(GROUP_AUDIT_PREFIXES):
            continue
        for target in e.get("targetResources") or []:
            if target.get("type") == "Group" and target["id"] in only_ids and e.get("activityDateTime"):
                latest[target["id"]] = max(latest.get(target["id"], ""), e["activityDateTime"])
    return latest


def _scan_intune_apps(conn: sqlite3.Connection, graph: GraphClient, signals: Signals, ids: list[str],
                      stamp: str, say: Progress) -> None:
    """Read dependency / supersedence links of the selected Intune apps (one call per app)."""
    for i, app_id in enumerate(ids, 1):
        say(f"Checking Intune app relationships ({i}/{len(ids)})")
        rels = signals.guard("intune_app_relationships", lambda: _skip_404(lambda: graph.app_relationships(app_id), []), None)
        conn.execute("DELETE FROM intune_app_relationships WHERE app_id = ?", (app_id,))
        for r in rels or []:
            kind = {"mobileappdependency": "dependency", "mobileappsupersedence": "supersedence"}.get(
                str(r.get("@odata.type", "")).rsplit(".", 1)[-1].lower())
            if kind and r.get("targetType") in ("parent", "child") and r.get("targetId"):
                conn.execute("INSERT OR IGNORE INTO intune_app_relationships (app_id, kind, role, other_id, other_name, detail) "
                             "VALUES (?,?,?,?,?,?)", (app_id, kind, r["targetType"], r["targetId"], r.get("targetDisplayName"),
                                                      r.get("dependencyType") or r.get("supersedenceType")))
        conn.execute("UPDATE intune_apps SET scanned_at = ? WHERE id = ?", (stamp, app_id))
    conn.commit()


def _scan_scripts(conn: sqlite3.Connection, graph: GraphClient, signals: Signals, ids: list[str],
                  stamp: str, say: Progress) -> None:
    """Read the run summary (success / error counts, last run) of the selected scripts and remediations."""
    paths = {SCRIPT_KINDS[s.signal]: s.path for s in USAGE_SOURCES if s.signal in SCRIPT_KINDS}
    kinds = {r[0]: r[1] for r in conn.execute("SELECT id, kind FROM intune_scripts").fetchall()}
    for i, sid in enumerate(ids, 1):
        say(f"Reading script run results ({i}/{len(ids)})")
        run = signals.guard("intune_script_runs", lambda: _skip_404(lambda: graph.script_run_summary(paths[kinds[sid]], sid), None), None)
        conn.execute("UPDATE intune_scripts SET run_json = ?, scanned_at = ? WHERE id = ?",
                     (json.dumps({k: v for k, v in run.items() if not k.startswith("@")}) if run is not None else None, stamp, sid))
    conn.commit()


def _scan_guests(conn: sqlite3.Connection, graph: GraphClient, signals: Signals, ids: list[str],
                 stamp: str, say: Progress) -> None:
    """Read the groups and Teams (nested ones included) of the selected guests, one call per guest."""
    for i, gid in enumerate(ids, 1):
        say(f"Checking guest memberships ({i}/{len(ids)})")
        groups = signals.guard("guest_memberships", lambda: _skip_404(lambda: graph.guest_memberships(gid), []), None)
        conn.execute("DELETE FROM guest_memberships WHERE guest_id = ?", (gid,))
        for g in groups or []:
            kind = ("team" if "Team" in (g.get("resourceProvisioningOptions") or [])
                    else "microsoft365" if "Unified" in (g.get("groupTypes") or []) else "security")
            conn.execute("INSERT OR IGNORE INTO guest_memberships (guest_id, group_id, group_name, kind) VALUES (?,?,?,?)",
                         (gid, g["id"], g.get("displayName"), kind))
        conn.execute("UPDATE guests SET scanned_at = ? WHERE id = ?", (stamp, gid))
    conn.commit()


def _scan_distribution_lists(conn: sqlite3.Connection, exchange: ExchangeClient, signals: Signals, ids: list[str], now: datetime,
                             stamp: str, say: Progress) -> None:
    """Read the member count and the newest mail (message trace, 89 days back) of the selected lists."""
    for i, lid in enumerate(ids, 1):
        say(f"Checking distribution lists ({i}/{len(ids)})")
        row = conn.execute("SELECT address, kind FROM distribution_lists WHERE id = ?", (lid,)).fetchone()
        address, dynamic = row["address"], row["kind"] == "dynamic"
        if not address:
            continue
        members = signals.guard("exchange_members", lambda: exchange.member_count(address, dynamic), None)
        mail = signals.guard("exchange_traffic", lambda: ("seen", exchange.last_mail_received(address, now)), None)
        last = mail[1] if mail else None
        conn.execute("UPDATE distribution_lists SET scanned_at = ?, member_count = ?, last_mail_at = ?, traffic_known = ? WHERE id = ?",
                     (stamp, members, last.isoformat() if last else None, int(mail is not None), lid))
    conn.commit()


def _read_mailbox_types(conn: sqlite3.Connection, exchange: ExchangeClient, signals: Signals, stamp: str, say: Progress) -> None:
    """Read the shared, room and equipment mailboxes (about 25 MB on a large tenant). Kept if they cannot be read."""
    say("Reading shared, room and equipment mailboxes (about 40 seconds on a large tenant)")
    boxes = signals.guard("exchange_mailboxes", lambda: exchange.mailboxes(), None)
    if boxes is None:
        return
    conn.executemany(
        "INSERT INTO mailboxes (id, mailbox_type, display_name, address, created_at, inventoried_at, send_on_behalf) VALUES (?,?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET mailbox_type = excluded.mailbox_type, display_name = excluded.display_name, "
        "address = excluded.address, created_at = excluded.created_at, inventoried_at = excluded.inventoried_at, "
        "send_on_behalf = excluded.send_on_behalf",
        [(str(b["ExternalDirectoryObjectId"]), b.get("RecipientTypeDetails") or "SharedMailbox", b.get("DisplayName"),
          b.get("PrimarySmtpAddress"), b.get("WhenCreated"), stamp, json.dumps([str(x) for x in (b.get("GrantSendOnBehalfTo") or [])]))
         for b in boxes if b.get("ExternalDirectoryObjectId")])
    conn.execute("DELETE FROM mailboxes WHERE inventoried_at <> ?", (stamp,))
    conn.commit()


def _scan_mailbox_details(conn: sqlite3.Connection, exchange: ExchangeClient, signals: Signals, ids: list[str], now: datetime,
                          stamp: str, say: Progress) -> None:
    """For the selected mailboxes read the last sign-in and size, who has Full Access / Send As, and the newest mail (message trace)."""
    for i, mid in enumerate(ids, 1):
        say(f"Checking mailboxes ({i}/{len(ids)})")
        row = conn.execute("SELECT address FROM mailboxes WHERE id = ?", (mid,)).fetchone()
        if row is None:
            continue
        address = row["address"]
        stats = signals.guard("exchange_mailbox_stats", lambda: ("ok", exchange.mailbox_statistics(mid)), None)
        perms = signals.guard("exchange_mailbox_permissions", lambda: (exchange.mailbox_permissions(mid), exchange.recipient_permissions(mid)), None)
        mail = signals.guard("exchange_traffic", lambda: ("seen", exchange.last_mail_received(address, now)), None) if address else None
        logon = _logon_time((stats[1] or {}).get("LastLogonTime")) if stats else None
        last = mail[1] if mail else None
        conn.execute(
            "UPDATE mailboxes SET scanned_at = ?, last_logon_at = ?, logon_known = ?, item_count = ?, last_mail_at = ?, traffic_known = ?, "
            "delegates_known = ? WHERE id = ?",
            (stamp, logon, int(stats is not None), (stats[1] or {}).get("ItemCount") if stats else None, last.isoformat() if last else None,
             int(mail is not None), int(perms is not None), mid))
        if perms is not None:
            conn.execute("DELETE FROM mailbox_delegates WHERE mailbox_id = ?", (mid,))
            for kind, names in (("full_access", full_access_trustees(perms[0])), ("send_as", send_as_trustees(perms[1]))):
                for name in names:
                    conn.execute("INSERT OR IGNORE INTO mailbox_delegates (mailbox_id, trustee, kind) VALUES (?,?,?)", (mid, name, kind))
    conn.commit()


def _logon_time(value: Any) -> str | None:
    """LastLogonTime as an ISO string; Exchange reports never-signed-in as empty or the year 1601."""
    if not value or str(value).startswith("1601"):
        return None
    return parse_graph_dt(str(value)).isoformat() if parse_graph_dt(str(value)) else None
