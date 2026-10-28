import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from broom365.services import repository as repo
from broom365.services.graph import GraphError, SignalUnavailable
from broom365.services.sync import run_inventory, run_scan

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)
ALL_SCOPES = ["User.Read", "Group.Read.All", "Application.Read.All", "Directory.Read.All", "Exchange.ManageAsApp",
              "RoleManagement.Read.Directory", "AuditLog.Read.All", "Policy.Read.All", "DeviceManagementApps.Read.All", "DeviceManagementConfiguration.Read.All"]
SCHEMA = Path(__file__).parents[1] / "broom365" / "models" / "schema.sql"


class FakeGraph:
    """In-memory stand-in for GraphClient. `deny` makes the named endpoints raise 403; `calls` records per-object calls."""

    def __init__(self, deny: set[str] = frozenset()):  # type: ignore[assignment]
        self.deny = set(deny)
        self.calls: list[str] = []
        self.user_calls: list[tuple[int, bool]] = []
        self.guest_calls: list[bool] = []
        self.member_calls: list[bool] = []
        self.groups = [
            {"id": "g-orphan", "displayName": "CRM Users", "createdDateTime": "2026-09-01T00:00:00Z", "assignedLicenses": []},
            {"id": "g-priv", "displayName": "Admins", "createdDateTime": "2026-09-01T00:00:00Z", "assignedLicenses": []},
            {"id": "g-ok", "displayName": "Fine", "createdDateTime": "2026-09-01T00:00:00Z", "assignedLicenses": [{"x": 1}]},
            {"id": "g-win-1", "displayName": "win10-app-deployment-a", "createdDateTime": "2026-09-01T00:00:00Z", "assignedLicenses": []},
            {"id": "g-win-2", "displayName": "win10-app-deployment-b", "createdDateTime": "2026-09-01T00:00:00Z", "assignedLicenses": []},
        ]

    def _check(self, name: str) -> None:
        if name in self.deny:
            raise SignalUnavailable(403, name, "denied")

    # --- bulk (inventory)
    def list_service_principals(self):
        return [{"id": "sp-app", "appId": "app-1", "displayName": "Old CRM", "accountEnabled": True},
                {"id": "sp-graph", "appId": "gr", "displayName": "Microsoft Graph", "accountEnabled": True}]

    def list_applications(self):
        return [{"id": "ap-1", "appId": "app-1", "displayName": "Old CRM", "createdDateTime": "2020-01-01T00:00:00Z",
                 "passwordCredentials": [{"keyId": "k1", "displayName": "s", "endDateTime": "2026-08-01T00:00:00Z"}],
                 "keyCredentials": []}]

    def list_oauth2_permission_grants(self):
        self._check("grants")
        return [{"id": "gr1", "clientId": "sp-app", "resourceId": "sp-graph", "consentType": "AllPrincipals",
                 "scope": "Mail.Read User.Read"}]

    def list_sp_sign_in_activities(self):
        self._check("sp_signins")
        return [{"appId": "app-1", "lastSignInActivity": {"lastSignInDateTime": "2025-12-01T00:00:00Z"}}]

    def list_role_assignments(self):
        self._check("roles")
        return [{"id": "r1", "principalId": "u1", "roleDefinitionId": "rd-ga", "principal": {"@odata.type": "#microsoft.graph.user"}},
                {"id": "r2", "principalId": "g-priv", "roleDefinitionId": "rd-ua", "principal": {"@odata.type": "#microsoft.graph.group"}}]

    def list_role_definitions(self):
        return [{"id": "rd-ga", "displayName": "Global Administrator"}, {"id": "rd-ua", "displayName": "User Administrator"}]

    USER_BATCH = 15

    def users_by_ids(self, ids, with_sign_in=False):
        self.user_calls.append((len(ids), with_sign_in))
        if with_sign_in:
            self._check("user_signins")
        return [{"id": uid, "displayName": "Ann", "userPrincipalName": "ann@x", "accountEnabled": True,
                 **({"signInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z"}} if with_sign_in else {})} for uid in ids]

    def list_guests(self, with_sign_in=False):
        self.guest_calls.append(with_sign_in)
        self._check("guests")
        if with_sign_in:
            self._check("guest_signins")
        rows = [("gu1", "Old Pat", "pat@partner.com", "Accepted", "2021-03-01T00:00:00Z", "2021-04-01T00:00:00Z", "2022-01-01T00:00:00Z"),
                ("gu2", "Sam", "sam@supplies.com", "PendingAcceptance", "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z", None),
                ("gu3", "Active", "ann@client.com", "Accepted", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z", "2026-10-01T00:00:00Z")]
        return [{"id": i, "displayName": n, "mail": m, "userPrincipalName": m.replace("@", "_") + "#EXT#@t.onmicrosoft.com",
                 "accountEnabled": True, "createdDateTime": c, "externalUserState": st, "externalUserStateChangeDateTime": ch,
                 "userType": "Guest", **({"signInActivity": {"lastSignInDateTime": last} if last else None} if with_sign_in else {})}
                for i, n, m, st, c, ch, last in rows]

    def guest_memberships(self, uid):
        self.calls.append(f"gm:{uid}")
        self._check("memberships")
        team = {"id": "gt", "displayName": "Project Atlas", "groupTypes": ["Unified"], "resourceProvisioningOptions": ["Team"]}
        sec = {"id": "gs", "displayName": "Partners", "groupTypes": [], "resourceProvisioningOptions": []}
        return {"gu1": [sec, team], "gu2": [], "gu3": [sec]}.get(uid, [])

    def list_skus(self):
        self._check("skus")
        return [{"skuId": "sku-e3", "skuPartNumber": "SPE_E3"}, {"skuId": "sku-free", "skuPartNumber": "FLOW_FREE"}]

    def list_members(self, with_sign_in=False):
        self.member_calls.append(with_sign_in)
        self._check("members")
        if with_sign_in:
            self._check("member_signins")
        rows = [("mem1", "Gone Gary", False, True, ["sku-e3", "sku-free"], "2020-01-01T00:00:00Z", "2022-05-01T00:00:00Z"),
                ("mem2", "Idle Ivan", True, False, ["sku-e3"], "2020-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
                ("mem3", "Ghost Gina", True, True, [], "2020-01-01T00:00:00Z", None),
                ("mem4", "Active Alice", True, False, ["sku-e3"], "2020-01-01T00:00:00Z", "2026-10-20T00:00:00Z"),
                ("mem5", "Free Fred", False, False, ["sku-free"], "2020-01-01T00:00:00Z", "2022-01-01T00:00:00Z")]
        return [{"id": i, "displayName": n, "mail": n.split()[0].lower() + "@x.com", "userPrincipalName": n.split()[0].lower() + "@x.com",
                 "accountEnabled": en, "onPremisesSyncEnabled": sy or None, "createdDateTime": c, "userType": "Member",
                 "assignedLicenses": [{"skuId": s} for s in lic],
                 **({"signInActivity": {"lastSignInDateTime": last} if last else None} if with_sign_in else {})}
                for i, n, en, sy, lic, c, last in rows]

    def list_deleted_service_principals(self):
        return [{"id": "sp-gone", "deletedDateTime": "2026-09-01T00:00:00Z"}]

    def list_conditional_access_policies(self):
        self._check("policies")
        return [{"id": "ca1", "displayName": "Require MFA", "state": "enabled",
                 "conditions": {"users": {"includeGroups": ["g-ok"], "excludeGroups": ["g-win-2"]}}}]

    def list_with_assignments(self, api, path):
        self._check("intune:" + path)
        if path.endswith("mobileApps"):
            return [{"id": "ma3", "displayName": "7-Zip 22", "@odata.type": "#microsoft.graph.win32LobApp", "assignments": []},
                    {"id": "ma4", "displayName": "VC runtime", "@odata.type": "#microsoft.graph.win32LobApp", "assignments": []},
                    {"id": "ma1", "displayName": "Adobe 2024 Uninstall", "@odata.type": "#microsoft.graph.win32LobApp",
                     "createdDateTime": "2024-10-30T00:00:00Z", "assignments": [
                {"intent": "uninstall", "target": {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": "g-win-1"}},
                {"intent": "required", "target": {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}}]},
                    {"id": "ma2", "displayName": "Old Reader", "@odata.type": "#microsoft.graph.win32LobApp", "assignments": [
                {"intent": "uninstall", "target": {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": "g-win-1"}},
                {"intent": "required", "target": {"@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget", "groupId": "g-win-2"}}]}]
        if path.endswith("deviceManagementScripts"):
            return [{"id": "ps1", "displayName": "Old fix", "createdDateTime": "2021-03-01T00:00:00Z",
                     "lastModifiedDateTime": "2021-03-02T00:00:00Z", "assignments": [
                         {"target": {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": "g-win-1"}}]}]
        if path.endswith("deviceHealthScripts"):
            return [{"id": "hs1", "displayName": "Detect thing", "lastModifiedDateTime": "2025-01-01T00:00:00Z", "assignments": [
                {"target": {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": "g-win-2"}}]}]
        if path.endswith("configurationPolicies"):
            return [{"id": "sc1", "name": "Kiosk policy", "assignments": [
                {"target": {"@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget", "groupId": "g-win-2"}}]}]
        return []

    def app_relationships(self, app_id):
        self.calls.append(f"rels:{app_id}")
        self._check("relationships")
        dep, sup = "#microsoft.graph.mobileAppDependency", "#microsoft.graph.mobileAppSupersedence"
        return {"ma3": [{"@odata.type": sup, "targetType": "parent", "targetId": "ma1", "targetDisplayName": "Adobe 2024 Uninstall",
                         "supersedenceType": "replace"}],
                "ma4": [{"@odata.type": dep, "targetType": "parent", "targetId": "ma1", "targetDisplayName": "Adobe 2024 Uninstall",
                         "dependencyType": "autoInstall"}]}.get(app_id, [])

    def script_run_summary(self, path, sid):
        self.calls.append(f"runs:{sid}")
        self._check("runs")
        if sid == "missing":
            raise GraphError(404, path, "{}")
        return {"ps1": {"successDeviceCount": 0, "errorDeviceCount": 535, "@odata.context": "x"},
                "hs1": {"lastScriptRunDateTime": "2025-02-01T00:00:00Z"}}.get(sid, {})

    def group_member_of(self, gid):
        self.calls.append(f"parents:{gid}")
        return [{"id": "g-ok", "displayName": "Fine"}] if gid == "g-win-2" else []

    def list_groups(self):
        return list(self.groups)

    # --- per-object (scan)
    def application_owners(self, _id):
        self.calls.append(f"app_owners:{_id}")
        return []

    def get_service_principal_roles(self, _id):
        return {"appRoles": [{"id": "role-1", "value": "Directory.ReadWrite.All"}]}

    def sp_app_role_assignments(self, _id):
        return [{"id": "ara1", "resourceId": "sp-graph", "resourceDisplayName": "Microsoft Graph", "appRoleId": "role-1"}]

    def list_group_membership_audits(self, since):
        self._check("audits")
        self.audit_since = since
        return []

    def group_owners(self, gid):
        self.calls.append(f"owners:{gid}")
        return [] if gid == "g-priv" else [{"id": "u9", "displayName": "Owner"}]

    def group_member_count(self, gid):
        return 3

    def group_app_role_assignments(self, gid):
        if gid == "g-orphan":
            return [{"id": "a1", "resourceId": "sp-gone", "resourceDisplayName": "Deleted App", "appRoleId": "x"}]
        return []


@pytest.fixture()
def conn(tmp_path):
    c = sqlite3.connect(tmp_path / "t.sqlite")
    c.executescript(SCHEMA.read_text(encoding="utf-8"))
    yield c
    c.close()


def flags_for(conn, otype, oid):
    return {r[0] for r in conn.execute("SELECT flag FROM flags WHERE object_type=? AND object_id=?", (otype, oid))}


def scanned_groups(conn):
    return {r[0] for r in conn.execute("SELECT id FROM groups WHERE scanned_at IS NOT NULL")}


# ------------------------------------------------------------- inventory ----
def test_inventory_makes_no_per_object_calls_and_produces_no_group_or_app_flags(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    assert g.calls == []
    assert conn.execute("SELECT COUNT(*) FROM groups").fetchone()[0] == 5
    assert scanned_groups(conn) == set()
    assert conn.execute("SELECT COUNT(*) FROM flagged_objects WHERE object_type IN ('group','app')").fetchone()[0] == 0


def test_inventory_still_flags_dormant_privileged_user(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    assert flags_for(conn, "user", "u1") == {"DORMANT_PRIVILEGED_USER"}


# ------------------------------------------------------------------- scan ---
def test_scan_only_touches_matching_groups_plus_privileged(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_scan(conn, g, ALL_SCOPES, "win10-app-deployment*", "", now=NOW)
    assert scanned_groups(conn) == {"g-win-1", "g-win-2", "g-priv"}  # g-priv holds a directory role
    assert not any(c.endswith(("g-orphan", "g-ok")) for c in g.calls)
    assert "app_owners:ap-1" not in g.calls


def test_scans_accumulate(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_scan(conn, g, ALL_SCOPES, "win10-app-deployment*", "", now=NOW)
    run_scan(conn, g, ALL_SCOPES, "CRM*", "Old*", now=NOW)
    assert scanned_groups(conn) == {"g-win-1", "g-win-2", "g-priv", "g-orphan"}
    assert repo.scan_counts(conn)["apps_scanned"] == 1


def test_scan_produces_expected_flags_and_deletion_date(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_scan(conn, g, ALL_SCOPES, "*", "*", now=NOW)
    assert "ORPHANED_APP_ASSIGNMENT" in flags_for(conn, "group", "g-orphan")
    assert "PRIVILEGED_ORPHAN_GROUP" in flags_for(conn, "group", "g-priv")
    assert flags_for(conn, "group", "g-ok") == set()
    assert {"EXPIRED_SECRET", "STALE_APP", "LIKELY_ABANDONED_APP", "DANGEROUS_PERMISSION",
            "RISK_WITHOUT_USAGE"} <= flags_for(conn, "app", "ap-1")
    text = conn.execute("SELECT explanation FROM flags WHERE flag='ORPHANED_APP_ASSIGNMENT'").fetchone()[0]
    assert "2026-09-01" in text and "Deleted App" in text


def test_application_permissions_resolved_and_delegated_loaded(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    assert {r[0] for r in conn.execute("SELECT scope FROM permission_grants")} == {"Mail.Read", "User.Read"}
    run_scan(conn, g, ALL_SCOPES, "", "*", now=NOW)
    assert "Directory.ReadWrite.All" in {r[0] for r in conn.execute("SELECT scope FROM permission_grants")}


def test_reinventory_preserves_scan_data(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_scan(conn, g, ALL_SCOPES, "*", "*", now=NOW)
    run_inventory(conn, g, ALL_SCOPES, now=NOW + timedelta(days=1))
    assert len(scanned_groups(conn)) == 5
    assert "ORPHANED_APP_ASSIGNMENT" in flags_for(conn, "group", "g-orphan")
    assert "Directory.ReadWrite.All" in {r[0] for r in conn.execute("SELECT scope FROM permission_grants")}


def test_reinventory_removes_objects_deleted_in_tenant(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_scan(conn, g, ALL_SCOPES, "*", "", now=NOW)
    g.groups = [x for x in g.groups if x["id"] != "g-ok"]
    run_inventory(conn, g, ALL_SCOPES, now=NOW + timedelta(days=1))
    assert conn.execute("SELECT COUNT(*) FROM groups WHERE id='g-ok'").fetchone()[0] == 0


def test_denied_beta_endpoints_degrade_not_crash(conn):
    g = FakeGraph(deny={"sp_signins", "user_signins", "audits"})
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run = run_scan(conn, g, ALL_SCOPES, "*", "*", now=NOW)
    assert conn.execute("SELECT status FROM sync_runs WHERE id=?", (run,)).fetchone()[0] == "partial"
    sig = repo.signal_map(conn)
    assert not sig["sp_sign_in_activity"] and not sig["user_sign_in_activity"] and not sig["group_audit_activity"]
    app_flags = flags_for(conn, "app", "ap-1")
    assert "EXPIRED_SECRET" in app_flags and not ({"STALE_APP", "LIKELY_ABANDONED_APP"} & app_flags)
    assert flags_for(conn, "user", "u1") == set()


def test_missing_scope_skips_signal_without_calling_graph(conn):
    scopes = [s for s in ALL_SCOPES if s != "RoleManagement.Read.Directory"]
    run_inventory(conn, FakeGraph(deny={"roles"}), scopes, now=NOW)  # would raise if called
    reason = conn.execute("SELECT reason FROM signal_availability WHERE signal='role_assignments'").fetchone()[0]
    assert "RoleManagement.Read.Directory" in reason


def test_core_failure_marks_run_failed_and_raises(conn):
    class Broken(FakeGraph):
        def list_service_principals(self):
            raise GraphError(500, "x", "boom")

    with pytest.raises(GraphError):
        run_inventory(conn, Broken(), ALL_SCOPES, now=NOW)
    assert conn.execute("SELECT status FROM sync_runs").fetchone()[0] == "failed"
    assert repo.last_run(conn, "inventory") is None


# ---------------------------------------------------------------- preview ---
def test_preview_scope_counts_and_includes_privileged(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    p = repo.preview_scope(conn, "groups", "win10-app-deployment*")
    assert p["total"] == 5 and p["matched"] == 2 and p["selected"] == 3 and p["already_scanned"] == 0
    assert p["sample"] == ["win10-app-deployment-a", "win10-app-deployment-b"]


def test_scanning_apps_only_never_touches_groups_and_vice_versa(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_scan(conn, g, ALL_SCOPES, "", "*", now=NOW, kinds=("apps",))
    assert scanned_groups(conn) == set()  # not even the privileged group
    assert repo.scan_counts(conn)["apps_scanned"] == 1
    run_scan(conn, g, ALL_SCOPES, "win10-app-deployment*", "", now=NOW + timedelta(hours=1), kinds=("groups",))
    assert scanned_groups(conn) == {"g-win-1", "g-win-2", "g-priv"}
    assert repo.scan_counts(conn)["apps_scanned"] == 1  # untouched, kept


def test_role_names_come_from_role_definitions_and_audit_filter_is_z_format(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_scan(conn, g, ALL_SCOPES, "*", "", now=NOW)
    names = {r[0] for r in conn.execute("SELECT role_name FROM role_assignments")}
    assert names == {"Global Administrator", "User Administrator"}
    assert g.audit_since.endswith("Z") and "+" not in g.audit_since
    assert "User Administrator" in conn.execute(
        "SELECT explanation FROM flags WHERE flag='PRIVILEGED_ORPHAN_GROUP'").fetchone()[0]


def test_unavailable_reason_includes_graphs_own_message(conn):
    class Bad(FakeGraph):
        def list_role_assignments(self):
            raise GraphError(400, "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=x",
                             '{"error":{"message":"Expand is not supported"}}')

    run_inventory(conn, Bad(), ALL_SCOPES, now=NOW)
    reason = conn.execute("SELECT reason FROM signal_availability WHERE signal='role_assignments'").fetchone()[0]
    assert "400" in reason and "Expand is not supported" in reason


# ----------------------------------------------- where a group is used ---
def test_inventory_collects_ca_and_intune_references_with_names(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    rows = {(r["group_id"], r["source"], r["object_name"], r["mode"], r["detail"]) for r in conn.execute("SELECT * FROM group_usages")}
    assert ("g-ok", "policy_binding", "Require MFA", "include", "enabled") in rows
    assert ("g-win-2", "policy_binding", "Require MFA", "exclude", "enabled") in rows
    assert ("g-win-1", "intune_apps", "Adobe 2024 Uninstall", "assigned", "uninstall") in rows
    assert ("g-win-2", "intune_settings_catalog", "Kiosk policy", "exclude", None) in rows
    assert not any(r[0] is None for r in rows)  # 'all devices' style targets are not group references


def test_referenced_empty_ownerless_group_is_not_high(conn):
    g = FakeGraph()
    g.group_owners = lambda gid: []
    g.group_member_count = lambda gid: 0
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_scan(conn, g, ALL_SCOPES, "win10-app-deployment-a", "", now=NOW)
    risk = conn.execute("SELECT risk_level FROM flagged_objects WHERE object_id='g-win-1'").fetchone()[0]
    text = conn.execute("SELECT explanation FROM flags WHERE object_id='g-win-1' AND flag='EMPTY_GROUP'").fetchone()[0]
    assert risk == "MEDIUM" and "Adobe 2024 Uninstall" in text


def test_nesting_is_scanned_and_stored(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_scan(conn, g, ALL_SCOPES, "win10-app-deployment-b", "", now=NOW)
    assert conn.execute("SELECT parent_name FROM group_parents WHERE group_id='g-win-2'").fetchone()[0] == "Fine"
    assert conn.execute("SELECT parent_count FROM groups WHERE id='g-win-2'").fetchone()[0] == 1
    assert conn.execute("SELECT parent_count FROM groups WHERE id='g-orphan'").fetchone()[0] is None  # never scanned


def test_unreadable_intune_source_is_unchecked_not_unused(conn):
    g = FakeGraph(deny={"intune:/deviceAppManagement/mobileApps"})
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    cov = {r["label"]: r for r in repo.usage_coverage(conn, "g-win-1")}
    assert cov["Intune apps"]["status"] == "unchecked" and "403" in cov["Intune apps"]["reason"]
    assert cov["Conditional Access policies"]["status"] == "none"
    assert cov["Intune compliance policies"]["status"] == "none"  # read fine, nothing assigned


def test_missing_intune_scope_marks_sources_unchecked_without_calling_graph(conn):
    scopes = [s for s in ALL_SCOPES if not s.startswith("DeviceManagement")]
    g = FakeGraph(deny={"intune:/deviceAppManagement/mobileApps", "intune:/deviceManagement/deviceConfigurations"})
    run_inventory(conn, g, scopes, now=NOW)  # would raise if Graph were called for them
    cov = {r["label"]: r for r in repo.usage_coverage(conn, "g-win-1")}
    assert cov["Intune apps"]["status"] == "unchecked" and "DeviceManagementApps.Read.All" in cov["Intune apps"]["reason"]


def test_coverage_reports_found_items_and_scan_dependent_rows(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    before = {r["label"]: r for r in repo.usage_coverage(conn, "g-win-1")}
    assert before["Intune apps"]["status"] == "found" and "Adobe 2024 Uninstall (assigned, uninstall)" in before["Intune apps"]["items"]
    assert before["Member of other groups (nesting)"]["status"] == "unchecked"  # not scanned yet
    run_scan(conn, g, ALL_SCOPES, "win10-app-deployment-*", "", now=NOW)
    after = {r["label"]: r for r in repo.usage_coverage(conn, "g-win-2")}
    assert after["Member of other groups (nesting)"]["status"] == "found" and after["Member of other groups (nesting)"]["items"] == ["Fine"]


def test_audit_window_is_clamped_to_the_logs_retention(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_scan(conn, g, ALL_SCOPES, "*", "", now=NOW)  # default stale threshold is 180 days
    assert g.audit_since == (NOW - timedelta(days=29)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_audit_retries_with_a_shorter_window_when_graph_names_a_minimum_time(conn):
    class ShortRetention(FakeGraph):
        calls_since: list = []

        def list_group_membership_audits(self, since):
            self.calls_since.append(since)
            if len(self.calls_since) == 1:
                raise GraphError(400, "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits",
                                 '{"error":{"message":"Minimum allowed time for activityDateTime is 10/19/2026"}}')
            return []

    g = ShortRetention()
    g.calls_since = []
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_scan(conn, g, ALL_SCOPES, "*", "", now=NOW)
    assert len(g.calls_since) == 2 and g.calls_since[1] == (NOW - timedelta(days=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert repo.signal_map(conn)["group_audit_activity"] is True


def test_other_audit_400s_are_still_reported_as_unavailable(conn):
    class Bad(FakeGraph):
        def list_group_membership_audits(self, since):
            raise GraphError(400, "u", '{"error":{"message":"Invalid filter clause"}}')

    g = Bad()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_scan(conn, g, ALL_SCOPES, "*", "", now=NOW)
    assert repo.signal_map(conn)["group_audit_activity"] is False


# ------------------------------------------------------------ Intune apps ---
def test_inventory_stores_intune_apps_and_all_target_kinds(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    assert conn.execute("SELECT COUNT(*) FROM intune_apps").fetchone()[0] == 4
    rows = {tuple(r) for r in conn.execute("SELECT app_id, target, group_id, mode, intent FROM intune_app_assignments")}
    assert ("ma1", "all_devices", "", "include", "required") in rows
    assert ("ma1", "group", "g-win-1", "include", "uninstall") in rows
    assert ("ma2", "group", "g-win-2", "exclude", "required") in rows


def test_uninstall_only_app_is_flagged_at_inventory_without_any_scan(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    flagged = {r["object_id"]: r["risk_level"] for r in conn.execute("SELECT * FROM flagged_objects WHERE object_type='intune_app'")}
    # ma1 also installs on all devices; ma2's only install target is an exclusion. ma3 and ma4 are unassigned, but
    # whether they are old versions or dependencies is only known after their relations are checked on demand.
    assert flagged == {"ma2": "MEDIUM"}
    assert g.calls == []
    text = conn.execute("SELECT explanation FROM flags WHERE object_id='ma2'").fetchone()[0]
    assert "members unknown: group not scanned" in text  # nothing scanned yet: disclosed, not guessed


def test_scanning_the_target_group_fills_in_its_member_count(conn):
    g = FakeGraph()
    g.group_member_count = lambda gid: 0
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_scan(conn, g, ALL_SCOPES, "win10-app-deployment-a", "", now=NOW)
    text = conn.execute("SELECT explanation FROM flags WHERE object_id='ma2'").fetchone()[0]
    assert "'win10-app-deployment-a' (0 members)" in text and "1 of 1 target group(s) are empty" in text


def test_reinventory_replaces_intune_apps(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    g.list_with_assignments = lambda api, path: []
    run_inventory(conn, g, ALL_SCOPES, now=NOW + timedelta(days=1))
    assert conn.execute("SELECT COUNT(*) FROM intune_apps").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM intune_app_assignments").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM flagged_objects WHERE object_type='intune_app'").fetchone()[0] == 0


# ----------------------------------- relations are checked on demand only ---
def check(conn, g, apps="*", scripts="*", kinds=("intune", "scripts")):
    return run_scan(conn, g, ALL_SCOPES, "", "", now=NOW, kinds=kinds, intune_patterns=apps, script_patterns=scripts)


def flagged_intune(conn, otype):
    return {r["object_id"]: r["risk_level"] for r in conn.execute("SELECT * FROM flagged_objects WHERE object_type=?", (otype,))}


def test_inventory_never_reads_relationships_or_run_results(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    assert g.calls == []  # not one per-object call
    assert conn.execute("SELECT COUNT(*) FROM intune_app_relationships").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM intune_scripts WHERE run_json IS NOT NULL OR scanned_at IS NOT NULL").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM intune_apps WHERE scanned_at IS NOT NULL").fetchone()[0] == 0


def test_unchecked_unassigned_apps_are_not_flagged_yet(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    assert flagged_intune(conn, "intune_app") == {"ma2": "MEDIUM"}  # only the uninstall-only app, which needs no check


def test_checking_apps_touches_only_the_selected_ones(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check(conn, g, apps="7-Zip 22", kinds=("intune",))
    assert g.calls == ["rels:ma3"]
    assert {r[0] for r in conn.execute("SELECT app_id FROM intune_app_relationships")} == {"ma3"}
    assert flagged_intune(conn, "intune_app") == {"ma2": "MEDIUM", "ma3": "MEDIUM"}  # ma4 not checked: still unflagged
    assert repo.scan_counts(conn)["intune_scanned"] == 1


def test_checked_unassigned_apps_split_into_old_version_dependency_and_unused(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check(conn, g, kinds=("intune",))
    assert flagged_intune(conn, "intune_app") == {"ma2": "MEDIUM", "ma3": "MEDIUM"}  # ma4 is a dependency: not flagged
    text = conn.execute("SELECT explanation FROM flags WHERE object_id='ma3'").fetchone()[0]
    assert "superseded by 'Adobe 2024 Uninstall' (assigned)" in text
    rows = {(r["app_id"], r["kind"], r["role"], r["detail"]) for r in conn.execute("SELECT * FROM intune_app_relationships")}
    assert ("ma3", "supersedence", "parent", "replace") in rows and ("ma4", "dependency", "parent", "autoInstall") in rows


def test_unreadable_relationships_are_disclosed_and_never_escalate(conn):
    g = FakeGraph(deny={"relationships"})
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check(conn, g, kinds=("intune",))
    assert repo.signal_map(conn)["intune_app_relationships"] is False
    assert flagged_intune(conn, "intune_app")["ma3"] == "LOW" and flagged_intune(conn, "intune_app")["ma4"] == "LOW"
    assert "could not be read" in conn.execute("SELECT explanation FROM flags WHERE object_id='ma4'").fetchone()[0]


def test_inventory_alone_flags_stale_scripts_but_not_failing_or_idle(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    codes = {r[0] for r in conn.execute("SELECT flag FROM flags WHERE object_id='ps1'")}
    assert codes == {"STALE_SCRIPT"}  # failing / obsolete need the run results
    assert conn.execute("SELECT COUNT(*) FROM flags WHERE object_id='hs1'").fetchone()[0] == 0


def test_checking_scripts_reads_only_the_selected_ones_and_adds_run_based_flags(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check(conn, g, scripts="Old fix", kinds=("scripts",))
    assert g.calls == ["runs:ps1"]
    assert conn.execute("SELECT run_json FROM intune_scripts WHERE id='hs1'").fetchone()[0] is None
    run = conn.execute("SELECT run_json FROM intune_scripts WHERE id='ps1'").fetchone()[0]
    assert '"errorDeviceCount": 535' in run and "@odata.context" not in run
    codes = {r[0] for r in conn.execute("SELECT flag FROM flags WHERE object_id='ps1'")}
    assert {"FAILING_SCRIPT", "STALE_SCRIPT", "LIKELY_OBSOLETE_SCRIPT"} <= codes
    assert "failed 535 time(s)" in conn.execute("SELECT explanation FROM flags WHERE object_id='ps1' AND flag='LIKELY_OBSOLETE_SCRIPT'").fetchone()[0]


def test_idle_remediation_appears_after_its_run_results_are_read(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check(conn, g, kinds=("scripts",))
    text = conn.execute("SELECT explanation FROM flags WHERE object_id='hs1' AND flag='IDLE_REMEDIATION'").fetchone()[0]
    assert "last ran on 2025-02-01" in text


def test_unreadable_run_results_skip_failing_and_idle_with_a_note(conn):
    g = FakeGraph(deny={"runs"})
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check(conn, g, kinds=("scripts",))
    assert repo.signal_map(conn)["intune_script_runs"] is False
    codes = {r[0] for r in conn.execute("SELECT flag FROM flags WHERE object_id IN ('ps1','hs1')")}
    assert "FAILING_SCRIPT" not in codes and "IDLE_REMEDIATION" not in codes and "STALE_SCRIPT" in codes


def test_reinventory_keeps_what_was_checked(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check(conn, g)
    g.calls.clear()
    run_inventory(conn, g, ALL_SCOPES, now=NOW + timedelta(days=1))
    assert g.calls == []  # still no per-object calls
    assert conn.execute("SELECT COUNT(*) FROM intune_app_relationships").fetchone()[0] > 0
    assert conn.execute("SELECT COUNT(*) FROM intune_scripts WHERE run_json IS NOT NULL AND scanned_at IS NOT NULL").fetchone()[0] == 2
    assert repo.scan_counts(conn)["intune_scanned"] == 4
    assert "FAILING_SCRIPT" in {r[0] for r in conn.execute("SELECT flag FROM flags WHERE object_id='ps1'")}
    assert flagged_intune(conn, "intune_app")["ma3"] == "MEDIUM"


def test_a_list_that_cannot_be_read_does_not_wipe_what_was_stored(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check(conn, g)
    run_inventory(conn, FakeGraph(deny={"intune:/deviceAppManagement/mobileApps", "intune:/deviceManagement/deviceManagementScripts"}),
                  ALL_SCOPES, now=NOW + timedelta(days=1))
    assert conn.execute("SELECT COUNT(*) FROM intune_apps").fetchone()[0] == 4
    assert conn.execute("SELECT COUNT(*) FROM intune_app_relationships").fetchone()[0] > 0
    assert conn.execute("SELECT COUNT(*) FROM intune_scripts WHERE kind='powershell'").fetchone()[0] == 1


def test_reinventory_removes_apps_and_scripts_that_left_the_tenant_with_their_data(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check(conn, g)
    g.list_with_assignments = lambda api, path: []
    run_inventory(conn, g, ALL_SCOPES, now=NOW + timedelta(days=1))
    for table in ("intune_apps", "intune_app_assignments", "intune_app_relationships", "intune_scripts", "intune_script_assignments"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table
    assert conn.execute("SELECT COUNT(*) FROM flagged_objects WHERE object_type IN ('intune_app','intune_script')").fetchone()[0] == 0


def test_script_targets_are_group_references_for_every_script_kind(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    rows = {(r["group_id"], r["source"], r["object_name"]) for r in conn.execute("SELECT * FROM group_usages")}
    assert ("g-win-1", "intune_scripts", "Old fix") in rows and ("g-win-2", "intune_remediations", "Detect thing") in rows


def test_scope_selection_and_preview_work_for_intune_apps_and_scripts(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    assert repo.preview_scope(conn, "intune", "7-Zip*")["matched"] == 1 and repo.preview_scope(conn, "intune", "*")["total"] == 4
    assert repo.select_scope_ids(conn, "scripts", "Old*") == ["ps1"]
    assert repo.select_scope_ids(conn, "intune", "") == []


def test_patterns_are_saved_per_kind(conn):
    repo.save_scope_patterns(conn, "intune", "7-Zip*")
    repo.save_scope_patterns(conn, "scripts", "Old*")
    assert repo.get_scope_patterns(conn) == {"groups": "", "apps": "", "intune": "7-Zip*", "scripts": "Old*", "guests": "", "dls": "", "mailboxes": ""}


# ------------------------------------------------ users are looked up in batches ---
class ManyAdmins(FakeGraph):
    def list_role_assignments(self):
        return [{"id": f"r{i}", "principalId": f"u{i:02d}", "roleDefinitionId": "rd-ga",
                 "principal": {"@odata.type": "#microsoft.graph.user"}} for i in range(20)]


def test_privileged_users_are_looked_up_in_batches_of_fifteen_never_one_by_one(conn):
    g = ManyAdmins()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    assert g.user_calls == [(15, True), (5, True)]  # 20 users, 2 calls, sign-in activity included
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 20
    assert conn.execute("SELECT COUNT(*) FROM sign_in_activity WHERE object_type='user'").fetchone()[0] == 20


def test_user_names_still_load_when_sign_in_activity_is_unreadable(conn):
    g = ManyAdmins(deny={"user_signins"})
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    assert g.user_calls == [(15, True), (15, False), (5, False)]  # first batch discovers it, the rest skip the beta call
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 20
    assert conn.execute("SELECT COUNT(*) FROM sign_in_activity WHERE object_type='user'").fetchone()[0] == 0
    assert repo.signal_map(conn)["user_sign_in_activity"] is False


def test_user_without_sign_in_activity_in_the_response_means_no_sign_in_on_record(conn):
    class NeverSignedIn(FakeGraph):
        def users_by_ids(self, ids, with_sign_in=False):
            return [{"id": u, "displayName": "New", "signInActivity": None} for u in ids]

    run_inventory(conn, NeverSignedIn(), ALL_SCOPES, now=NOW)
    assert tuple(conn.execute("SELECT last_sign_in_at FROM sign_in_activity WHERE object_id='u1'").fetchone()) == (None,)
    assert "DORMANT_PRIVILEGED_USER" in {r[0] for r in conn.execute("SELECT flag FROM flags WHERE object_id='u1'")}


def test_account_state_flows_from_graph_to_the_flag(conn):
    class DisabledAdmin(FakeGraph):
        def users_by_ids(self, ids, with_sign_in=False):
            return [{"id": u, "displayName": "Jim", "accountEnabled": False,
                     "signInActivity": {"lastSignInDateTime": "2025-03-17T00:00:00Z"}} for u in ids]

    run_inventory(conn, DisabledAdmin(), ALL_SCOPES, now=NOW)
    assert conn.execute("SELECT account_enabled FROM users WHERE id='u1'").fetchone()[0] == 0
    risk = conn.execute("SELECT risk_level FROM flagged_objects WHERE object_id='u1'").fetchone()[0]
    text = conn.execute("SELECT explanation FROM flags WHERE object_id='u1'").fetchone()[0]
    assert risk == "MEDIUM" and text.startswith("Disabled account")
    assert [r[0] for r in conn.execute("SELECT flag FROM flags WHERE object_id='u1'")] == ["DISABLED_PRIVILEGED_USER"]


# ------------------------------------------------------------ external guests ---
def guest_flags(conn):
    return {r["object_id"]: (r["risk_level"], r["flag"]) for r in conn.execute(
        "SELECT o.object_id, o.risk_level, f.flag FROM flagged_objects o JOIN flags f ON f.object_id = o.object_id AND f.object_type = o.object_type "
        "WHERE o.object_type = 'guest'")}


def test_guests_are_read_as_one_paged_list_with_sign_in_and_flagged(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    assert g.guest_calls == [True]  # one list, sign-in activity included, no per-guest call
    assert conn.execute("SELECT COUNT(*) FROM guests").fetchone()[0] == 3
    assert guest_flags(conn) == {"gu1": ("MEDIUM", "STALE_GUEST"), "gu2": ("LOW", "PENDING_GUEST")}  # gu3 signed in recently


def test_guest_sign_in_uses_the_newest_of_the_activity_dates(conn):
    class Newest(FakeGraph):
        def list_guests(self, with_sign_in=False):
            return [{"id": "gx", "displayName": "X", "userType": "Guest", "accountEnabled": True, "createdDateTime": "2020-01-01T00:00:00Z",
                     "externalUserState": "Accepted", "signInActivity": {"lastSignInDateTime": "2021-01-01T00:00:00Z",
                                                                       "lastNonInteractiveSignInDateTime": "2026-10-20T00:00:00Z"}}]

    run_inventory(conn, Newest(), ALL_SCOPES, now=NOW)
    assert conn.execute("SELECT last_sign_in_at FROM guests").fetchone()[0] == "2026-10-20T00:00:00Z"
    assert guest_flags(conn) == {}  # active 5 days ago through a non-interactive sign-in


def test_guests_still_load_without_sign_in_activity_and_stale_is_not_guessed(conn):
    g = FakeGraph(deny={"guest_signins"})
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    assert g.guest_calls == [True, False]
    assert conn.execute("SELECT COUNT(*) FROM guests WHERE sign_in_known = 0").fetchone()[0] == 3
    assert repo.signal_map(conn)["guest_sign_in_activity"] is False
    assert guest_flags(conn) == {"gu2": ("LOW", "PENDING_GUEST")}  # pending needs no sign-in data; stale does


def test_an_unreadable_guest_list_keeps_what_was_stored(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    run_inventory(conn, FakeGraph(deny={"guests"}), ALL_SCOPES, now=NOW + timedelta(days=1))
    assert conn.execute("SELECT COUNT(*) FROM guests").fetchone()[0] == 3
    assert repo.signal_map(conn)["guests"] is False


def test_guests_who_left_the_tenant_disappear_on_the_next_inventory(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    g.list_guests = lambda with_sign_in=False: []
    run_inventory(conn, g, ALL_SCOPES, now=NOW + timedelta(days=1))
    assert conn.execute("SELECT COUNT(*) FROM guests").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM flagged_objects WHERE object_type = 'guest'").fetchone()[0] == 0


def test_external_admin_flows_from_graph_to_the_flag(conn):
    class GuestAdmin(FakeGraph):
        def users_by_ids(self, ids, with_sign_in=False):
            return [{"id": u, "displayName": "Ext", "userType": "Guest", "accountEnabled": True,
                     "signInActivity": {"lastSignInDateTime": "2026-10-20T00:00:00Z"}} for u in ids]

    run_inventory(conn, GuestAdmin(), ALL_SCOPES, now=NOW)
    assert conn.execute("SELECT user_type FROM users WHERE id='u1'").fetchone()[0] == "Guest"
    assert {r[0] for r in conn.execute("SELECT flag FROM flags WHERE object_id='u1'")} == {"EXTERNAL_PRIVILEGED_USER"}


# --------------------------------------------- guest memberships, on demand ---
def check_guests(conn, g, patterns, now=NOW):
    return run_scan(conn, g, ALL_SCOPES, "", "", now=now, kinds=("guests",), guest_patterns=patterns)


def test_inventory_never_reads_guest_memberships(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    assert not any(c.startswith("gm:") for c in g.calls)
    assert conn.execute("SELECT COUNT(*) FROM guest_memberships").fetchone()[0] == 0
    assert repo.scan_counts(conn)["guests_total"] == 3 and repo.scan_counts(conn)["guests_scanned"] == 0
    assert "member of" not in conn.execute("SELECT explanation FROM flags WHERE object_id='gu1'").fetchone()[0]


def test_guests_are_selected_by_company_domain_email_or_name_and_only_those_are_read(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check_guests(conn, g, "partner.com")
    assert [c for c in g.calls if c.startswith("gm:")] == ["gm:gu1"]
    g.calls.clear()
    check_guests(conn, g, "*@supplies.com")
    assert g.calls == ["gm:gu2"]
    g.calls.clear()
    check_guests(conn, g, "Active")
    assert g.calls == ["gm:gu3"]
    g.calls.clear()
    check_guests(conn, g, "*\n!Sam*\n!partner.com")
    assert g.calls == ["gm:gu3"]  # exclusions apply to name, e-mail and domain


def test_checked_guest_explanation_names_groups_and_teams(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check_guests(conn, g, "partner.com")
    text = conn.execute("SELECT explanation FROM flags WHERE object_id='gu1'").fetchone()[0]
    assert "still a member of 2 group(s) by assignment: 'Project Atlas' (Team), 'Partners'" in text
    rows = {(r["group_name"], r["kind"]) for r in conn.execute("SELECT * FROM guest_memberships WHERE guest_id='gu1'")}
    assert rows == {("Project Atlas", "team"), ("Partners", "security")}
    check_guests(conn, g, "supplies.com")
    assert "member of no group" in conn.execute("SELECT explanation FROM flags WHERE object_id='gu2'").fetchone()[0]


def test_what_was_checked_survives_a_reinventory(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check_guests(conn, g, "partner.com")
    g.calls.clear()
    run_inventory(conn, g, ALL_SCOPES, now=NOW + timedelta(days=1))
    assert not any(c.startswith("gm:") for c in g.calls)
    assert conn.execute("SELECT COUNT(*) FROM guest_memberships WHERE guest_id='gu1'").fetchone()[0] == 2
    assert repo.scan_counts(conn)["guests_scanned"] == 1
    assert "'Project Atlas' (Team)" in conn.execute("SELECT explanation FROM flags WHERE object_id='gu1'").fetchone()[0]


def test_a_guest_who_left_takes_its_memberships_with_it(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check_guests(conn, g, "*")
    g.list_guests = lambda with_sign_in=False: []
    run_inventory(conn, g, ALL_SCOPES, now=NOW + timedelta(days=1))
    assert conn.execute("SELECT COUNT(*) FROM guest_memberships").fetchone()[0] == 0


def test_unreadable_memberships_are_disclosed_and_the_finding_is_unchanged(conn):
    g = FakeGraph(deny={"memberships"})
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check_guests(conn, g, "partner.com")
    assert repo.signal_map(conn)["guest_memberships"] is False
    assert "member of" not in conn.execute("SELECT explanation FROM flags WHERE object_id='gu1'").fetchone()[0]
    assert conn.execute("SELECT risk_level FROM flagged_objects WHERE object_id='gu1'").fetchone()[0] == "MEDIUM"


def test_guest_scope_preview_counts_and_samples(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    p = repo.preview_scope(conn, "guests", "partner.com")
    assert p["total"] == 3 and p["matched"] == 1 and p["sample"] == ["Old Pat"]
    assert repo.select_scope_ids(conn, "guests", "") == []


def test_dynamic_groups_are_recognised_from_the_inventory_rule(conn):
    class WithDynamic(FakeGraph):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.groups[2]["membershipRule"] = "user.accountEnabled -eq true"   # g-ok becomes a dynamic group

        def guest_memberships(self, uid):
            return [{"id": "g-ok", "displayName": "Everyone", "groupTypes": [], "securityEnabled": True},
                    {"id": "gs", "displayName": "Partners", "groupTypes": [], "resourceProvisioningOptions": []}]

    g = WithDynamic()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    check_guests(conn, g, "partner.com")
    text = conn.execute("SELECT explanation FROM flags WHERE object_id='gu1'").fetchone()[0]
    assert "by assignment: 'Partners'" in text and "also in 1 dynamic (rule-based) group(s) such as 'Everyone'" in text


# ------------------------------------------------------------ internal users ---
def member_flags(conn):
    out = {}
    for r in conn.execute("SELECT o.object_id, o.risk_level, f.flag FROM flagged_objects o JOIN flags f ON f.object_id = o.object_id "
                          "AND f.object_type = o.object_type WHERE o.object_type = 'member'"):
        out[r["object_id"]] = (r["risk_level"], r["flag"])
    return out


def test_members_are_read_as_one_paged_list_with_licences_by_name(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    assert g.member_calls == [True]  # one list, sign-in activity included, no per-user call
    assert conn.execute("SELECT COUNT(*) FROM members").fetchone()[0] == 5
    assert conn.execute("SELECT licences FROM members WHERE id='mem1'").fetchone()[0] == '["FLOW_FREE", "SPE_E3"]'
    assert conn.execute("SELECT on_prem_synced FROM members WHERE id='mem3'").fetchone()[0] == 1


def test_disabled_licensed_stale_and_never_signed_in_accounts_are_flagged_and_the_rest_are_not(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    assert member_flags(conn) == {"mem1": ("MEDIUM", "DISABLED_LICENSED_MEMBER"), "mem2": ("MEDIUM", "STALE_MEMBER"),
                                  "mem3": ("LOW", "STALE_MEMBER")}  # mem4 active; mem5 is disabled but holds only a free licence


def test_member_explanations_name_the_licences_and_the_ad_sync(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    text = conn.execute("SELECT explanation FROM flags WHERE object_id='mem1'").fetchone()[0]
    assert "paid licence(s): SPE_E3" in text and "FLOW_FREE" not in text and "synced from on-premises Active Directory" in text
    never = conn.execute("SELECT explanation FROM flags WHERE object_id='mem3'").fetchone()[0]
    assert "no sign-in on record" in never and "holds no paid licence" in never and "synced from on-premises" in never


def test_licence_ids_are_kept_when_the_sku_list_cannot_be_read(conn):
    run_inventory(conn, FakeGraph(deny={"skus"}), ALL_SCOPES, now=NOW)
    assert repo.signal_map(conn)["license_skus"] is False
    assert "sku-e3" in conn.execute("SELECT licences FROM members WHERE id='mem2'").fetchone()[0]


def test_members_still_load_without_sign_in_activity_and_stale_is_not_guessed(conn):
    g = FakeGraph(deny={"member_signins"})
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    assert g.member_calls == [True, False] and repo.signal_map(conn)["member_sign_in_activity"] is False
    assert member_flags(conn) == {"mem1": ("MEDIUM", "DISABLED_LICENSED_MEMBER")}  # disabled+licensed needs no sign-in data


def test_an_unreadable_member_list_keeps_what_was_stored_and_leavers_disappear(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW)
    run_inventory(conn, FakeGraph(deny={"members"}), ALL_SCOPES, now=NOW + timedelta(days=1))
    assert conn.execute("SELECT COUNT(*) FROM members").fetchone()[0] == 5 and repo.signal_map(conn)["members"] is False
    g.list_members = lambda with_sign_in=False: []
    run_inventory(conn, g, ALL_SCOPES, now=NOW + timedelta(days=2))
    assert conn.execute("SELECT COUNT(*) FROM members").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM flagged_objects WHERE object_type = 'member'").fetchone()[0] == 0


# ------------------------------------------------------------- Exchange ---
def _dl(oid, name, addr, owners=("Owner",), synced=False, created="2019-01-01T00:00:00Z", changed="2021-01-01T00:00:00Z", kind="MailUniversalDistributionGroup"):
    return {"ExternalDirectoryObjectId": oid, "DisplayName": name, "PrimarySmtpAddress": addr, "ManagedBy": list(owners), "WhenCreated": created,
            "WhenChanged": changed, "IsDirSynced": synced, "HiddenFromAddressListsEnabled": False, "RecipientTypeDetails": kind}


class FakeExchange:
    """Read-only stand-in for ExchangeClient. `deny` makes the named reads raise 403; `calls` records every read."""

    def __init__(self, deny=()):
        self.deny, self.calls = set(deny), []

    def _check(self, name):
        if name in self.deny:
            raise SignalUnavailable(403, name, "denied")

    def distribution_groups(self):
        self.calls.append("lists")
        self._check("lists")
        return [_dl("dl1", "Sales Team", "sales@x.com"), _dl("dl2", "Old Project", "old@x.com", owners=()),
                _dl("dl3", "Finance", "fin@x.com"), _dl("dl4", "Secure Mail", "sec@x.com", kind="MailUniversalSecurityGroup")]

    def dynamic_distribution_groups(self):
        self.calls.append("dynamic")
        return [_dl("dd1", "Everyone", "everyone@x.com", synced=True)]

    def transport_rules(self):
        self.calls.append("rules")
        self._check("rules")
        return [{"Name": "Archive finance", "SentToMemberOf": ["fin@x.com"], "Description": "if sent to fin@x.com then archive", "Identity": "Archive finance"}]

    def mailboxes(self, types=None):
        self.calls.append("mailboxes")
        self._check("mailboxes")
        return [{"ExternalDirectoryObjectId": "mem5", "RecipientTypeDetails": "SharedMailbox", "DisplayName": "Free Fred",
                 "PrimarySmtpAddress": "fred@x.com", "WhenCreated": "2020-01-01T00:00:00Z"}]

    def accepted_domains(self):
        self.calls.append("domains")
        self._check("domains")
        return ["x.com"]

    stats = {"LastLogonTime": "2023-01-01T00:00:00", "ItemCount": 9}
    perms = [{"User": "NT AUTHORITY\\SELF", "AccessRights": ["FullAccess, ReadPermission"], "IsInherited": False, "Deny": False},
             {"User": "gone@x.com", "AccessRights": ["FullAccess"], "IsInherited": False, "Deny": False}]
    sendas = []

    def mailbox_statistics(self, identity):
        self.calls.append(f"stats:{identity}")
        self._check("stats")
        return self.stats

    def mailbox_permissions(self, identity):
        self.calls.append(f"perms:{identity}")
        self._check("perms")
        return self.perms

    def recipient_permissions(self, identity):
        self.calls.append(f"sendas:{identity}")
        return self.sendas

    def member_count(self, identity, dynamic=False):
        self.calls.append(f"members:{identity}:{'dynamic' if dynamic else 'static'}")
        self._check("members")
        return {"sales@x.com": 5, "old@x.com": 0, "fin@x.com": 4, "sec@x.com": 2, "everyone@x.com": 100}[identity]

    def last_mail_received(self, address, now=None):
        self.calls.append(f"trace:{address}")
        self._check("trace")
        return {"sales@x.com": NOW - timedelta(days=2)}.get(address)


def check_lists(conn, graph, ex, patterns, kinds=("dls",)):
    return run_scan(conn, graph, ALL_SCOPES, "", "", now=NOW, kinds=kinds, dl_patterns=patterns, exchange=ex)


def list_flags(conn):
    out = {}
    for r in conn.execute("SELECT f.object_id, f.flag FROM flags f WHERE f.object_type = 'dl'"):
        out.setdefault(r["object_id"], set()).add(r["flag"])
    return out


def test_inventory_reads_the_lists_and_the_rules_in_three_calls_and_nothing_per_list(conn):
    ex = FakeExchange()
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW, exchange=ex)
    assert ex.calls == ["lists", "dynamic", "rules", "domains"]
    assert conn.execute("SELECT COUNT(*) FROM distribution_lists").fetchone()[0] == 5
    assert {r[0]: r[1] for r in conn.execute("SELECT id, kind FROM distribution_lists")} == {
        "dl1": "distribution", "dl2": "distribution", "dl3": "distribution", "dl4": "security", "dd1": "dynamic"}
    assert conn.execute("SELECT synced FROM distribution_lists WHERE id='dd1'").fetchone()[0] == 1
    assert [tuple(r) for r in conn.execute("SELECT dl_id, rule_name, field FROM dl_rule_refs")] == [("dl3", "Archive finance", "SentToMemberOf")]


def test_inventory_without_exchange_just_skips_it(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    assert conn.execute("SELECT COUNT(*) FROM distribution_lists").fetchone()[0] == 0
    assert "exchange_distribution_lists" not in repo.signal_map(conn)


def test_without_the_exchange_permission_the_signals_are_unavailable_and_exchange_is_never_called(conn):
    ex = FakeExchange()
    scopes = [s for s in ALL_SCOPES if s != "Exchange.ManageAsApp"]
    run_inventory(conn, FakeGraph(), scopes, now=NOW, exchange=ex)
    assert ex.calls == [] and repo.signal_map(conn)["exchange_distribution_lists"] is False
    assert "Exchange.ManageAsApp" in conn.execute("SELECT reason FROM signal_availability WHERE signal='exchange_distribution_lists'").fetchone()[0]


def test_the_inventory_alone_only_finds_lists_without_an_owner(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW, exchange=FakeExchange())
    assert list_flags(conn) == {"dl2": {"DL_NO_OWNER"}}


def test_checking_reads_only_the_selected_lists_and_decides_unused_ones(conn):
    g, ex = FakeGraph(), FakeExchange()
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    ex.calls.clear()
    check_lists(conn, g, ex, "old@x.com\nfin@x.com\nsales@x.com")
    assert sorted(ex.calls) == sorted(["members:old@x.com:static", "trace:old@x.com", "members:fin@x.com:static", "trace:fin@x.com",
                                       "members:sales@x.com:static", "trace:sales@x.com"])
    assert list_flags(conn) == {"dl2": {"DL_NO_OWNER", "DL_EMPTY", "DL_NO_MAIL", "LIKELY_UNUSED_DL"},   # empty, ownerless, no mail, no rule
                                "dl3": {"DL_NO_MAIL"}}                                                   # no mail but a rule mentions it
    assert conn.execute("SELECT last_mail_at FROM distribution_lists WHERE id='dl1'").fetchone()[0] is not None
    assert repo.scan_counts(conn)["dls_scanned"] == 3 and repo.scan_counts(conn)["dls_total"] == 5


def test_lists_are_matched_by_name_or_address_and_dynamic_ones_use_the_dynamic_cmdlet(conn):
    g, ex = FakeGraph(), FakeExchange()
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    ex.calls.clear()
    check_lists(conn, g, ex, "Everyone")
    assert "members:everyone@x.com:dynamic" in ex.calls and "trace:everyone@x.com" in ex.calls
    ex.calls.clear()
    check_lists(conn, g, ex, "*@x.com\n!old@x.com\n!everyone*")
    assert not any("old@x.com" in c or "everyone" in c for c in ex.calls) and any("sec@x.com" in c for c in ex.calls)


def test_what_was_checked_survives_a_reinventory(conn):
    g, ex = FakeGraph(), FakeExchange()
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    check_lists(conn, g, ex, "old@x.com")
    ex.calls.clear()
    run_inventory(conn, g, ALL_SCOPES, now=NOW + timedelta(days=1), exchange=ex)
    assert ex.calls == ["lists", "dynamic", "rules", "domains"]
    assert conn.execute("SELECT scanned_at, member_count FROM distribution_lists WHERE id='dl2'").fetchone()[0] is not None
    assert "LIKELY_UNUSED_DL" in list_flags(conn)["dl2"]


def test_a_list_deleted_in_exchange_disappears_with_its_data(conn):
    g, ex = FakeGraph(), FakeExchange()
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    check_lists(conn, g, ex, "*")
    ex.distribution_groups = lambda: [_dl("dl1", "Sales Team", "sales@x.com")]
    run_inventory(conn, g, ALL_SCOPES, now=NOW + timedelta(days=1), exchange=ex)
    assert [r[0] for r in conn.execute("SELECT id FROM distribution_lists ORDER BY id")] == ["dd1", "dl1"]
    assert conn.execute("SELECT COUNT(*) FROM dl_rule_refs").fetchone()[0] == 0


def test_an_unreadable_list_read_keeps_what_was_stored(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=FakeExchange())
    run_inventory(conn, g, ALL_SCOPES, now=NOW + timedelta(days=1), exchange=FakeExchange(deny={"lists"}))
    assert conn.execute("SELECT COUNT(*) FROM distribution_lists").fetchone()[0] == 5
    assert repo.signal_map(conn)["exchange_distribution_lists"] is False


def test_unreadable_transport_rules_stop_any_unused_verdict(conn):
    g, ex = FakeGraph(), FakeExchange(deny={"rules"})
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    check_lists(conn, g, ex, "old@x.com")
    assert repo.signal_map(conn)["exchange_transport_rules"] is False
    assert "LIKELY_UNUSED_DL" not in list_flags(conn)["dl2"] and "DL_NO_MAIL" in list_flags(conn)["dl2"]


def test_unreadable_message_trace_is_not_reported_as_no_mail(conn):
    g, ex = FakeGraph(), FakeExchange(deny={"trace"})
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    check_lists(conn, g, ex, "old@x.com")
    assert tuple(conn.execute("SELECT traffic_known, member_count FROM distribution_lists WHERE id='dl2'").fetchone()) == (0, 0)
    assert list_flags(conn)["dl2"] == {"DL_NO_OWNER", "DL_EMPTY"} and repo.signal_map(conn)["exchange_traffic"] is False


def test_checking_lists_without_an_exchange_client_does_nothing(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW, exchange=FakeExchange())
    check_lists(conn, FakeGraph(), None, "*")
    assert repo.scan_counts(conn)["dls_scanned"] == 0


def test_default_scan_kinds_never_touch_exchange(conn):
    g, ex = FakeGraph(), FakeExchange()
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    ex.calls.clear()
    run_scan(conn, g, ALL_SCOPES, "*", "*", now=NOW, exchange=ex)   # default kinds
    assert ex.calls == []


# --------------------------------------------- mailboxes and disabled accounts ---
def test_mailboxes_are_not_read_by_the_inventory_or_by_a_list_check(conn):
    g, ex = FakeGraph(), FakeExchange()
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    check_lists(conn, g, ex, "*")
    assert "mailboxes" not in ex.calls and conn.execute("SELECT COUNT(*) FROM mailboxes").fetchone()[0] == 0


def test_disabled_unlicensed_accounts_are_not_guessed_before_the_mailboxes_are_read(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW, exchange=FakeExchange())
    assert "DISABLED_MEMBER" not in {r[0] for r in conn.execute("SELECT flag FROM flags")}


def test_reading_the_mailboxes_separates_shared_mailboxes_from_leftover_accounts(conn):
    g, ex = FakeGraph(), FakeExchange()
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    check_lists(conn, g, ex, "", kinds=("mailbox_types",))
    assert ex.calls.count("mailboxes") == 1 and conn.execute("SELECT mailbox_type FROM mailboxes WHERE id='mem5'").fetchone()[0] == "SharedMailbox"
    flagged = {r["object_id"]: r["flag"] for r in conn.execute("SELECT object_id, flag FROM flags WHERE object_type = 'member'")}
    assert "mem5" not in flagged                     # disabled, free licence only, but it IS a shared mailbox: by design
    assert flagged["mem1"] == "DISABLED_LICENSED_MEMBER"


def test_a_disabled_account_that_is_not_a_mailbox_becomes_a_leftover_once_mailboxes_are_read(conn):
    g, ex = FakeGraph(), FakeExchange()
    ex.mailboxes = lambda types=None: []                # no shared mailboxes at all
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    check_lists(conn, g, ex, "", kinds=("mailbox_types",))
    assert {r["object_id"] for r in conn.execute("SELECT object_id FROM flags WHERE flag = 'DISABLED_MEMBER'")} == {"mem5"}


def test_unreadable_mailboxes_keep_what_was_stored_and_report_the_gap(conn):
    g, ex = FakeGraph(), FakeExchange()
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    check_lists(conn, g, ex, "", kinds=("mailbox_types",))
    check_lists(conn, g, FakeExchange(deny={"mailboxes"}), "", kinds=("mailbox_types",))
    assert conn.execute("SELECT COUNT(*) FROM mailboxes").fetchone()[0] == 1 and repo.signal_map(conn)["exchange_mailboxes"] is False


# --------------------------------------------- mailbox check and mail flow rules ---
def check_mailboxes(conn, graph, ex, patterns, types=False):
    kinds = ("mailbox_types", "mailboxes") if types else ("mailboxes",)
    return run_scan(conn, graph, ALL_SCOPES, "", "", now=NOW, kinds=kinds, mailbox_patterns=patterns, exchange=ex)


def mailbox_flags(conn):
    out = {}
    for r in conn.execute("SELECT object_id, flag FROM flags WHERE object_type = 'mailbox'"):
        out.setdefault(r["object_id"], set()).add(r["flag"])
    return out


def with_mailboxes(conn, ex=None, **over):
    g, ex = FakeGraph(), ex or FakeExchange()
    for k, v in over.items():
        setattr(ex, k, v)
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    run_scan(conn, g, ALL_SCOPES, "", "", now=NOW, kinds=("mailbox_types",), exchange=ex)
    ex.calls.clear()
    return g, ex


def test_the_inventory_stores_the_rules_and_the_tenant_domains(conn):
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW, exchange=FakeExchange())
    assert [tuple(r) for r in conn.execute("SELECT name, state FROM transport_rules")] == [("Archive finance", None)]
    assert conn.execute("SELECT value FROM settings WHERE name = 'accepted_domains'").fetchone()[0] == '["x.com"]'


def test_checking_a_mailbox_reads_only_the_selected_ones(conn):
    g, ex = with_mailboxes(conn)
    check_mailboxes(conn, g, ex, "nobody*")
    assert ex.calls == [] and repo.scan_counts(conn)["mailboxes_scanned"] == 0
    check_mailboxes(conn, g, ex, "fred@x.com")
    assert ex.calls == ["stats:mem5", "perms:mem5", "sendas:mem5", "trace:fred@x.com"]
    assert repo.scan_counts(conn)["mailboxes_scanned"] == 1 and repo.scan_counts(conn)["mailboxes_total"] == 1


def test_a_shared_mailbox_nobody_signs_in_to_and_nobody_can_open_is_likely_unused(conn):
    g, ex = with_mailboxes(conn)
    check_mailboxes(conn, g, ex, "*")
    assert mailbox_flags(conn) == {"mem5": {"MAILBOX_NO_ACTIVITY", "MAILBOX_NO_DELEGATES", "LIKELY_UNUSED_MAILBOX"}}
    assert [tuple(r) for r in conn.execute("SELECT trustee, kind FROM mailbox_delegates")] == [("gone@x.com", "full_access")]   # SELF is not a delegate
    assert conn.execute("SELECT item_count FROM mailboxes").fetchone()[0] == 9


def test_an_enabled_account_with_full_access_means_the_mailbox_can_be_used(conn):
    g, ex = with_mailboxes(conn, perms=[{"User": "active@x.com", "AccessRights": ["FullAccess"], "IsInherited": False, "Deny": False}])
    check_mailboxes(conn, g, ex, "*")
    assert mailbox_flags(conn) == {"mem5": {"MAILBOX_NO_ACTIVITY"}}                      # idle, but someone could open it


def test_deleted_and_disabled_holders_are_called_out_when_others_remain(conn):
    perms = [{"User": u, "AccessRights": ["FullAccess"], "IsInherited": False, "Deny": False}
             for u in ("active@x.com", "S-1-5-21-1-2-3-4001", "gone@x.com")]
    g, ex = with_mailboxes(conn, perms=perms, stats={"LastLogonTime": "2026-10-01T00:00:00", "ItemCount": 3})
    check_mailboxes(conn, g, ex, "*")
    assert mailbox_flags(conn) == {"mem5": {"MAILBOX_ORPHAN_DELEGATES"}}


def test_send_as_alone_keeps_a_silent_mailbox_from_being_called_unused(conn):
    sendas = [{"Trustee": "active@x.com", "AccessRights": ["SendAs"], "AccessControlType": "Allow", "IsInherited": False}]
    g, ex = with_mailboxes(conn, sendas=sendas)
    check_mailboxes(conn, g, ex, "*")
    assert "LIKELY_UNUSED_MAILBOX" not in mailbox_flags(conn)["mem5"] and "MAILBOX_NO_DELEGATES" in mailbox_flags(conn)["mem5"]


def test_unreadable_statistics_permissions_or_trace_are_not_guessed(conn):
    g, ex = with_mailboxes(conn, FakeExchange(deny={"stats", "perms", "trace"}))
    check_mailboxes(conn, g, ex, "*")
    row = conn.execute("SELECT logon_known, delegates_known, traffic_known FROM mailboxes").fetchone()
    assert tuple(row) == (0, 0, 0) and mailbox_flags(conn) == {}
    sig = repo.signal_map(conn)
    assert sig["exchange_mailbox_stats"] is False and sig["exchange_mailbox_permissions"] is False


def test_a_mailbox_check_survives_reading_the_mailbox_list_again(conn):
    g, ex = with_mailboxes(conn)
    check_mailboxes(conn, g, ex, "*")
    run_scan(conn, g, ALL_SCOPES, "", "", now=NOW, kinds=("mailbox_types",), exchange=ex)
    assert conn.execute("SELECT scanned_at FROM mailboxes").fetchone()[0] is not None and "LIKELY_UNUSED_MAILBOX" in mailbox_flags(conn)["mem5"]


def test_reading_the_mailbox_list_and_checking_in_one_run_works(conn):
    g, ex = FakeGraph(), FakeExchange()
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    check_mailboxes(conn, g, ex, "*", types=True)
    assert conn.execute("SELECT COUNT(*) FROM mailboxes WHERE scanned_at IS NOT NULL").fetchone()[0] == 1


def rule_flags(conn):
    out = {}
    for r in conn.execute("SELECT object_id, flag FROM flags WHERE object_type = 'rule'"):
        out.setdefault(r["object_id"], set()).add(r["flag"])
    return out


def rule_ex(rules):
    ex = FakeExchange()
    ex.transport_rules = lambda: rules
    return ex


def test_rules_that_are_off_expired_or_only_auditing_are_flagged_from_the_inventory(conn):
    rules = [{"Name": "Off", "State": "Disabled", "Mode": "Enforce", "Priority": 1, "WhenChanged": "2024-01-01T00:00:00Z"},
             {"Name": "Old", "State": "Enabled", "Mode": "Enforce", "Priority": 2, "ExpiryDate": "2025-01-01T00:00:00Z"},
             {"Name": "Test", "State": "Enabled", "Mode": "Audit", "Priority": 3},
             {"Name": "Fine", "State": "Enabled", "Mode": "Enforce", "Priority": 4, "ExpiryDate": "2030-01-01T00:00:00Z"}]
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW, exchange=rule_ex(rules))
    assert rule_flags(conn) == {"Off": {"RULE_DISABLED"}, "Old": {"RULE_EXPIRED"}, "Test": {"RULE_NOT_ENFORCING"}}


def test_dead_references_wait_until_the_mailbox_list_has_been_read(conn):
    rules = [{"Name": "Notify", "State": "Enabled", "Mode": "Enforce", "SentTo": ["gone-team@x.com", "fin@x.com", "support@elsewhere.org"]}]
    g, ex = FakeGraph(), rule_ex(rules)
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    assert rule_flags(conn) == {}                                                       # mailbox types not read: not guessed
    run_scan(conn, g, ALL_SCOPES, "", "", now=NOW, kinds=("mailbox_types",), exchange=ex)
    assert rule_flags(conn) == {"Notify": {"RULE_DEAD_REFERENCE"}}                      # fin@ is a list, elsewhere.org is external
    text = conn.execute("SELECT explanation FROM flags WHERE object_type = 'rule'").fetchone()[0]
    assert "gone-team@x.com" in text and "fin@x.com" not in text and "elsewhere.org" not in text


def test_unreadable_rules_keep_the_stored_ones(conn):
    g = FakeGraph()
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=FakeExchange())
    run_inventory(conn, g, ALL_SCOPES, now=NOW + timedelta(days=1), exchange=FakeExchange(deny={"rules"}))
    assert conn.execute("SELECT COUNT(*) FROM transport_rules").fetchone()[0] == 1


def test_an_alias_of_a_user_or_group_is_not_a_dead_reference(conn):
    rules = [{"Name": "Notify", "State": "Enabled", "Mode": "Enforce", "SentTo": ["alias@x.com", "grp@x.com", "gone@x.com", "nobody@x.com"]}]
    g, ex = FakeGraph(), rule_ex(rules)
    run_inventory(conn, g, ALL_SCOPES, now=NOW, exchange=ex)
    run_scan(conn, g, ALL_SCOPES, "", "", now=NOW, kinds=("mailbox_types",), exchange=ex)
    conn.execute("UPDATE members SET aliases = '[\"alias@x.com\"]' WHERE id = 'mem4'")
    conn.execute("UPDATE groups SET aliases = '[\"grp@x.com\"]' WHERE id = (SELECT MIN(id) FROM groups)")
    from broom365.services.sync import recompute_flags
    recompute_flags(conn, repo.load_thresholds(conn), NOW)
    text = conn.execute("SELECT explanation FROM flags WHERE object_type = 'rule'").fetchone()[0]
    assert "nobody@x.com" in text and "alias@x.com" not in text and "grp@x.com" not in text and "gone@x.com" not in text   # gone@ is a user
