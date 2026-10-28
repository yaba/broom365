"""Demo mode: a synthetic tenant served through the real sync + correlation code.

Enabled with BROOM_DEMO=1. No Entra sign-in or Graph access is needed. The audit-log
endpoint is deliberately denied so the "signal unavailable" UI can be seen.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from .services.graph import Json, SignalUnavailable

NOW = datetime.now(timezone.utc)


def _ago(days: float) -> str:
    return (NOW - timedelta(days=days)).isoformat()


def _ahead(days: float) -> str:
    return (NOW + timedelta(days=days)).isoformat()


# (name, expired-days-ago | None, expiring-in-days | None, valid-in-days | None, last-signin-days | None, perms)
_APPS: list[tuple[str, int | None, int | None, int | None, int | None, list[tuple[str, str]]]] = [
    ("Legacy CRM Sync", 200, None, None, 400, [("delegated", "Mail.Read")]),
    ("HR Portal", None, None, 300, 2, []),
    ("Reporting Bot", None, 12, None, 1, [("application", "Files.ReadWrite.All")]),
    ("Marketing Mailer", 20, None, 250, 10, []),
    ("Old Inventory API", None, None, None, None, [("application", "Directory.ReadWrite.All")]),
    ("Teams Helper", None, None, 120, 5, []),
    ("Payroll Export", 45, None, None, 30, []),
    ("Directory Sync Tool", None, None, 120, 3, [("application", "Directory.Read.All")]),
]

# (name, created-days-ago, members, owners, licensed, role | None, assigned-resource-sp | None)
_GROUPS: list[tuple[str, int, int, int, bool, str | None, str | None]] = [
    ("CRM Legacy Users", 900, 14, 1, False, None, "sp-deleted"),
    ("Old Intranet Access", 700, 3, 1, False, None, "sp-disabled"),
    ("Project Phoenix", 365, 0, 0, False, None, None),
    ("Admins - Helpdesk", 500, 2, 0, False, "User Administrator", None),
    ("Contractors 2019", 900, 0, 1, False, None, None),
    ("Misc Sharing", 400, 25, 1, False, None, None),
    ("All Staff", 1200, 480, 2, True, None, None),
    ("Finance Team", 800, 12, 1, True, None, None),
    ("Engineering", 1000, 85, 3, True, None, None),
    ("Sales EMEA", 600, 31, 1, True, None, None),
    ("HR Portal Users", 300, 40, 1, False, None, "sp-ap-1"),
    ("Security Admins", 700, 4, 2, True, "Security Administrator", None),
    ("win10-app-deployment-office", 400, 220, 1, False, None, "sp-ap-1"),
    ("win10-app-deployment-adobe", 380, 0, 0, False, None, None),
    ("win10-app-deployment-vpn", 350, 64, 1, False, None, None),
    ("win10-app-deployment-legacy", 800, 9, 1, False, None, "sp-deleted"),
    ("win10-app-deployment-chrome", 300, 180, 2, True, None, None),
    ("win11-app-deployment-pilot", 60, 5, 1, False, None, None),
    ("All Users", 3000, 4000, 1, True, None, None),   # dynamic: catches every user and guest
]

_USERS = [("u-ann", "Ann Admin", "Global Administrator", 150), ("u-bob", "Bob Ops", "Exchange Administrator", 3),
          ("u-carol", "Carol Contractor", "Privileged Role Administrator", None),
          ("u-dan", "Dan Disabled", "Helpdesk Administrator", 400),
          ("u-gus", "Gus Guest", "Security Reader", 20)]


class DemoGraph:
    """Implements the subset of GraphClient that sync.py calls."""

    def list_service_principals(self) -> list[Json]:
        sps: list[Json] = [{"id": "sp-graph", "appId": "gr", "displayName": "Microsoft Graph", "accountEnabled": True},
                           {"id": "sp-disabled", "appId": "dis", "displayName": "Old Intranet", "accountEnabled": False}]
        sps += [{"id": f"sp-ap-{i}", "appId": f"app-{i}", "displayName": a[0], "accountEnabled": True}
                for i, a in enumerate(_APPS)]
        return sps

    def list_applications(self) -> list[Json]:
        out = []
        for i, (name, exp, soon, valid, _, _) in enumerate(_APPS):
            pw = []
            if exp is not None:
                pw.append({"keyId": f"k{i}a", "displayName": "old secret", "endDateTime": _ago(exp)})
            if soon is not None:
                pw.append({"keyId": f"k{i}b", "displayName": "rotating secret", "endDateTime": _ahead(soon)})
            if valid is not None:
                pw.append({"keyId": f"k{i}c", "displayName": "current secret", "endDateTime": _ahead(valid)})
            out.append({"id": f"ap-{i}", "appId": f"app-{i}", "displayName": name, "createdDateTime": _ago(900),
                        "passwordCredentials": pw, "keyCredentials": []})
        return out

    def application_owners(self, app_id: str) -> list[Json]:
        return [] if app_id in ("ap-0", "ap-4") else [{"id": "u-bob", "displayName": "Bob Ops"}]

    def list_oauth2_permission_grants(self) -> list[Json]:
        return [{"id": f"dg{i}", "clientId": f"sp-ap-{i}", "resourceId": "sp-graph", "consentType": "AllPrincipals",
                 "scope": p[1]} for i, a in enumerate(_APPS) for p in a[5] if p[0] == "delegated"]

    def get_service_principal_roles(self, _sp_id: str) -> Json:
        return {"appRoles": [{"id": "role-files", "value": "Files.ReadWrite.All"},
                             {"id": "role-dir", "value": "Directory.ReadWrite.All"},
                             {"id": "role-dirread", "value": "Directory.Read.All"}]}

    def sp_app_role_assignments(self, sp_id: str) -> list[Json]:
        i = int(sp_id.rsplit("-", 1)[1])
        ids = {"Files.ReadWrite.All": "role-files", "Directory.ReadWrite.All": "role-dir", "Directory.Read.All": "role-dirread"}
        return [{"id": f"ara{i}", "resourceId": "sp-graph", "resourceDisplayName": "Microsoft Graph",
                 "appRoleId": ids[p[1]]} for p in _APPS[i][5] if p[0] == "application"]

    def list_sp_sign_in_activities(self) -> list[Json]:
        return [{"appId": f"app-{i}", "lastSignInActivity": {"lastSignInDateTime": _ago(a[4])}}
                for i, a in enumerate(_APPS) if a[4] is not None]

    def list_role_assignments(self) -> list[Json]:
        out: list[Json] = []
        for uid, _, role, _ in _USERS:
            out.append({"id": f"ra-{uid}", "principalId": uid, "roleDefinitionId": f"rd-{role}",
                        "principal": {"@odata.type": "#microsoft.graph.user"}})
        for i, g in enumerate(_GROUPS):
            if g[5]:
                out.append({"id": f"ra-g{i}", "principalId": f"g-{i}", "roleDefinitionId": f"rd-{g[5]}",
                            "principal": {"@odata.type": "#microsoft.graph.group"}})
        return out

    def list_role_definitions(self) -> list[Json]:
        names = {u[2] for u in _USERS} | {g[5] for g in _GROUPS if g[5]}
        return [{"id": f"rd-{n}", "displayName": n} for n in sorted(names)]

    USER_BATCH = 15

    def users_by_ids(self, ids: list[str], with_sign_in: bool = False) -> list[Json]:
        out = []
        for uid in ids:
            _, name, _, days = next(u for u in _USERS if u[0] == uid)
            user: Json = {"id": uid, "displayName": name, "userPrincipalName": f"{name.split()[0].lower()}@contoso.example",
                          "accountEnabled": uid != "u-dan", "userType": "Guest" if uid == "u-gus" else "Member"}
            if with_sign_in:
                user["signInActivity"] = None if days is None else {"lastSignInDateTime": _ago(days)}
            out.append(user)
        return out

    def list_guests(self, with_sign_in: bool = False) -> list[Json]:
        # (id, name, mail, enabled, created days ago, external state, last sign-in days ago)
        data = [("gst-1", "Pat Partner", "pat@partner-corp.com", True, 1500, "Accepted", 1460),
                ("gst-2", "Sam Supplier", "sam@supplies.example", True, 200, "PendingAcceptance", None),
                ("gst-3", "Active Ann", "ann@client.example", True, 400, "Accepted", 10),
                ("gst-4", "Old Disabled", "old@gone.example", False, 1800, "Accepted", 1500),
                ("gst-5", "Never Nick", "nick@vendor.example", True, 800, "Accepted", None),
                ("gst-6", "New Nora", "nora@fresh.example", True, 5, "PendingAcceptance", None),
                ("gst-7", "Second Partner", "sue@partner-corp.com", True, 1200, "Accepted", 900)]
        out = []
        for gid, name, mail, enabled, created, state, last in data:
            u: Json = {"id": gid, "displayName": name, "mail": mail, "userPrincipalName": mail.replace("@", "_") + "#EXT#@contoso.example",
                       "accountEnabled": enabled, "createdDateTime": _ago(created), "externalUserState": state,
                       "externalUserStateChangeDateTime": _ago(created), "userType": "Guest"}
            if with_sign_in:
                u["signInActivity"] = None if last is None else {"lastSignInDateTime": _ago(last)}
            out.append(u)
        return out

    def guest_memberships(self, uid: str) -> list[Json]:
        team = {"id": "gm-1", "displayName": "Project Atlas", "groupTypes": ["Unified"], "resourceProvisioningOptions": ["Team"]}
        sec = {"id": "gm-2", "displayName": "Partners", "groupTypes": [], "securityEnabled": True}
        m365 = {"id": "gm-3", "displayName": "Shared documents", "groupTypes": ["Unified"], "resourceProvisioningOptions": []}
        everyone = {"id": f"g-{len(_GROUPS) - 1}", "displayName": "All Users", "groupTypes": [], "securityEnabled": True}
        return {"gst-1": [team, sec, everyone], "gst-5": [team, everyone], "gst-7": [m365, everyone], "gst-2": [],
                "gst-3": [everyone], "gst-4": [everyone], "gst-6": [everyone]}.get(uid, [])

    def list_skus(self) -> list[Json]:
        return [{"skuId": "sku-e3", "skuPartNumber": "SPE_E3"}, {"skuId": "sku-free", "skuPartNumber": "FLOW_FREE"},
                {"skuId": "sku-bp", "skuPartNumber": "SPB"}]

    def list_members(self, with_sign_in: bool = False) -> list[Json]:
        # (id, name, enabled, synced from AD, licence sku ids, created days ago, last sign-in days ago)
        data = [("m-8", "Shared Support", False, False, [], 2000, None),                          # a shared mailbox: disabled by design
                ("m-9", "Ex Employee", False, True, [], 1800, 900),                              # disabled, unlicensed, not a mailbox: leftover
                ("m-1", "Active Alice", True, True, ["sku-e3"], 900, 2),
                ("m-2", "Gone Gary", False, True, ["sku-e3", "sku-free"], 1500, 700),            # disabled, still paying for E3
                ("m-3", "Idle Ivan", True, False, ["sku-bp"], 1200, 400),                         # stale and licensed
                ("m-4", "Ghost Gina", True, True, [], 800, None),                                 # never signed in, no licence
                ("m-5", "Free Fred", False, False, ["sku-free"], 600, 500),                       # disabled, only a free licence: not spend
                ("m-6", "New Nina", True, False, ["sku-e3"], 20, None),                           # created recently: not stale yet
                ("m-7", "Service Sam", True, False, [], 1000, 5)]
        out = []
        for uid, name, enabled, synced, skus, created, last in data:
            u: Json = {"id": uid, "displayName": name, "mail": f"{name.split()[0].lower()}@contoso.example",
                       "userPrincipalName": f"{name.split()[0].lower()}@contoso.example", "accountEnabled": enabled,
                       "onPremisesSyncEnabled": synced or None, "createdDateTime": _ago(created), "userType": "Member",
                       "assignedLicenses": [{"skuId": s} for s in skus]}
            if with_sign_in:
                u["signInActivity"] = None if last is None else {"lastSignInDateTime": _ago(last)}
            out.append(u)
        return out

    def list_deleted_service_principals(self) -> list[Json]:
        return [{"id": "sp-deleted", "deletedDateTime": _ago(21)}]

    def list_conditional_access_policies(self) -> list[Json]:
        return [{"id": "ca-1", "displayName": "Require MFA for admins", "state": "enabled",
                 "conditions": {"users": {"includeGroups": ["g-11"], "excludeGroups": ["g-5"]}}}]

    def list_with_assignments(self, api: str, path: str) -> list[Json]:
        """Intune collections with assignments: apps, profiles, compliance, scripts and remediations."""
        def grp(gid: str, intent: str | None = None) -> Json:
            return {"intent": intent, "target": {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": gid}}

        if path.endswith("mobileApps"):
            meta = {"@odata.type": "#microsoft.graph.win32LobApp", "createdDateTime": _ago(500), "lastModifiedDateTime": _ago(200)}
            excl = {"intent": "uninstall", "target": {"@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget", "groupId": "g-9"}}
            all_users = {"intent": "uninstall", "target": {"@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"}}
            return [
                {"id": "app-1", "displayName": "Microsoft Office 365", **meta, "assignments": [grp("g-12", "required")]},
                {"id": "app-2", "displayName": "Cisco VPN (old)", **meta, "assignments": [grp("g-15", "required")]},
                {"id": "app-3", "displayName": "Adobe Acrobat 2024", **meta, "assignments": [grp("g-13", "uninstall"), grp("g-16", "uninstall"), excl]},
                {"id": "app-4", "displayName": "Adobe Reader 2023", **meta, "assignments": [grp("g-13", "uninstall"), all_users]},
                {"id": "app-5", "displayName": "Google Chrome", **meta, "assignments": [grp("g-16", "required"), grp("g-13", "uninstall")]},
                {"id": "app-6", "displayName": "Unassigned helper", **meta, "assignments": []},
                {"id": "app-7", "displayName": "7-Zip 22.00", **meta, "assignments": []},
                {"id": "app-8", "displayName": "7-Zip 23.01", **meta, "assignments": [grp("g-6", "required")]},
                {"id": "app-9", "displayName": "VC++ runtime", **meta, "assignments": []},
            ]
        if path.endswith("deviceManagementScripts"):
            old = {"createdDateTime": _ago(2000), "lastModifiedDateTime": _ago(1800)}
            return [
                {"id": "s-1", "displayName": "Install legacy VPN client", **old, "assignments": [grp("g-4")]},
                {"id": "s-2", "displayName": "Map network drives", "createdDateTime": _ago(300), "lastModifiedDateTime": _ago(100),
                 "assignments": [grp("g-6")]},
                {"id": "s-3", "displayName": "Old registry fix", **old, "assignments": [grp("g-6")]},
            ]
        if path.endswith("deviceHealthScripts"):
            return [
                {"id": "h-1", "displayName": "Clear temp files", "createdDateTime": _ago(200), "lastModifiedDateTime": _ago(30),
                 "assignments": [grp("g-8")]},
                {"id": "h-2", "displayName": "Legacy detection", "createdDateTime": _ago(1500), "lastModifiedDateTime": _ago(900),
                 "assignments": []},
            ]
        if path.endswith("deviceConfigurations"):
            ring = {"@odata.type": "#microsoft.graph.windowsUpdateForBusinessConfiguration", "createdDateTime": _ago(400),
                    "lastModifiedDateTime": _ago(120), "qualityUpdatesPaused": False, "featureUpdatesPaused": False,
                    "deadlineGracePeriodInDays": 2}
            return [
                {"id": "ur-1", "displayName": "Update ring - Pilot", **ring, "qualityUpdatesDeferralPeriodInDays": 0, "featureUpdatesDeferralPeriodInDays": 0,
                 "deadlineForQualityUpdatesInDays": 2, "deadlineForFeatureUpdatesInDays": 5, "assignments": [grp("g-17")]},
                {"id": "ur-2", "displayName": "Update ring - Broad", **ring, "qualityUpdatesDeferralPeriodInDays": 7, "featureUpdatesDeferralPeriodInDays": 30,
                 "deadlineForQualityUpdatesInDays": None, "deadlineForFeatureUpdatesInDays": None, "featureUpdatesPaused": True,
                 "featureUpdatesPauseExpiryDateTime": _ago(10), "assignments": [grp("g-6")]},
                {"id": "dc-1", "displayName": "Wi-Fi corporate profile", "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
                 "assignments": [grp("g-6")]},
            ]
        if path.endswith("windowsFeatureUpdateProfiles"):
            return [
                {"id": "fu-1", "displayName": "Windows 11 24H2 - everyone", "featureUpdateVersion": "Windows 11, version 24H2",
                 "endOfSupportDate": _ago(20), "createdDateTime": _ago(600), "lastModifiedDateTime": _ago(300),
                 "assignments": [grp("g-6"), grp("g-8")]},
                {"id": "fu-2", "displayName": "Windows 11 25H2 - pilot and staff", "featureUpdateVersion": "Windows 11, version 25H2",
                 "endOfSupportDate": _ahead(900), "createdDateTime": _ago(120), "lastModifiedDateTime": _ago(60),
                 "assignments": [grp("g-6"), grp("g-17")]},
                {"id": "fu-3", "displayName": "Windows 11 26H2 - next", "featureUpdateVersion": "Windows 11, version 26H2",
                 "endOfSupportDate": _ahead(1400), "createdDateTime": _ago(30), "lastModifiedDateTime": _ago(30), "assignments": []},
            ]
        if path.endswith("windowsQualityUpdateProfiles"):
            return [{"id": "qu-1", "displayName": "Expedite critical fix", "createdDateTime": _ago(260), "lastModifiedDateTime": _ago(250),
                     "releaseDateDisplayName": "2026-02 Security Update", "expeditedUpdateSettings": {"qualityUpdateRelease": "2026-02-10T00:00:00Z", "daysUntilForcedReboot": 2},
                     "assignments": [grp("g-17")]}]
        if path.endswith("windowsDriverUpdateProfiles"):
            return [{"id": "du-1", "displayName": "Drivers - manual approval", "createdDateTime": _ago(200), "lastModifiedDateTime": _ago(40),
                     "approvalType": "manual", "deploymentDeferralInDays": None, "newUpdates": 7, "deviceReporting": 120,
                     "assignments": [grp("g-8")]}]
        if path.endswith("deviceCompliancePolicies"):
            return [{"id": "cp-1", "displayName": "Windows 10 baseline", "assignments": [grp("g-14")]}]
        if path.endswith("configurationPolicies"):
            raise SignalUnavailable(403, path, "demo: settings catalog not licensed")
        return []

    def app_relationships(self, app_id: str) -> list[Json]:
        sup, dep = "#microsoft.graph.mobileAppSupersedence", "#microsoft.graph.mobileAppDependency"
        return {
            "app-7": [{"@odata.type": sup, "targetType": "parent", "targetId": "app-8", "targetDisplayName": "7-Zip 23.01",
                       "supersedenceType": "replace"}],
            "app-9": [{"@odata.type": dep, "targetType": "parent", "targetId": "app-1", "targetDisplayName": "Microsoft Office 365",
                       "dependencyType": "autoInstall"}],
        }.get(app_id, [])

    def script_run_summary(self, path: str, sid: str) -> Json:
        zero = {"successDeviceCount": 0, "errorDeviceCount": 0, "successUserCount": 0, "errorUserCount": 0}
        return {
            "s-1": zero,
            "s-2": {**zero, "successDeviceCount": 480, "errorDeviceCount": 3},
            "s-3": {**zero, "errorDeviceCount": 120},
            "h-1": {"issueDetectedDeviceCount": 4, "issueRemediatedDeviceCount": 4, "lastScriptRunDateTime": _ago(1)},
            "h-2": {"issueDetectedDeviceCount": 0, "lastScriptRunDateTime": None},
        }.get(sid, {})

    def group_member_of(self, gid: str) -> list[Json]:
        return [{"id": "g-6", "displayName": "All Staff"}] if gid == "g-14" else []

    def list_group_membership_audits(self, _since: str) -> Iterator[Any]:
        raise SignalUnavailable(403, "auditLogs/directoryAudits", "demo: audit logs not licensed")

    def list_groups(self) -> list[Json]:
        return [{"id": f"g-{i}", "displayName": g[0], "createdDateTime": _ago(g[1]),
                 "assignedLicenses": [{"skuId": "x"}] if g[4] else [],
                 "groupTypes": ["Unified"] if g[0] in ("Project Phoenix", "Engineering") else [],
                 "membershipRule": 'user.accountEnabled -eq true' if g[0] == "All Users" else None} for i, g in enumerate(_GROUPS)]

    def group_owners(self, gid: str) -> list[Json]:
        return [{"id": f"o{n}", "displayName": f"Owner {n}"} for n in range(_GROUPS[int(gid[2:])][3])]

    def group_member_count(self, gid: str) -> int:
        return _GROUPS[int(gid[2:])][2]

    def group_app_role_assignments(self, gid: str) -> list[Json]:
        res = _GROUPS[int(gid[2:])][6]
        names = {"sp-deleted": "CRM Legacy", "sp-disabled": "Old Intranet", "sp-ap-1": "HR Portal"}
        return [] if res is None else [{"id": f"a-{gid}", "resourceId": res, "resourceDisplayName": names[res],
                                        "appRoleId": "r", "createdDateTime": _ago(400)}]


class DemoExchange:
    """Synthetic Exchange Online data for demo mode (same read-only surface as services.exchange.ExchangeClient)."""

    # (id, name, address, kind, owners, created days ago, changed days ago, synced, members, last mail days ago)
    LISTS = [("dl-1", "All Staff DL", "all-staff@contoso.example", "distribution", ["Ann Admin"], 2500, 30, False, 480, 1),
             ("dl-2", "Old Project Team", "old-project@contoso.example", "distribution", [], 2000, 1500, False, 0, None),
             ("dl-3", "Finance Alerts", "finance-alerts@contoso.example", "distribution", ["Fin Manager"], 1800, 200, False, 12, None),
             ("dl-4", "Legacy Sales", "legacy-sales@contoso.example", "distribution", ["Sam Sales"], 2200, 1200, True, 0, None),
             ("dl-5", "Helpdesk", "helpdesk@contoso.example", "distribution", [], 1000, 100, False, 9, 3),
             ("dl-6", "All Engineers", "all-engineers@contoso.example", "dynamic", ["Eng Lead"], 700, 60, False, 80, 20)]

    def _row(self, d: tuple) -> Json:  # type: ignore[type-arg]
        did, name, addr, kind, owners, created, changed, synced, _, _ = d
        return {"ExternalDirectoryObjectId": did, "DisplayName": name, "PrimarySmtpAddress": addr, "ManagedBy": owners,
                "WhenCreated": _ago(created), "WhenChanged": _ago(changed), "IsDirSynced": synced, "HiddenFromAddressListsEnabled": False,
                "RecipientTypeDetails": "MailUniversalDistributionGroup"}

    def distribution_groups(self) -> list[Json]:
        return [self._row(d) for d in self.LISTS if d[3] != "dynamic"]

    def dynamic_distribution_groups(self) -> list[Json]:
        return [self._row(d) for d in self.LISTS if d[3] == "dynamic"]

    def transport_rules(self) -> list[Json]:
        def rule(name: str, **kw: Any) -> Json:
            return {"Name": name, "State": "Enabled", "Mode": "Enforce", "Priority": 0, "WhenChanged": _ago(400), "ExpiryDate": None,
                    "Description": f"Demo rule {name}", **kw}

        return [rule("Archive finance mail", Priority=0, SentToMemberOf=["finance-alerts@contoso.example"]),
                rule("Old legal hold copy", Priority=1, State="Disabled", WhenChanged=_ago(1100), BlindCopyTo=["legal@contoso.example"]),
                rule("Campaign footer", Priority=2, ExpiryDate=_ago(200), WhenChanged=_ago(500)),
                rule("Audit external forwarding", Priority=3, Mode="Audit"),
                rule("Notify the former project team", Priority=4, SentTo=["old-team@contoso.example"], RedirectMessageTo=["helpdesk@contoso.example"])]

    def accepted_domains(self) -> list[str]:
        return ["contoso.example", "contoso.onmicrosoft.com"]

    # (id, name, address, type, created days ago, last sign-in days ago (None = never), last mail days ago (None = none),
    #  full access, send as)
    MAILBOXES = [("m-8", "Shared Support", "support@contoso.example", "SharedMailbox", 2000, 3, 1, ["active@contoso.example"], []),
                 ("m-10", "Old Projects", "old-projects@contoso.example", "SharedMailbox", 1900, 700, None, ["ex@contoso.example"], ["gone@contoso.example"]),
                 ("m-11", "Conference Room A", "room-a@contoso.example", "RoomMailbox", 1500, None, 5, [], []),
                 ("m-12", "Billing Inbox", "billing@contoso.example", "SharedMailbox", 1700, 20, 2,
                  ["active@contoso.example", "S-1-5-21-1111111111-2222222222-3333333333-4001"], []),
                 ("m-13", "Unused Room B", "room-b@contoso.example", "RoomMailbox", 1600, None, None, [], [])]

    def mailboxes(self, types: Any = None) -> list[Json]:
        return [{"ExternalDirectoryObjectId": m[0], "RecipientTypeDetails": m[3], "DisplayName": m[1], "PrimarySmtpAddress": m[2],
                 "WhenCreated": _ago(m[4]), "GrantSendOnBehalfTo": []} for m in self.MAILBOXES]

    def mailbox_statistics(self, identity: str) -> Json | None:
        m = next(m for m in self.MAILBOXES if m[0] == identity)
        return {"LastLogonTime": None if m[5] is None else _ago(m[5]), "ItemCount": 120}

    def mailbox_permissions(self, identity: str) -> list[Json]:
        m = next(m for m in self.MAILBOXES if m[0] == identity)
        rows = [{"User": "NT AUTHORITY\\SELF", "AccessRights": ["FullAccess, ReadPermission"], "IsInherited": False, "Deny": False},
                {"User": "Domain Admins", "AccessRights": ["FullAccess"], "IsInherited": True, "Deny": False}]
        return rows + [{"User": u, "AccessRights": ["FullAccess, ReadPermission"], "IsInherited": False, "Deny": False} for u in m[7]]

    def recipient_permissions(self, identity: str) -> list[Json]:
        m = next(m for m in self.MAILBOXES if m[0] == identity)
        return [{"Trustee": u, "AccessRights": ["SendAs"], "AccessControlType": "Allow", "IsInherited": False} for u in m[8]]

    def member_count(self, identity: str, dynamic: bool = False) -> int:
        return next(d[8] for d in self.LISTS if d[2] == identity)

    def last_mail_received(self, address: str, now: Any = None) -> datetime | None:
        days = next((d[9] for d in self.LISTS if d[2] == address), None)
        if days is None and address in {m[2] for m in self.MAILBOXES}:
            days = next(m[6] for m in self.MAILBOXES if m[2] == address)
        return None if days is None else NOW - timedelta(days=days)

    def invoke(self, cmdlet: str, **params: Any) -> list[Json]:
        return self.distribution_groups()[:1]
