from broom365.services.permissions import check_permissions

ALL = ["User.Read", "Group.Read.All", "Application.Read.All", "Directory.Read.All",
       "RoleManagement.Read.Directory", "AuditLog.Read.All", "Policy.Read.All",
       "DeviceManagementApps.Read.All", "DeviceManagementConfiguration.Read.All"]


def test_all_granted_is_ok():
    assert check_permissions(ALL).status == "ok"


def test_case_insensitive():
    assert check_permissions([s.lower() for s in ALL]).status == "ok"


def test_missing_optional_is_degraded():
    r = check_permissions([s for s in ALL if s != "AuditLog.Read.All"])
    assert r.status == "degraded" and r.missing_scopes == ("AuditLog.Read.All",)


def test_missing_required_is_blocked():
    r = check_permissions([s for s in ALL if s != "User.Read"])
    assert r.status == "blocked" and r.missing_required[0].scope == "User.Read"


def test_broader_scope_satisfies_requirement():
    granted = ["User.Read", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
               "AuditLog.Read.All", "Policy.Read.All", "DeviceManagementApps.ReadWrite.All",
               "DeviceManagementConfiguration.ReadWrite.All"]
    assert check_permissions(granted).status == "ok"


def test_nothing_granted_lists_everything():
    from broom365.services.permissions import REQUIREMENTS
    assert len(check_permissions([]).missing_scopes) == len([r for r in REQUIREMENTS if r.scope != "Exchange.ManageAsApp"])  # an application role: not for delegated
