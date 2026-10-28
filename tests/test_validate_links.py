import re
import sqlite3

import pytest
import requests

from broom365 import auth, create_app, links
from broom365.auth import AppAuthState, AppOnlyTokens
from broom365.config import Config
from broom365.models.types import FlagCode as F, GroupUsage
from broom365.services.graph import GraphError, SignalUnavailable
from broom365.services.permissions import check_permissions, is_granted
from broom365.services.usage import USAGE_SOURCES
from broom365.services.validate import PROBES, Probe, missing_permissions, run_probes
from tests.test_correlate import NOW, T, ago, group
from broom365.services.correlate import evaluate_group


# ------------------------------------------------------------------- probes ---
class ScriptedGraph:
    """Stands in for GraphClient.get: `outcomes` maps a path fragment to an exception to raise (else success)."""

    def __init__(self, outcomes=None):
        self.outcomes, self.urls = outcomes or {}, []

    def get(self, url, params=None, headers=None):
        self.urls.append(url)
        for frag, exc in self.outcomes.items():
            if frag in url:
                raise exc
        return {"value": []}


def err(status, msg="boom"):
    body = '{"error":{"message":"%s"}}' % msg
    return (SignalUnavailable if status in (401, 403) else GraphError)(status, "u", body)


ONE = (Probe("audit", "Audit", "AuditLog.Read.All", "v1.0", "/auditLogs/directoryAudits"),)


def run(outcome, granted):
    return run_probes(ScriptedGraph({"auditLogs": outcome} if outcome else {}), granted, probes=ONE)[0]


def test_ok():
    r = run(None, ["AuditLog.Read.All"])
    assert r.ok and r.status == "ok" and r.advice == ""


def test_403_without_the_permission_is_missing_and_names_it():
    r = run(err(403, "Insufficient privileges"), [])
    assert r.status == "missing" and "AuditLog.Read.All" in r.advice and "grant admin consent" in r.advice


def test_403_with_the_permission_granted_is_denied_not_missing():
    r = run(err(403, "Premium licence required"), ["AuditLog.Read.All"])
    assert r.status == "denied" and r.permission_granted and "licence" in r.advice and "Premium licence required" in r.advice


def test_400_is_rejected_and_explicitly_not_a_permission_problem():
    r = run(err(400, "Invalid filter clause"), ["AuditLog.Read.All"])
    assert r.status == "rejected" and "Not a permission problem" in r.advice and "Invalid filter clause" in r.advice


def test_404_and_other_statuses():
    assert run(err(404, "nope"), []).status == "not_found"
    assert run(err(500, "oops"), []).status == "error"


def test_network_error_is_a_result_not_an_exception():
    r = run(requests.ConnectionError("dns failure"), [])
    assert r.status == "error" and r.http is None and "dns failure" in r.message


def test_broader_permission_counts_as_granted():
    assert is_granted("Group.Read.All", ["Directory.Read.All"])
    assert is_granted("AuditLog.Read.All", ["auditlog.read.all"])
    assert not is_granted("AuditLog.Read.All", ["Group.Read.All"])


def test_missing_permissions_are_deduplicated_in_order():
    g = ScriptedGraph({"auditLogs": err(403), "reports": err(403), "roleAssignments": err(403)})
    res = run_probes(g, [])
    assert missing_permissions(res) == [p for p in dict.fromkeys(
        r.probe.permission for r in res if r.status == "missing")]
    assert "AuditLog.Read.All" in missing_permissions(res) and missing_permissions(res).count("AuditLog.Read.All") == 1


def test_every_data_source_is_probed_with_exact_permission_names():
    names = {p.permission for p in PROBES}
    assert all(re.fullmatch(r"[A-Za-z]+(\.[A-Za-z]+)+", n) for n in names)
    for s in USAGE_SOURCES:
        assert any(p.key == s.signal for p in PROBES)  # Conditional Access + each Intune source
    assert {"Group.Read.All", "Application.Read.All", "RoleManagement.Read.Directory", "AuditLog.Read.All",
            "Policy.Read.All", "DeviceManagementApps.Read.All", "DeviceManagementConfiguration.Read.All"} <= names
    g = ScriptedGraph()
    run_probes(g, [])
    assert len(g.urls) == len(PROBES) and any("/beta/" in u for u in g.urls)


# --------------------------------------------------------------- settings page --
@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.delenv("BROOM_DEMO", raising=False)
    from tests.test_app_mode import ALL_ROLES as roles
    monkeypatch.setattr(AppOnlyTokens, "state", lambda self, force=False: AppAuthState(
        check_permissions(roles, app_only=True), tuple(roles), None, 0.0))
    cfg = Config(tenant_id="t", client_id="c", client_secret="s", secret_key="k", database_path=tmp_path / "db.sqlite")
    c = create_app(cfg).test_client()
    from tests.test_app_mode import sign_in_admin
    sign_in_admin(c)
    return c


def csrf(client):
    return re.search(r'name="csrf-token" content="([^"]+)"', client.get("/settings").get_data(as_text=True)).group(1)


def test_validate_button_shows_exact_missing_permissions(client, monkeypatch):
    from broom365 import settings as settings_mod
    probe = Probe("audit", "Directory audit log", "AuditLog.Read.All", "v1.0", "/auditLogs/directoryAudits")
    probe2 = Probe("users", "Users", "Directory.Read.All", "v1.0", "/users")
    canned = [run_probes(ScriptedGraph({"auditLogs": err(403)}), [], probes=(probe,))[0],
              run_probes(ScriptedGraph({"users": err(403, "needs licence")}), ["Directory.Read.All"], probes=(probe2,))[0]]
    monkeypatch.setattr(settings_mod, "refresh_granted_scopes", lambda: (["Directory.Read.All"], None))
    monkeypatch.setattr(settings_mod, "graph_token_provider", lambda: (lambda: "tok"))
    monkeypatch.setattr(settings_mod, "run_probes", lambda graph, granted, perm_type, **kw: canned)
    html = client.post("/settings/validate", data={"csrf_token": csrf(client)}).get_data(as_text=True)
    assert "Add these Application permissions" in html and "<code>AuditLog.Read.All</code>" in html
    assert "Permission missing" in html and "Granted but denied" in html and "needs licence" in html


def test_validate_reports_token_failure(client, monkeypatch):
    from broom365 import settings as settings_mod
    monkeypatch.setattr(settings_mod, "refresh_granted_scopes", lambda: ([], "invalid_client: AADSTS7000215"))
    html = client.post("/settings/validate", data={"csrf_token": csrf(client)}).get_data(as_text=True)
    assert "No token could be obtained" in html and "AADSTS7000215" in html


def test_validate_requires_csrf(client):
    assert client.post("/settings/validate").status_code == 400


def test_validate_in_demo_mode_is_disabled(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BROOM_DEMO", "1")
    c = create_app().test_client()
    html = c.get("/settings").get_data(as_text=True)
    assert re.search(r'<button type="submit" class="btn" disabled', html)
    tok = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
    assert c.post("/settings/validate", data={"csrf_token": tok}).status_code == 302


# ---------------------------------------------------------------- portal links --
GID = "b62bc900-75fe-49a2-b6a0-b0859d5e7266"
TENANT = "11111111-2222-3333-4444-555555555555"


def test_group_links_match_the_portal_url_pattern():
    (intune_label, intune), (entra_label, entra) = links.group_links(GID, TENANT)
    assert intune == (f"https://intune.microsoft.com/#@{TENANT}/view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Overview/"
                      f"groupId/{GID}/menuId/")
    assert entra.startswith("https://entra.microsoft.com/#@") and entra.endswith(f"groupId/{GID}/menuId/")
    assert intune_label == "Open in Intune" and entra_label == "Open in Entra"


def test_links_without_a_guid_tenant_use_the_plain_form():
    assert links.group_links(GID, "demo")[0][1].startswith("https://intune.microsoft.com/#view/")
    assert links.group_links(GID, None)[0][1] == (
        f"https://intune.microsoft.com/#view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Overview/groupId/{GID}/menuId/")


@pytest.mark.parametrize("bad", ["", "g-0", "../../evil", GID + "/x", GID[:-1], "javascript:alert(1)"])
def test_non_guid_ids_never_make_a_link(bad):
    assert links.group_links(bad) == [] and links.user_links(bad) == [] and links.app_links(bad, bad) == []


def test_group_page_shows_open_in_intune_link(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BROOM_DEMO", "1")
    c = create_app().test_client()
    conn = sqlite3.connect("instance/demo.sqlite")
    conn.execute("INSERT INTO groups (id, display_name, inventoried_at) VALUES (?,?,?)", (GID, "Group to Uninstall Adobe 2024 Products", "2026-01-01T00:00:00+00:00"))
    conn.commit()
    conn.close()
    html = c.get(f"/groups/{GID}").get_data(as_text=True)
    assert f"groupId/{GID}/menuId/" in html and "Open in Intune" in html and 'target="_blank"' in html
    assert 'rel="noopener noreferrer"' in html
    assert "Where this group is used" in html and "Not scanned yet" in html


# ----------------------------------------------------- uninstall-only nuance ---
UNINSTALL = GroupUsage("intune_apps", "Intune app", "Adobe 2024 Uninstall", "assigned", "uninstall")


def test_group_referenced_only_by_uninstall_assignments_gets_the_nuance():
    a = evaluate_group(group(member_count=0, owner_count=0, created_at=ago(700), usages=(UNINSTALL,), parent_group_names=()), T, NOW)
    text = next(f for f in a.flags if f.code is F.EMPTY_GROUP).explanation
    assert "Every reference is an uninstall assignment" in text and "currently does nothing" in text


def test_required_assignment_does_not_get_the_uninstall_nuance():
    req = GroupUsage("intune_apps", "Intune app", "Office", "assigned", "required")
    a = evaluate_group(group(member_count=0, owner_count=0, created_at=ago(700), usages=(req,), parent_group_names=()), T, NOW)
    assert "uninstall assignment" not in next(f for f in a.flags if f.code is F.EMPTY_GROUP).explanation


def test_uninstall_nuance_ignores_intune_exclusions_but_not_other_references():
    excl = GroupUsage("intune_apps", "Intune app", "InDesign", "exclude", "required")
    base = dict(member_count=0, owner_count=0, created_at=ago(700), parent_group_names=())
    a = evaluate_group(group(**base, usages=(UNINSTALL, excl)), T, NOW)
    text = next(f for f in a.flags if f.code is F.EMPTY_GROUP).explanation
    assert "Every reference is an uninstall assignment" in text
    assert "'InDesign' (excluded)" in text and "exclude, required" not in text
    ca = GroupUsage("policy_binding", "Conditional Access policy", "MFA", "include", "enabled")
    text = next(f for f in evaluate_group(group(**base, usages=(UNINSTALL, ca)), T, NOW).flags if f.code is F.EMPTY_GROUP).explanation
    assert "uninstall assignment" not in text.replace("Intune app 'Adobe 2024 Uninstall' (assigned, uninstall)", "")
    only_excl = evaluate_group(group(**base, usages=(excl,)), T, NOW)
    assert "uninstall assignment" not in next(f for f in only_excl.flags if f.code is F.EMPTY_GROUP).explanation


def test_coverage_describes_exclusions_without_the_misleading_intent(tmp_path):
    from broom365.db import reset_database
    from broom365.services import repository as repo
    c = sqlite3.connect(tmp_path / "x.sqlite")
    c.row_factory = sqlite3.Row
    reset_database(c)
    c.execute("INSERT INTO groups (id, display_name, inventoried_at) VALUES ('g','G','t')")
    c.execute("INSERT INTO signal_availability VALUES ('intune_apps', 1, NULL, 't')")
    c.executemany("INSERT INTO group_usages VALUES ('g','intune_apps','Intune app',?,?,?,?)",
                  [("a1", "InDesign", "exclude", "required"), ("a2", "Illustrator", "assigned", "uninstall")])
    items = {r["label"]: r for r in repo.usage_coverage(c, "g")}["Intune apps"]["items"]
    assert "InDesign (excluded)" in items and "Illustrator (assigned, uninstall)" in items


# ------------------------------------------------------------- Exchange probe ---
class FakeExchangeProbe:
    def __init__(self, exc=None):
        self.exc, self.cmdlets = exc, []

    def invoke(self, cmdlet, **params):
        self.cmdlets.append(cmdlet)
        if self.exc:
            raise self.exc
        return []


def test_exchange_probe_ok_and_read_only():
    ex = FakeExchangeProbe()
    results = run_probes(ScriptedGraph(), ["Exchange.ManageAsApp"], probes=(), exchange=ex)
    assert [r.probe.key for r in results] == ["exchange"] and results[0].ok and ex.cmdlets == ["Get-DistributionGroup"]


def test_exchange_probe_missing_names_the_permission_and_the_entra_role():
    r = run_probes(ScriptedGraph(), [], probes=(), exchange=FakeExchangeProbe(err(403, "not authorized")))[0]
    assert r.status == "missing" and "Exchange.ManageAsApp" in r.advice and "Global Reader" in r.advice and "Office 365 Exchange Online" in r.advice


def test_exchange_probe_denied_when_the_role_is_granted_but_exchange_refuses():
    r = run_probes(ScriptedGraph(), ["Exchange.ManageAsApp"], probes=(), exchange=FakeExchangeProbe(err(403, "no role")))[0]
    assert r.status == "denied" and "Entra role" in r.advice


def test_no_exchange_client_means_no_exchange_probe():
    assert run_probes(ScriptedGraph(), [], probes=()) == []
