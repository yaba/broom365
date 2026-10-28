import csv
import io
import re
import sqlite3

import pytest

from broom365 import create_app

TABS = ("groups", "apps", "users", "intune", "scripts", "updates", "guests", "members", "dls", "mailboxes", "rules")
TYPE = {"groups": "group", "apps": "app", "intune": "intune_app", "scripts": "intune_script", "updates": "update", "guests": "guest", "users": "user", "members": "member", "dls": "dl", "mailboxes": "mailbox", "rules": "rule"}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BROOM_DEMO", "1")
    return create_app().test_client()


def fetch(client, tab):
    r = client.get(f"/export/{tab}")
    assert r.status_code == 200
    rows = list(csv.DictReader(io.StringIO(r.get_data(as_text=True).lstrip("﻿"))))
    return r, rows


def by_name(rows, name, key="display_name"):
    return next(r for r in rows if r[key] == name)


def flagged_count(otype):
    c = sqlite3.connect("instance/demo.sqlite")
    try:
        return c.execute("SELECT COUNT(*) FROM flagged_objects WHERE object_type = ?", (otype,)).fetchone()[0]
    finally:
        c.close()


@pytest.mark.parametrize("tab", TABS)
def test_every_tab_has_its_own_csv_with_a_proper_filename(client, tab):
    r, rows = fetch(client, tab)
    assert r.mimetype == "text/csv" and re.search(rf"filename=broom365-{tab}-\d{{4}}-\d\d-\d\d\.csv", r.headers["Content-Disposition"])
    assert rows and "risk_level" in rows[0] and "explanations" in rows[0]
    if tab != "users":  # users lists every privileged account; the others list the flagged objects of that tab
        assert len(rows) == flagged_count(TYPE[tab])


def test_unknown_tab_is_a_404(client):
    assert client.get("/export/nonsense").status_code == 404
    assert client.get("/export/user").status_code == 404


def test_rows_are_sorted_by_risk_then_name(client):
    for tab in ("groups", "guests", "intune"):
        _, rows = fetch(client, tab)
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        assert [order[r["risk_level"]] for r in rows] == sorted(order[r["risk_level"]] for r in rows), tab


def test_groups_csv_has_members_owners_and_what_references_the_group(client):
    _, rows = fetch(client, "groups")
    g = by_name(rows, "Contractors 2019")  # empty, referenced only by an Intune script
    assert g["members"] == "0" and "Intune PowerShell script 'Install legacy VPN client'" in g["referenced_by"]
    assert g["group_type"] and g["created_at"] and g["checked_at"] and g["flags"] and g["explanations"]
    assert by_name(rows, "CRM Legacy Users")["members"] == "14"


def test_apps_csv_counts_secrets_and_permissions(client):
    _, rows = fetch(client, "apps")
    a = by_name(rows, "Legacy CRM Sync")
    assert a["secrets"] == "1" and a["secrets_expired"] == "1" and a["permissions"] == "1" and a["owners"] == "0"
    assert a["last_sign_in_at"] and "LIKELY_ABANDONED_APP" in a["flags"] and a["client_id"] == "app-0"


def test_users_csv_lists_every_privileged_user_internal_and_external(client):
    _, rows = fetch(client, "users")
    assert {r["display_name"] for r in rows} == {"Ann Admin", "Bob Ops", "Carol Contractor", "Dan Disabled", "Gus Guest"}
    bob = by_name(rows, "Bob Ops")
    assert bob["risk_level"] == "LOW" and bob["flags"] == "" and bob["roles"] == "Exchange Administrator"
    assert by_name(rows, "Gus Guest")["account_type"] == "External" and by_name(rows, "Ann Admin")["account_type"] == "Internal"
    dan = by_name(rows, "Dan Disabled")
    assert dan["account_enabled"] == "no" and "DISABLED_PRIVILEGED_USER" in dan["flags"]


def test_intune_csv_shows_assignments_with_intent_and_exclusions(client):
    _, rows = fetch(client, "intune")
    a = by_name(rows, "Adobe Acrobat 2024")
    assert "(uninstall)" in a["assignments"] and "excluded: group" in a["assignments"] and a["relations_checked"] == "yes"
    assert "UNINSTALL_ONLY_APP" in a["flags"] and a["app_type"] == "win32LobApp"
    assert "All licensed users" in by_name(rows, "Adobe Reader 2023")["assignments"].replace("all licensed users", "All licensed users")
    assert "UNASSIGNED_APP" in by_name(rows, "7-Zip 22.00")["flags"] and by_name(rows, "Unassigned helper")["assignments"] == ""


def test_scripts_csv_has_kind_and_run_results(client):
    _, rows = fetch(client, "scripts")
    s = by_name(rows, "Old registry fix")
    assert s["kind"] == "PowerShell script" and s["runs_failed"] == "120" and s["runs_succeeded"] == "0"
    assert "LIKELY_OBSOLETE_SCRIPT" in s["flags"] and s["run_results_checked"] == "yes"
    assert by_name(rows, "Legacy detection")["kind"] == "Remediation"


def test_guests_csv_has_company_domain_and_invitation_state(client):
    _, rows = fetch(client, "guests")
    pat = by_name(rows, "Pat Partner")
    assert pat["company_domain"] == "partner-corp.com" and pat["invitation_state"] == "Accepted" and pat["last_sign_in_at"]
    assert by_name(rows, "Sam Supplier")["invitation_state"] == "PendingAcceptance"
    assert by_name(rows, "Old Disabled")["account_enabled"] == "no"
    assert {r["company_domain"] for r in rows} >= {"partner-corp.com", "supplies.example", "vendor.example"}
    assert "Active Ann" not in {r["display_name"] for r in rows}


def test_tenant_text_cannot_become_a_spreadsheet_formula_in_any_tab_export(client):
    c = sqlite3.connect("instance/demo.sqlite")
    c.execute("UPDATE groups SET display_name = '=HYPERLINK(\"http://x\")' WHERE id = 'g-4'")
    c.execute("UPDATE guests SET display_name = '+cmd|calc' WHERE id = 'gst-1'")
    c.execute("UPDATE intune_scripts SET display_name = '@SUM(1)' WHERE id = 's-1'")
    c.commit()
    c.close()
    assert any(r["display_name"].startswith("'=HYPERLINK") for r in fetch(client, "groups")[1])
    assert any(r["display_name"].startswith("'+cmd") for r in fetch(client, "guests")[1])
    assert any(r["display_name"].startswith("'@SUM") for r in fetch(client, "scripts")[1])


def test_the_general_export_still_has_every_type_in_one_file(client):
    r = client.get("/export")
    rows = list(csv.DictReader(io.StringIO(r.get_data(as_text=True).lstrip("﻿"))))
    assert {x["object_type"] for x in rows} == {"group", "app", "user", "intune_app", "intune_script", "guest", "member", "dl", "mailbox", "rule", "update"}
    assert len(rows) == sum(flagged_count(t) for t in TYPE.values())
    assert "filename=broom365-flagged-" in r.headers["Content-Disposition"]


def test_each_tab_page_links_to_its_own_csv_and_the_nav_keeps_the_general_one(client):
    for tab in TABS:
        html = client.get(f"/?tab={tab}").get_data(as_text=True)
        assert f'href="/export/{tab}"' in html and 'href="/export"' in html and "Export all (CSV)" in html, tab
        others = [t for t in TABS if t != tab]
        assert not any(f'href="/export/{o}"' in html for o in others), tab


def test_guests_csv_lists_what_each_checked_guest_still_belongs_to(client):
    _, rows = fetch(client, "guests")
    pat = by_name(rows, "Pat Partner")
    assert pat["memberships_checked"] == "yes" and pat["member_of_count"] == "3" and pat["member_of_assigned"] == "2"
    assert pat["member_of"] == "Project Atlas (Team) ; Partners ; All Users (dynamic)"  # assigned first, Teams first, dynamic last
    assert by_name(rows, "Sam Supplier")["member_of_count"] == "0"


def test_guests_csv_leaves_memberships_blank_when_not_checked(client):
    c = sqlite3.connect("instance/demo.sqlite")
    c.execute("UPDATE guests SET scanned_at = NULL WHERE id = 'gst-1'")
    c.commit()
    c.close()
    pat = by_name(fetch(client, "guests")[1], "Pat Partner")
    assert pat["memberships_checked"] == "no" and pat["member_of_count"] == "" and pat["member_of_assigned"] == "" and pat["member_of"] == ""


def test_members_csv_has_licences_ad_sync_and_state(client):
    _, rows = fetch(client, "members")
    gary = by_name(rows, "Gone Gary")
    assert gary["account_enabled"] == "no" and gary["synced_from_ad"] == "yes" and gary["licences"] == "FLOW_FREE, SPE_E3"
    assert "DISABLED_LICENSED_MEMBER" in gary["flags"] and gary["last_sign_in_at"] and gary["created_at"]
    assert by_name(rows, "Idle Ivan")["synced_from_ad"] == "no"
    assert {r["display_name"] for r in rows} == {"Gone Gary", "Idle Ivan", "Ghost Gina", "Free Fred", "Ex Employee"}   # + two leftover disabled accounts


def test_mailboxes_csv_has_permissions_and_activity(client):
    r, rows = fetch(client, "mailboxes")
    old = by_name(rows, "Old Projects")
    assert old["type"] == "SharedMailbox" and old["full_access"] == "ex@contoso.example" and old["send_as"] == "gone@contoso.example"
    assert old["checked"] == "yes" and old["last_mail_seen"] == "" and "MAILBOX_NO_DELEGATES" in old["flags"]
    assert {x["display_name"] for x in rows} == {"Old Projects", "Billing Inbox", "Unused Room B"}


def test_rules_csv_lists_state_mode_and_addresses(client):
    r, rows = fetch(client, "rules")
    legal = by_name(rows, "Old legal hold copy", "rule")
    assert legal["state"] == "Disabled" and "legal@contoso.example" in legal["addresses"] and "RULE_DISABLED" in legal["flags"]
    assert by_name(rows, "Audit external forwarding", "rule")["mode"] == "Audit"
