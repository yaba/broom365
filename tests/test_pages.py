"""Smoke tests for the pages, served from the synthetic demo tenant (no Graph, no sign-in)."""
import re
from datetime import datetime, timezone

import pytest

from broom365 import create_app
from broom365.models.types import Credential
from broom365.services.extended_signals import credential_status

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BROOM_DEMO", "1")
    return create_app().test_client()


def ids(client, table):
    import sqlite3
    conn = sqlite3.connect("instance/demo.sqlite")
    try:
        return {r[1]: r[0] for r in conn.execute(f"SELECT id, display_name FROM {table}")}
    finally:
        conn.close()


def test_each_tab_lists_only_its_own_type_and_links_to_details(client):
    groups = client.get("/?tab=groups").get_data(as_text=True)
    apps = client.get("/?tab=apps").get_data(as_text=True)
    users = client.get("/?tab=users").get_data(as_text=True)
    assert 'href="/groups/g-0"' in groups and 'href="/apps/' not in groups and 'href="/users/' not in groups
    assert 'href="/apps/ap-0"' in apps and 'href="/groups/g-' not in apps and 'href="/users/' not in apps
    assert 'href="/users/u-ann"' in users and 'href="/groups/g-' not in users and 'href="/apps/ap-' not in users
    assert client.get("/").get_data(as_text=True) == groups  # groups is the default tab
    assert client.get("/?tab=bogus").get_data(as_text=True) == groups


def test_scan_panel_only_for_the_active_tab(client):
    groups = client.get("/?tab=groups").get_data(as_text=True)
    apps = client.get("/?tab=apps").get_data(as_text=True)
    users = client.get("/?tab=users").get_data(as_text=True)
    assert 'data-kind="groups"' in groups and 'data-kind="apps"' not in groups
    assert 'data-kind="apps"' in apps and 'data-kind="groups"' not in apps
    assert "data-kind=" not in users and "no scan scope is needed" in users


def test_users_tab_shows_every_privileged_user_including_unflagged(client):
    html = client.get("/?tab=users").get_data(as_text=True)
    assert 'href="/users/u-bob"' in html  # Bob signs in regularly: no flags, still listed
    assert "Exchange Administrator" in html and "DORMANT_PRIVILEGED_USER" in html


def test_tab_badges_count_flagged_objects_per_type(client):
    html = client.get("/").get_data(as_text=True)
    assert re.search(r'Flagged groups">\d+<', html) and re.search(r'Flagged users">\d+<', html)


def test_group_page_has_portal_links_and_usage_coverage(client):
    html = client.get("/groups/b62bc900-0000-0000-0000-000000000000").status_code
    assert html == 404
    page = client.get("/groups/g-12").get_data(as_text=True)  # win10-app-deployment-office, assigned to the Intune app
    assert "Where this group is used" in page and "Microsoft Office 365" in page
    assert "Not checked by Broom365" in page


def test_group_detail_explains_orphaned_assignment(client):
    r = client.get("/groups/g-0")  # CRM Legacy Users -> deleted SP
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and "ORPHANED_APP_ASSIGNMENT" in html
    assert "Does not exist" in html and "CRM Legacy" in html
    assert "safe to delete" not in html.lower()


def test_unscanned_group_shows_notice_and_no_findings(client):
    html = client.get("/groups/g-12").get_data(as_text=True)  # win10-app-deployment-office, excluded from the demo scan
    assert "Not scanned yet" in html and "<h2>Findings</h2>" not in html


def test_app_detail_shows_credentials_permissions_and_highlights_risky(client):
    html = client.get("/apps/ap-0").get_data(as_text=True)  # Legacy CRM Sync
    assert "Expired" in html and "Mail.Read" in html and "HIGH-RISK LIST" in html
    assert "LIKELY_ABANDONED_APP" in html


def test_app_detail_lists_assigned_groups(client):
    html = client.get("/apps/ap-1").get_data(as_text=True)  # HR Portal
    assert "HR Portal Users" in html


def test_user_detail(client):
    html = client.get("/users/u-ann").get_data(as_text=True)
    assert "Global Administrator" in html and "DORMANT_PRIVILEGED_USER" in html


def test_unknown_ids_404(client):
    assert client.get("/groups/nope").status_code == 404
    assert client.get("/apps/nope").status_code == 404
    assert client.get("/users/nope").status_code == 404


def test_no_literal_unicode_escapes_leak_into_pages(client):
    for url in ("/", "/groups/g-0", "/groups/g-12", "/apps/ap-0", "/users/u-ann"):
        assert "\\u2014" not in client.get(url).get_data(as_text=True), url


# ------------------------------------------------------- credential_status ---
def cred(end):
    return Credential("k", "password", "s", end)


def test_credential_status_kinds():
    from datetime import timedelta
    assert credential_status(cred(NOW - timedelta(days=5)), NOW, 30) == ("expired", "Expired 5 days ago")
    assert credential_status(cred(NOW + timedelta(days=10)), NOW, 30)[0] == "expiring"
    assert credential_status(cred(NOW + timedelta(days=90)), NOW, 30)[0] == "valid"
    assert credential_status(cred(None), NOW, 30)[0] == "unknown"


def test_unscanned_app_page_shows_inventory_credentials_without_findings(client):
    import sqlite3
    conn = sqlite3.connect("instance/demo.sqlite")
    conn.execute("UPDATE applications SET scanned_at = NULL WHERE id = 'ap-0'")
    conn.commit()
    conn.close()
    r = client.get("/apps/ap-0")
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and "Not scanned yet" in html
    assert "Expired" in html  # credentials arrive with the inventory
    assert "<h2>Findings</h2>" not in html and "<h2>Permissions" not in html


def test_intune_tab_lists_cleanup_candidates_with_portal_link_and_no_scan_panel(client):
    html = client.get("/?tab=intune").get_data(as_text=True)
    for name in ("Adobe Acrobat 2024", "Adobe Reader 2023", "Unassigned helper", "7-Zip 22.00"):
        assert name in html, name
    assert "UNINSTALL_ONLY_APP" in html and "UNASSIGNED_APP" in html
    for name in ("Microsoft Office 365", "Google Chrome", "7-Zip 23.01", "VC++ runtime"):
        assert f'class="name">{name}' not in html, name  # installed, assigned, or a dependency another app needs (not a row)
    assert 'data-kind="intune"' in html and 'data-kind="groups"' not in html and "only uninstall assignments" in html
    assert 'href="/groups/' not in html and 'href="/apps/' not in html  # no detail pages for Intune apps


def test_superseded_unassigned_app_explains_the_supersedence_risk(client):
    html = client.get("/?tab=intune").get_data(as_text=True)
    assert "superseded by &#39;7-Zip 23.01&#39; (assigned)" in html and "no longer be upgraded" in html


def test_scripts_tab_lists_obsolete_scripts_and_remediations(client):
    html = client.get("/?tab=scripts").get_data(as_text=True)
    for name in ("Install legacy VPN client", "Old registry fix", "Legacy detection"):
        assert name in html, name
    for name in ("Map network drives", "Clear temp files"):
        assert name not in html, name
    assert "LIKELY_OBSOLETE_SCRIPT" in html and "FAILING_SCRIPT" in html and "EMPTY_TARGETS_SCRIPT" in html
    assert "PowerShell script" in html and "Remediation" in html
    assert 'data-kind="scripts"' in html and 'data-kind="intune"' not in html


def test_script_targets_count_as_group_usage(client):
    html = client.get("/groups/g-4").get_data(as_text=True)  # Contractors 2019: empty, referenced only by a script
    assert "Intune PowerShell scripts" in html and "Install legacy VPN client" in html
    assert "Intune macOS shell scripts" in html and "Intune remediations" in html


def test_badges_and_cards_for_the_intune_tabs(client):
    html = client.get("/").get_data(as_text=True)
    assert re.search(r'Flagged intune">4<', html) and re.search(r'Flagged scripts">3<', html)
    assert "Unassigned Intune apps" in client.get("/?tab=intune").get_data(as_text=True)
    assert "Likely obsolete scripts" in client.get("/?tab=scripts").get_data(as_text=True)


def test_checking_intune_apps_from_the_ui_reads_only_what_was_selected(client):
    import sqlite3, time
    from broom365.services import sync_runner
    tok = re.search(r'name="csrf-token" content="([^"]+)"', client.get("/?tab=intune").get_data(as_text=True)).group(1)
    conn = sqlite3.connect("instance/demo.sqlite")
    conn.execute("UPDATE intune_apps SET scanned_at = NULL"); conn.execute("DELETE FROM intune_app_relationships"); conn.commit()
    assert client.post("/sync/scan/intune", json={"patterns": "7-Zip 22*"}, headers={"X-CSRF-Token": tok}).get_json()["started"] is True
    for _ in range(100):
        if not sync_runner.is_running():
            break
        time.sleep(0.1)
    assert conn.execute("SELECT COUNT(*) FROM intune_apps WHERE scanned_at IS NOT NULL").fetchone()[0] == 1
    assert conn.execute("SELECT group_concat(app_id) FROM intune_app_relationships").fetchone()[0] == "app-7"
    saved = client.get("/?tab=intune").get_data(as_text=True)
    assert "7-Zip 22*" in saved and "1 of 9 Intune apps checked" in saved
    assert client.post("/sync/scan/nonsense", json={}, headers={"X-CSRF-Token": tok}).status_code == 404
    conn.close()


def test_users_tab_marks_disabled_accounts(client):
    html = client.get("/?tab=users").get_data(as_text=True)
    assert html.count(">Disabled</span>") == 1
    row = html[html.index("Dan Disabled") - 400:html.index("Dan Disabled") + 600]
    assert "Disabled</span>" in row and "Helpdesk Administrator" in row
    assert "Disabled account that still holds directory role" in html and "Dormant admin access needs manual review" in html


def test_user_detail_shows_disabled_state(client):
    dan = client.get("/users/u-dan").get_data(as_text=True)
    ann = client.get("/users/u-ann").get_data(as_text=True)
    assert "Disabled</span> <span class=\"muted\">(cannot sign in)" in dan and "Disabled</span>" not in ann and "Enabled" in ann


def test_guests_tab_lists_stale_and_pending_guests_only(client):
    html = client.get("/?tab=guests").get_data(as_text=True)
    for name in ("Pat Partner", "Second Partner", "Never Nick", "Old Disabled", "Sam Supplier"):
        assert f'class="name">{name}' in html or name in html, name
    for name in ("Active Ann", "New Nora"):
        assert f'<td class="name">{name}' not in html and f">{name}<" not in html, name
    assert "STALE_GUEST" in html and "PENDING_GUEST" in html and "from partner-corp.com" in html
    assert 'data-kind="guests"' in html and 'data-kind="intune"' not in html and "Invite pending" in html and 'href="/users/' not in html
    assert html.count(">Disabled</span>") == 1  # Old Disabled


def test_guests_tab_badge_and_cards(client):
    assert re.search(r'Flagged guests">5<', client.get("/").get_data(as_text=True))
    html = client.get("/?tab=guests").get_data(as_text=True)
    assert "Stale guests" in html and "Pending invitations" in html


def test_users_tab_marks_external_and_disabled_admins_apart(client):
    html = client.get("/?tab=users").get_data(as_text=True)
    assert html.count(">External</span>") == 1 and "Gus Guest" in html
    assert "EXTERNAL_PRIVILEGED_USER" in html and "DISABLED_PRIVILEGED_USER" in html and "DORMANT_PRIVILEGED_USER" in html
    assert "external (guest) account" in html


def test_guests_settings_thresholds_are_editable(client):
    html = client.get("/settings").get_data(as_text=True)
    assert "Stale guest (days)" in html and "Pending invitation (days)" in html


def test_guests_tab_offers_company_chips_ordered_by_count(client):
    html = client.get("/?tab=guests").get_data(as_text=True)
    assert 'data-q="partner-corp.com"' in html and "partner-corp.com <b>2</b>" in html  # two flagged guests from that company
    assert html.index("partner-corp.com <b>2</b>") < html.index('data-q="vendor.example"')  # biggest first
    assert 'data-q=""' in html  # reset chip
    assert 'data-q' not in client.get("/?tab=groups").get_data(as_text=True)


def test_checking_guests_from_the_ui_by_company_domain(client):
    import sqlite3, time
    from broom365.services import sync_runner
    tok = re.search(r'name="csrf-token" content="([^"]+)"', client.get("/?tab=guests").get_data(as_text=True)).group(1)
    conn = sqlite3.connect("instance/demo.sqlite")
    conn.execute("UPDATE guests SET scanned_at = NULL"); conn.execute("DELETE FROM guest_memberships"); conn.commit()
    pv = client.get("/scope/preview", query_string={"kind": "guests", "patterns": "partner-corp.com"}).get_json()
    assert pv["matched"] == 2 and pv["total"] == 7 and set(pv["sample"]) == {"Pat Partner", "Second Partner"}
    assert client.post("/sync/scan/guests", json={"patterns": "partner-corp.com"}, headers={"X-CSRF-Token": tok}).get_json()["started"] is True
    for _ in range(100):
        if not sync_runner.is_running():
            break
        time.sleep(0.1)
    assert conn.execute("SELECT COUNT(*) FROM guests WHERE scanned_at IS NOT NULL").fetchone()[0] == 2
    page = client.get("/?tab=guests").get_data(as_text=True)
    assert "2 of 7 guests checked" in page and "still a member of 2 group(s) by assignment: &#39;Project Atlas&#39; (Team), &#39;Partners&#39;" in page
    conn.close()


def test_guests_tab_explains_open_access_for_checked_guests(client):
    html = client.get("/?tab=guests").get_data(as_text=True)  # the demo seeds a full guest check
    assert "(Team)" in html and "member of no group" in html


def test_internal_users_tab_lists_only_the_cleanup_candidates_with_tags(client):
    html = client.get("/?tab=members").get_data(as_text=True)
    for name in ("Gone Gary", "Idle Ivan", "Ghost Gina", "Free Fred", "Ex Employee"):
        assert f'class="name">{name}' in html, name
    for name in ("Active Alice", "New Nina", "Service Sam", "Shared Support"):    # Shared Support is a mailbox: disabled by design
        assert f'class="name">{name}' not in html, name
    assert "DISABLED_LICENSED_MEMBER" in html and "STALE_MEMBER" in html and "DISABLED_MEMBER" in html and "paid licence(s): SPE_E3" in html
    assert html.count(">Disabled</span>") == 3 and "title=\"Synced from on-premises Active Directory" in html
    assert html.count("data-kind=") == 1 and 'data-kind="mailbox_types"' in html and 'href="/users/' not in html


def test_internal_users_badge_cards_and_threshold(client):
    assert re.search(r'Flagged members">5<', client.get("/").get_data(as_text=True))
    html = client.get("/?tab=members").get_data(as_text=True)
    assert "Stale internal users" in html and "Disabled with licences" in html
    assert "Stale internal user (days)" in client.get("/settings").get_data(as_text=True)


def test_distribution_lists_tab_flags_the_demo_lists_and_offers_a_scope_panel(client):
    html = client.get("/?tab=dls").get_data(as_text=True)
    assert 'data-kind="dls"' in html
    names = ids(client, "distribution_lists")
    assert len(names) == 6


def test_guests_show_the_invitation_date_and_can_be_sorted_by_it(client):
    html = client.get("/?tab=guests").get_data(as_text=True)
    assert 'id="f-sort"' in html and "Invited:" in html and 'data-invited="' in html
    assert 'id="f-sort"' not in client.get("/?tab=groups").get_data(as_text=True)


def test_shared_mailboxes_tab_lists_the_findings_and_offers_the_check(client):
    html = client.get("/?tab=mailboxes").get_data(as_text=True)
    assert 'data-kind="mailboxes"' in html and 'data-kind="mailbox_types"' in html           # the check, and re-reading the list
    assert "Old Projects" in html and "MAILBOX_NO_DELEGATES" in html and "Unused Room B" in html
    assert "Shared Support" not in html and "Conference Room A" not in html                  # used mailboxes are not listed
    assert '<span class="pill" title="Room mailbox">Room</span>' in html


def test_mail_flow_rules_tab_lists_the_rules_with_findings(client):
    html = client.get("/?tab=rules").get_data(as_text=True)
    for name in ("Old legal hold copy", "Campaign footer", "Audit external forwarding", "Notify the former project team"):
        assert name in html
    assert "Archive finance mail" not in html and "RULE_DEAD_REFERENCE" in html and "RULE_EXPIRED" in html


def test_the_new_tabs_have_their_counts_and_cards(client):
    html = client.get("/").get_data(as_text=True)
    assert "Shared mailboxes" in html and "Mail flow rules" in html
    assert "Likely unused mailboxes" in client.get("/?tab=mailboxes").get_data(as_text=True)
    assert "Rules with dead references" in client.get("/?tab=rules").get_data(as_text=True)


def test_mailbox_scope_preview_counts_the_mailboxes_read_from_exchange(client):
    r = client.get("/scope/preview?kind=mailboxes&patterns=*room*").get_json()
    assert r["total"] == 5 and r["matched"] == 2
    assert client.get("/scope/preview?kind=mailbox_types").status_code == 400


def tiles(html):
    import re
    return [(re.sub(r"\s+", " ", m.group(2)).strip(), m.group(1))
            for m in re.finditer(r'<button type="button" class="tile[^"]*"[^>]*>\s*<span class="num">(.*?)</span>\s*<span class="lbl">(.*?)</span>', html, re.S)][:0] or \
           [(m.group(2).strip(), m.group(1).strip()) for m in re.finditer(r'<span class="num">(.*?)</span>\s*<span class="lbl">(.*?)</span>', html, re.S)]


def test_apps_tab_has_the_six_summary_tiles_and_lists_every_app(client):
    html = client.get("/?tab=apps").get_data(as_text=True)
    assert dict(tiles(html)) == {"App registrations": "8", "Expired secrets": "3", "Apps with no owner": "2", "Older than a year": "8",
                                 "Younger than a month": "0", "High-risk Graph permissions": "3"}
    assert html.count("<tr data-risk=") == 8 and 'data-tag="expired"' in html and 'data-tag="risky"' in html
    assert 'class="cards"' not in html                                  # the old wall of counters is gone


def test_each_tab_shows_only_its_own_summary(client):
    assert "Orphaned app assignments" in client.get("/?tab=groups").get_data(as_text=True)
    assert "Orphaned app assignments" not in client.get("/?tab=apps").get_data(as_text=True)
    members = dict(tiles(client.get("/?tab=members").get_data(as_text=True)))
    assert members == {"Stale internal users": "2", "Disabled with licences": "1", "Leftover disabled accounts": "2"}


def test_apps_not_yet_checked_are_never_counted_as_having_no_owner_or_no_risk(client):
    import sqlite3
    c = sqlite3.connect("instance/demo.sqlite")
    c.execute("UPDATE applications SET scanned_at = NULL, owner_count = NULL")
    c.commit()
    c.close()
    html = client.get("/?tab=apps").get_data(as_text=True)
    t = dict(tiles(html))
    assert t["Apps with no owner"] == "&mdash;" and t["High-risk Graph permissions"] == "&mdash;" and t["App registrations"] == "8"
    assert html.count("not checked") >= 16 and "check apps to find out" in html
