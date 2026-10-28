import csv
import io
import re
import sqlite3

import pytest

from broom365 import create_app
from broom365.export import safe_cell
from broom365.settings import parse_form


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BROOM_DEMO", "1")
    return create_app().test_client()


def token(client):
    html = client.get("/settings").get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


FORM = {"stale_days_group": "180", "stale_days_app": "180", "expiring_days": "30", "dormant_days_user": "60",
        "danger_no_signin_days": "90", "stale_days_script": "730", "idle_days_script": "90", "stale_days_guest": "365", "pending_days_guest": "90", "stale_days_member": "180", "stale_days_mailbox": "180", "eos_warning_days": "180", "stale_days_expedite": "90",
        "high_risk_scopes": "Mail.Read\nFiles.ReadWrite.All"}


def flagged_count():
    c = sqlite3.connect("instance/demo.sqlite")
    try:
        return c.execute("SELECT COUNT(*) FROM flagged_objects").fetchone()[0]
    finally:
        c.close()


# ----------------------------------------------------------------- settings --
def test_settings_page_shows_unavailable_signal_with_reason(client):
    html = client.get("/settings").get_data(as_text=True)
    assert "group_audit_activity" in html and "unavailable" in html and "Graph returned 403" in html
    assert "Re-sync inventory from Graph" in html and "Used for" in html


def test_save_updates_thresholds_and_recomputes_flags(client):
    before = flagged_count()
    t = token(client)
    r = client.post("/settings", data={**FORM, "stale_days_group": "3650", "csrf_token": t})
    assert r.status_code == 302
    assert flagged_count() < before  # the audit-less demo has many STALE-only objects; 3650 days clears them
    html = client.get("/settings").get_data(as_text=True)
    assert 'value="3650"' in html and "Flags recomputed" in html


def test_save_changes_high_risk_list(client):
    t = token(client)
    client.post("/settings", data={**FORM, "high_risk_scopes": "Custom.Scope", "csrf_token": t})
    html = client.get("/apps/ap-0").get_data(as_text=True)  # Legacy CRM Sync holds Mail.Read
    assert "HIGH-RISK LIST" not in html


def test_invalid_input_is_rejected_and_nothing_changes(client):
    before = flagged_count()
    t = token(client)
    r = client.post("/settings", data={**FORM, "stale_days_group": "0", "high_risk_scopes": "bad scope!", "csrf_token": t})
    html = r.get_data(as_text=True)
    assert r.status_code == 400 and "Not saved" in html and "Stale group" in html and "bad scope!" in html
    assert flagged_count() == before


def test_parse_form_dedupes_scopes_case_insensitively():
    values, errors = parse_form({**FORM, "high_risk_scopes": "Mail.Read\nmail.read\n\n  Files.ReadWrite.All "})
    assert errors == [] and values["high_risk_scopes"] == ["Mail.Read", "Files.ReadWrite.All"]


# --------------------------------------------------------------------- CSRF --
def test_post_without_csrf_token_is_rejected(client):
    assert client.post("/settings", data=FORM).status_code == 400
    assert client.post("/sync/inventory").status_code == 400
    assert client.post("/sync/scan/groups", json={"patterns": "*"}).status_code == 400


def test_post_with_wrong_token_is_rejected(client):
    token(client)
    assert client.post("/settings", data={**FORM, "csrf_token": "nope"}).status_code == 400


def test_header_token_accepted_for_fetch_endpoints(client):
    t = token(client)
    r = client.post("/sync/inventory", headers={"X-CSRF-Token": t})
    assert r.status_code == 200 and r.get_json()["started"] in (True, False)


# ------------------------------------------------------------------- export --
def test_export_csv_has_one_row_per_flagged_object_with_explanations(client):
    r = client.get("/export")
    assert r.status_code == 200 and r.mimetype == "text/csv"
    assert "attachment" in r.headers["Content-Disposition"]
    rows = list(csv.DictReader(io.StringIO(r.get_data(as_text=True).lstrip("﻿"))))
    assert len(rows) == flagged_count() and rows
    assert rows[0]["risk_level"] == "HIGH"
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    assert [order[x["risk_level"]] for x in rows] == sorted(order[x["risk_level"]] for x in rows)
    orphan = next(x for x in rows if x["display_name"] == "CRM Legacy Users")
    assert "ORPHANED_APP_ASSIGNMENT" in orphan["flags"] and "no longer exists" in orphan["explanations"]
    assert orphan["inventory_at"] and orphan["last_scan_at"] and int(orphan["flag_count"]) >= 1
    assert "safe to delete" not in r.get_data(as_text=True).lower()


@pytest.mark.parametrize("raw,expected", [("=HYPERLINK(1)", "'=HYPERLINK(1)"), ("+1", "'+1"), ("-1", "'-1"),
                                          ("@x", "'@x"), ("Normal", "Normal"), (None, ""), (3, "3")])
def test_safe_cell_neutralises_formula_injection(raw, expected):
    assert safe_cell(raw) == expected


# ------------------------------------------------ the built-in high-risk list ---
def test_the_builtin_list_is_the_default_everywhere_and_has_no_duplicates():
    from broom365.config import DEFAULT_HIGH_RISK_SCOPES
    from broom365.models.types import Thresholds
    low = [s.lower() for s in DEFAULT_HIGH_RISK_SCOPES]
    assert len(low) == len(set(low)) >= 100
    assert Thresholds().high_risk_scopes is DEFAULT_HIGH_RISK_SCOPES  # one source of truth, not two copies
    for old in ("Mail.Read", "Mail.ReadWrite", "Files.ReadWrite.All", "Sites.ReadWrite.All", "Directory.ReadWrite.All",
                "RoleManagement.ReadWrite.Directory", "Application.ReadWrite.All"):
        assert old in DEFAULT_HIGH_RISK_SCOPES
    for added in ("Calendars.Read", "Chat.Read.All", "Policy.ReadWrite.ConditionalAccess", "Sites.Read.All",
                  "TeamsAppInstallation.ReadWriteForUser.All", "Teamwork.Migrate.All", "UserAuthenticationMethod.ReadWrite.All"):
        assert added in DEFAULT_HIGH_RISK_SCOPES


def test_the_two_tiers_are_disjoint_and_together_are_the_full_builtin_list():
    from broom365.config import DEFAULT_BROAD_READ_SCOPES, DEFAULT_HIGH_RISK_SCOPES
    from broom365.models.types import Thresholds
    assert not set(DEFAULT_HIGH_RISK_SCOPES) & set(DEFAULT_BROAD_READ_SCOPES)
    assert len(DEFAULT_HIGH_RISK_SCOPES) + len(DEFAULT_BROAD_READ_SCOPES) == 114
    assert {"Directory.Read.All", "User.Read.All", "Group.Read.All", "AuditLog.Read.All"} <= set(DEFAULT_BROAD_READ_SCOPES)
    assert not any("Write" in s or s.startswith(("Mail.", "Files.", "Chat", "Calendars.", "Sites.")) for s in DEFAULT_BROAD_READ_SCOPES)
    assert Thresholds().broad_read_scopes is DEFAULT_BROAD_READ_SCOPES


def test_an_app_holding_one_of_the_added_permissions_is_flagged_by_default():
    from datetime import datetime, timezone
    from broom365.models.types import AppFacts, FlagCode, Permission, Thresholds
    from broom365.services.extended_signals import evaluate_app
    app = AppFacts("a", "c", "Chat bot", permissions=(Permission("delegated", "Microsoft Graph", "Chat.Read.All"),
                                                       Permission("delegated", "Microsoft Graph", "User.Read")))
    a = evaluate_app(app, Thresholds(), datetime(2026, 10, 25, tzinfo=timezone.utc))
    assert FlagCode.DANGEROUS_PERMISSION in a.codes
    text = next(f for f in a.flags if f.code is FlagCode.DANGEROUS_PERMISSION).explanation
    assert "Chat.Read.All" in text and "User.Read " not in text and "User.Read (" not in text  # plain sign-in permission is not on the list


def test_settings_page_offers_the_builtin_list_and_a_restore_button(client):
    from broom365.config import DEFAULT_HIGH_RISK_SCOPES
    html = client.get("/settings").get_data(as_text=True)
    n = len(DEFAULT_HIGH_RISK_SCOPES)
    assert f"Restore the built-in list ({n})" in html and f"{n} permissions" in html
    assert 'id="restore-scopes"' in html and '"Calendars.Read"' in html  # the list is embedded for the button
    assert "Show the built-in list" in html


def test_a_saved_custom_list_replaces_the_default_and_delete_database_brings_the_default_back(client):
    import sqlite3
    from broom365.config import DEFAULT_HIGH_RISK_SCOPES
    t = token(client)
    client.post("/settings", data={**FORM, "high_risk_scopes": "Custom.One", "csrf_token": t})
    c = sqlite3.connect("instance/demo.sqlite")
    assert "Custom.One" in c.execute("SELECT value FROM settings WHERE name = 'high_risk_scopes'").fetchone()[0]
    c.close()
    assert "Custom.One" in client.get("/settings").get_data(as_text=True)
    client.post("/settings/reset", data={"confirm": "DELETE", "csrf_token": token(client)})
    html = client.get("/settings").get_data(as_text=True)
    assert "Custom.One" not in html and "Chat.Read.All" in html
    c = sqlite3.connect("instance/demo.sqlite")
    from broom365.services.repository import load_thresholds
    assert load_thresholds(c).high_risk_scopes == DEFAULT_HIGH_RISK_SCOPES
    c.close()


def test_settings_page_has_a_separate_editable_broad_read_list(client):
    html = client.get("/settings").get_data(as_text=True)
    assert 'name="broad_read_scopes"' in html and "Broad read permissions (to review)" in html and 'id="restore-broad"' in html
    assert "Directory.Read.All" in html.split('name="broad_read_scopes"')[1].split("</textarea>")[0]


def test_saving_the_broad_list_changes_what_is_reviewed_and_omitting_it_leaves_it_alone(client):
    import sqlite3
    t = token(client)
    client.post("/settings", data={**FORM, "broad_read_scopes": "Custom.Broad.Read", "csrf_token": t})
    c = sqlite3.connect("instance/demo.sqlite")
    assert "Custom.Broad.Read" in c.execute("SELECT value FROM settings WHERE name = 'broad_read_scopes'").fetchone()[0]
    c.close()
    assert "Custom.Broad.Read" in client.get("/settings").get_data(as_text=True)
    client.post("/settings", data={**FORM, "stale_days_group": "200", "csrf_token": token(client)})   # no broad field this time
    assert "Custom.Broad.Read" in client.get("/settings").get_data(as_text=True)


def test_an_invalid_broad_permission_name_is_rejected(client):
    r = client.post("/settings", data={**FORM, "broad_read_scopes": "bad name!", "csrf_token": token(client)})
    assert r.status_code == 400 and "Broad read permissions: &#39;bad name!&#39;" in r.get_data(as_text=True)


def test_app_page_shows_the_two_badges_apart(client):
    html = client.get("/apps/ap-7").get_data(as_text=True)    # Directory Sync Tool holds an application Directory.Read.All
    assert "BROAD READ" in html and "HIGH-RISK LIST" not in html and "BROAD_READ_PERMISSION" in html
    assert "HIGH-RISK LIST" in client.get("/apps/ap-2").get_data(as_text=True)   # Reporting Bot holds Files.ReadWrite.All
