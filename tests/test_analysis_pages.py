"""What a tab shows before and after it is analysed, the routes that start the jobs, and the progress bar on every page."""
import re
import sqlite3

import pytest

from broom365.services import repository as repo
from broom365.services.sync import run_analysis, run_counts
from tests.test_accounts import admin, cfg, connect, make  # noqa: F401 (fixtures)
from tests.test_analysis import NOW, CountingGraph
from tests.test_sync import ALL_SCOPES


def db(cfg):
    c = sqlite3.connect(cfg.database_path)
    c.row_factory = sqlite3.Row
    return c


@pytest.fixture()
def counted(admin, cfg):
    """A signed-in, connected admin, and a tenant whose objects were only counted."""
    connect(admin)
    c = db(cfg)
    run_counts(c, CountingGraph(), ALL_SCOPES, now=NOW)
    c.close()
    return admin


def test_nothing_is_shown_before_the_objects_are_counted(admin):
    connect(admin)
    html = admin.get("/").get_data(as_text=True)
    assert "Nothing counted yet" in html and "Count objects" in html and 'id="objects"' not in html


def test_a_tab_that_was_not_analysed_shows_its_total_and_one_button_and_no_findings(counted):
    html = counted.get("/?tab=apps").get_data(as_text=True)
    assert "<strong>119</strong> apps in the tenant" in html and "Not analysed yet" in html
    assert 'class="btn analyse" data-tab="apps"' in html and "Analyse apps" in html
    assert 'id="objects"' not in html and 'class="strip"' not in html and 'class="count"' not in html      # no table, no tiles, no badges
    assert "the app registrations with their secrets and age" in html and "Nothing else is read" in html


def test_every_unanalysed_tab_says_what_analysing_it_reads(counted):
    for tab, words in (("users", "directory role"), ("intune", "Intune apps"), ("scripts", "remediations"), ("updates", "update rings"),
                       ("guests", "external (guest) users"), ("members", "internal users"), ("dls", "distribution lists"), ("rules", "mail flow rules")):
        html = counted.get(f"/?tab={tab}").get_data(as_text=True)
        assert f'data-tab="{tab}"' in html and words in html and "Not analysed yet" in html, tab


def test_groups_and_mailboxes_have_their_own_first_step(counted):
    groups = counted.get("/?tab=groups").get_data(as_text=True)
    assert "<strong>2202</strong>" in groups and 'id="scope-groups"' in groups and 'data-tab="groups"' not in groups
    mail = counted.get("/?tab=mailboxes").get_data(as_text=True)
    assert 'data-kind="mailbox_types"' in mail and 'data-tab="mailboxes"' not in mail


def test_after_analysing_one_tab_only_that_tab_shows_data(counted, cfg):
    c = db(cfg)
    run_analysis(c, CountingGraph(), ALL_SCOPES, "apps", now=NOW)
    c.close()
    apps = counted.get("/?tab=apps").get_data(as_text=True)
    assert "Analysed" in apps and "Analyse again" in apps and 'id="objects"' in apps and "Old CRM" in apps and "EXPIRED_SECRET" in apps
    assert "Not analysed yet" in counted.get("/?tab=groups").get_data(as_text=True)         # the groups were not touched
    assert apps.count('class="count"') == 1                                                  # a badge only on the tab that was analysed


def test_the_header_says_what_was_counted_and_how_much_was_analysed(counted):
    html = counted.get("/").get_data(as_text=True)
    assert "Totals counted" in html and "nothing analysed yet" in html and ">Count objects<" in html


def test_every_page_carries_the_job_bar_and_the_dashboard_keeps_its_own(counted):
    assert "jobbar.js" in counted.get("/settings").get_data(as_text=True) and "jobbar.js" in counted.get("/accounts").get_data(as_text=True)
    js = counted.get("/static/jobbar.js").get_data(as_text=True)
    assert "/sync/status" in js and "keep browsing" in js and "sync-progress" in js


# ------------------------------------------------------------------- routes ---
def test_the_buttons_start_the_right_jobs(counted, monkeypatch):
    started = []

    def fake_start(factory, job):
        started.append(job)
        return True

    calls = []
    monkeypatch.setattr("broom365.dashboard.sync_runner.start_job", fake_start)
    monkeypatch.setattr("broom365.dashboard.run_counts", lambda conn, graph, scopes, **k: calls.append(("counts",)))
    monkeypatch.setattr("broom365.dashboard.run_analysis", lambda conn, graph, scopes, tab, **k: calls.append(("analyse", tab, k.get("group_patterns"))))
    tok = re.search(r'name="csrf-token" content="([^"]+)"', counted.get("/settings").get_data(as_text=True)).group(1)
    h = {"X-CSRF-Token": tok}
    assert counted.post("/sync/inventory", headers=h).get_json() == {"started": True}
    assert counted.post("/sync/analyse/apps", headers=h).get_json() == {"started": True}
    assert counted.post("/sync/scan/groups", json={"patterns": "win10*"}, headers=h).get_json() == {"started": True}
    for job in started:
        job(None)
    assert calls == [("counts",), ("analyse", "apps", None), ("analyse", "groups", "win10*")]
    assert counted.post("/sync/analyse/nope", headers=h).status_code == 404
    assert counted.post("/sync/analyse/apps").status_code == 400                       # still needs the CSRF token


def test_saving_settings_recomputes_only_what_was_analysed(counted, cfg):
    c = db(cfg)
    run_analysis(c, CountingGraph(), ALL_SCOPES, "apps", now=NOW)
    c.execute("INSERT INTO flagged_objects (object_type, object_id, display_name, risk_level) VALUES ('group', 'g-keep', 'Kept', 'LOW')")
    c.commit()
    c.close()
    from tests.test_settings_export import FORM
    tok = re.search(r'name="csrf-token" content="([^"]+)"', counted.get("/settings").get_data(as_text=True)).group(1)
    r = counted.post("/settings", data={**FORM, "csrf_token": tok}, follow_redirects=True)
    assert "Flags recomputed" in r.get_data(as_text=True)
    c = db(cfg)
    assert c.execute("SELECT COUNT(*) FROM flagged_objects WHERE object_id = 'g-keep'").fetchone()[0] == 1
    c.close()
