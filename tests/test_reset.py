import re
import sqlite3

import pytest

from broom365 import create_app
from broom365.db import reset_database
from broom365.services import sync_runner


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BROOM_DEMO", "1")
    return create_app().test_client()


def token(client):
    return re.search(r'name="csrf-token" content="([^"]+)"', client.get("/settings").get_data(as_text=True)).group(1)


def counts():
    c = sqlite3.connect("instance/demo.sqlite")
    try:
        return {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                for t in ("groups", "applications", "flagged_objects", "sync_runs", "group_usages")}
    finally:
        c.close()


def test_settings_page_has_a_delete_database_section(client):
    html = client.get("/settings").get_data(as_text=True)
    assert "Delete database" in html and 'name="confirm"' in html


def test_wrong_confirmation_deletes_nothing(client):
    before = counts()
    assert before["groups"] > 0
    r = client.post("/settings/reset", data={"confirm": "delete", "csrf_token": token(client)}, follow_redirects=True)
    assert "Nothing was deleted" in r.get_data(as_text=True) and counts() == before


def test_confirmed_reset_empties_everything_and_the_app_still_works(client):
    r = client.post("/settings/reset", data={"confirm": "DELETE", "csrf_token": token(client)}, follow_redirects=True)
    assert "Database deleted" in r.get_data(as_text=True)
    assert all(v == 0 for v in counts().values())
    html = client.get("/").get_data(as_text=True)
    assert "No inventory yet" in html
    # and it can be filled again from scratch
    tok = token(client)
    assert client.post("/sync/inventory", headers={"X-CSRF-Token": tok}).get_json()["started"] is True
    import time
    for _ in range(100):
        if not sync_runner.is_running():
            break
        time.sleep(0.1)
    assert counts()["groups"] > 0


def test_saved_scope_patterns_and_settings_are_wiped_too(client):
    tok = token(client)
    client.post("/sync/scan/groups", json={"patterns": "win10*"}, headers={"X-CSRF-Token": tok})
    for _ in range(100):
        if not sync_runner.is_running():
            break
        import time; time.sleep(0.1)
    client.post("/settings/reset", data={"confirm": "DELETE", "csrf_token": token(client)})
    c = sqlite3.connect("instance/demo.sqlite")
    assert c.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 0
    c.close()


def test_reset_is_refused_while_a_sync_runs(client):
    before = counts()
    assert sync_runner._lock.acquire(blocking=False)
    try:
        r = client.post("/settings/reset", data={"confirm": "DELETE", "csrf_token": token(client)}, follow_redirects=True)
    finally:
        sync_runner._lock.release()
    assert "A sync is running" in r.get_data(as_text=True) and counts() == before


def test_reset_requires_csrf(client):
    assert client.post("/settings/reset", data={"confirm": "DELETE"}).status_code == 400


def test_reset_database_recreates_a_usable_schema(tmp_path):
    c = sqlite3.connect(tmp_path / "x.sqlite")
    c.execute("CREATE TABLE junk (a)")
    reset_database(c)
    names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "junk" not in names and {"groups", "group_usages", "sync_runs", "settings"} <= names
    c.execute("INSERT INTO groups (id, display_name, inventoried_at) VALUES ('g', 'x', 't')")
    c.close()
