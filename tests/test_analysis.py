"""The inventory only counts; each tab is analysed on its own, reading only what it needs and evaluating only its own kind of object."""
import sqlite3
from datetime import datetime, timezone

import pytest

from broom365.services import repository as repo
from broom365.services.graph import SignalUnavailable
from broom365.services.sync import _Loader, _PLANS, run_analysis, run_counts
from tests.test_sync import ALL_SCOPES, SCHEMA, FakeGraph

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)


class CountingGraph(FakeGraph):
    """FakeGraph that can count, and that fails the test if a list it should not read is read."""

    def __init__(self, forbid=(), **kw):
        super().__init__(**kw)
        self.forbid = set(forbid)
        self.reads: list[str] = []
        self.counted: list[tuple[str, str | None]] = []

    def count(self, url, odata_filter=None):
        self.counted.append((url.rsplit("/", 1)[-1], odata_filter))
        if "applications" in url and "count_apps" in self.deny:
            raise SignalUnavailable(403, url, "denied")
        return {"groups": 2202, "applications": 119, "users": 2872 if odata_filter and "Member" in odata_filter else 2009}[url.rsplit("/", 1)[-1]]

    def __getattribute__(self, name):
        if name.startswith(("list_", "group_", "users_by")) and name in object.__getattribute__(self, "forbid"):
            raise AssertionError(f"{name} must not be read by this analysis")
        if name.startswith(("list_", "group_", "users_by")):
            object.__getattribute__(self, "reads").append(name)
        return object.__getattribute__(self, name)


@pytest.fixture()
def conn(tmp_path):
    c = sqlite3.connect(tmp_path / "t.sqlite")
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA.read_text(encoding="utf-8"))
    yield c
    c.close()


def tables_with_rows(conn, *tables):
    return {t for t in tables if conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]}


# ------------------------------------------------------------------ counts ---
def test_the_inventory_only_counts_and_evaluates_nothing(conn):
    g = CountingGraph()
    run_counts(conn, g, ALL_SCOPES, now=NOW)
    assert {r["kind"]: r["total"] for r in conn.execute("SELECT * FROM inventory_totals")} == {"groups": 2202, "apps": 119, "guests": 2009, "members": 2872}
    assert [c[0] for c in g.counted] == ["groups", "applications", "users", "users"] and g.reads == []          # a few cheap calls, no lists
    assert tables_with_rows(conn, "groups", "applications", "members", "guests", "flagged_objects", "analyses") == set()
    run = conn.execute("SELECT kind, status FROM sync_runs").fetchone()
    assert (run["kind"], run["status"]) == ("inventory", "success")


def test_a_total_that_cannot_be_counted_is_reported_and_the_others_are_kept(conn):
    run_counts(conn, CountingGraph(deny={"count_apps"}), ALL_SCOPES, now=NOW)
    assert {r["kind"] for r in conn.execute("SELECT kind FROM inventory_totals")} == {"groups", "guests", "members"}
    assert conn.execute("SELECT available FROM signal_availability WHERE signal = 'count_apps'").fetchone()[0] == 0
    assert conn.execute("SELECT status FROM sync_runs").fetchone()[0] == "partial"


def test_before_an_analysis_a_tab_shows_what_was_counted_and_after_it_what_was_read(conn):
    run_counts(conn, CountingGraph(), ALL_SCOPES, now=NOW)
    assert repo.tab_total(conn, "apps", analysed=False) == 119 and repo.tab_total(conn, "dls", analysed=False) is None     # Exchange is not counted
    run_analysis(conn, CountingGraph(), ALL_SCOPES, "apps", now=NOW)
    assert repo.tab_total(conn, "apps", analysed=True) == 1


# ---------------------------------------------------------------- analysis ---
def test_analysing_apps_reads_only_apps_and_flags_only_apps(conn):
    g = CountingGraph(forbid={"list_groups", "list_role_assignments", "list_guests", "list_members", "list_with_assignments",
                              "list_conditional_access_policies"})
    run_analysis(conn, g, ALL_SCOPES, "apps", now=NOW)
    assert tables_with_rows(conn, "applications", "service_principals", "app_credentials", "sign_in_activity") == {
        "applications", "service_principals", "app_credentials", "sign_in_activity"}
    assert tables_with_rows(conn, "groups", "role_assignments", "guests", "members", "intune_apps", "group_usages") == set()
    assert {r[0] for r in conn.execute("SELECT DISTINCT object_type FROM flagged_objects")} == {"app"}
    assert "EXPIRED_SECRET" in {r[0] for r in conn.execute("SELECT flag FROM flags WHERE object_type = 'app'")}
    assert set(repo.analysed_map(conn)) == {"apps"}


def test_analysing_groups_leaves_the_apps_alone(conn):
    g = CountingGraph(forbid={"list_applications", "list_guests", "list_members", "list_sp_sign_in_activities"})
    run_analysis(conn, g, ALL_SCOPES, "groups", now=NOW, group_patterns="Admins\nCRM*")
    assert tables_with_rows(conn, "groups", "group_usages", "role_assignments") == {"groups", "group_usages", "role_assignments"} or \
        tables_with_rows(conn, "groups", "role_assignments") == {"groups", "role_assignments"}
    assert tables_with_rows(conn, "applications", "guests", "members") == set()
    assert conn.execute("SELECT COUNT(*) FROM groups WHERE scanned_at IS NOT NULL").fetchone()[0] >= 2          # the selected groups were checked
    assert {r[0] for r in conn.execute("SELECT DISTINCT object_type FROM flagged_objects")} <= {"group", "user"}
    assert set(repo.analysed_map(conn)) == {"groups", "users"}            # the privileged roles came with it


def test_groups_analysis_does_not_overwrite_the_intune_tabs_it_only_borrows_assignments_from(conn):
    run_analysis(conn, CountingGraph(), ALL_SCOPES, "intune", now=NOW)
    apps_before = conn.execute("SELECT COUNT(*), MAX(inventoried_at) FROM intune_apps").fetchone()
    run_analysis(conn, CountingGraph(), ALL_SCOPES, "groups", now=NOW.replace(day=26), group_patterns="")
    assert tuple(conn.execute("SELECT COUNT(*), MAX(inventoried_at) FROM intune_apps").fetchone()) == tuple(apps_before)


def test_analysing_one_intune_tab_keeps_the_assignments_other_sources_recorded(conn):
    run_analysis(conn, CountingGraph(), ALL_SCOPES, "groups", now=NOW, group_patterns="")
    sources = {r[0] for r in conn.execute("SELECT DISTINCT source FROM group_usages")}
    assert "policy_binding" in sources and "intune_apps" in sources
    conn.execute("INSERT INTO group_usages (group_id, source, kind, object_id, object_name, mode, detail) VALUES ('g-ok', 'policy_binding', 'x', 'p9', 'Marker', 'include', NULL)")
    conn.commit()
    run_analysis(conn, CountingGraph(), ALL_SCOPES, "scripts", now=NOW)
    assert conn.execute("SELECT COUNT(*) FROM group_usages WHERE object_id = 'p9'").fetchone()[0] == 1     # Conditional Access was not re-read, not wiped
    assert conn.execute("SELECT COUNT(*) FROM group_usages WHERE source = 'intune_apps'").fetchone()[0] > 0


def test_flags_are_replaced_only_for_the_kind_that_was_analysed(conn):
    conn.execute("INSERT INTO flagged_objects (object_type, object_id, display_name, risk_level) VALUES ('group', 'g-old', 'Old finding', 'LOW')")
    conn.commit()
    run_analysis(conn, CountingGraph(), ALL_SCOPES, "apps", now=NOW)
    assert conn.execute("SELECT COUNT(*) FROM flagged_objects WHERE object_id = 'g-old'").fetchone()[0] == 1
    run_analysis(conn, CountingGraph(), ALL_SCOPES, "apps", now=NOW)
    assert conn.execute("SELECT COUNT(*) FROM flagged_objects WHERE object_id = 'g-old'").fetchone()[0] == 1


def test_the_two_sign_in_tables_do_not_wipe_each_other(conn):
    run_analysis(conn, CountingGraph(), ALL_SCOPES, "apps", now=NOW)
    apps = conn.execute("SELECT COUNT(*) FROM sign_in_activity WHERE object_type = 'servicePrincipal'").fetchone()[0]
    assert apps > 0
    run_analysis(conn, CountingGraph(), ALL_SCOPES, "users", now=NOW)
    assert conn.execute("SELECT COUNT(*) FROM sign_in_activity WHERE object_type = 'servicePrincipal'").fetchone()[0] == apps
    assert conn.execute("SELECT COUNT(*) FROM sign_in_activity WHERE object_type = 'user'").fetchone()[0] > 0


def test_exchange_tabs_need_an_exchange_client_and_say_so_on_the_run(conn):
    with pytest.raises(ValueError, match="app-only mode"):
        run_analysis(conn, CountingGraph(), ALL_SCOPES, "dls", now=NOW, exchange=None)
    run = conn.execute("SELECT status, error FROM sync_runs").fetchone()
    assert run["status"] == "failed" and "app-only mode" in run["error"] and repo.analysed_map(conn) == {}


def test_an_unknown_tab_is_refused(conn):
    with pytest.raises(ValueError):
        run_analysis(conn, CountingGraph(), ALL_SCOPES, "nope", now=NOW)


def test_every_step_of_every_plan_exists():
    for tab, plan in _PLANS.items():
        for step in plan.steps:
            assert hasattr(_Loader, "exchange_" if step == "exchange" else step), (tab, step)
        assert tab in repo.TAB_TYPES and all(a in repo.TAB_TYPES for a in plan.also)


def test_the_full_inventory_used_for_the_demo_still_marks_every_tab_but_the_mailbox_list_as_analysed(conn):
    from broom365.services.sync import run_inventory
    run_inventory(conn, FakeGraph(), ALL_SCOPES, now=NOW)
    assert set(repo.analysed_map(conn)) == set(repo.TAB_TYPES) - {"mailboxes"}
