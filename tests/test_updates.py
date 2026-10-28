"""Windows update policies: the pure checks, the overlap rule, and the Updates tab on the demo tenant."""
import re
from datetime import datetime, timedelta, timezone

import pytest

from broom365 import create_app
from broom365.models.types import FlagCode as F, IntuneAssignment, Thresholds, UpdatePolicyFacts
from broom365.services.updates import evaluate_update_policy, summarize, targets_text

NOW = datetime(2026, 10, 28, tzinfo=timezone.utc)
T = Thresholds()


def iso(days):
    return (NOW + timedelta(days=days)).isoformat()


def group(name="Pilot", members=5, mode="include"):
    return IntuneAssignment("group", mode, "", f"id-{name}", name, members)


def policy(kind="ring", assignments=None, **kw):
    settings = kw.pop("settings", {})
    base = dict(id="p1", kind=kind, display_name="P", created_at=NOW - timedelta(days=400), modified_at=NOW - timedelta(days=10),
                assignments=tuple(assignments if assignments is not None else [group()]), settings=settings)
    base.update(kw)
    return UpdatePolicyFacts(**base)


def codes(a):
    return {f.code for f in a.flags}


RING_OK = {"deadlineForQualityUpdatesInDays": 2, "deadlineForFeatureUpdatesInDays": 5, "qualityUpdatesPaused": False, "featureUpdatesPaused": False}


# ------------------------------------------------------------- pure checks ----
def test_a_healthy_ring_has_no_findings():
    assert evaluate_update_policy(policy(settings=RING_OK), T, NOW).flags == ()


def test_assigned_to_nobody_and_empty_targets():
    a = evaluate_update_policy(policy(assignments=[], settings=RING_OK), T, NOW)
    assert codes(a) == {F.UPDATE_UNASSIGNED} and "Candidate for review" in a.flags[0].explanation
    only_exclusion = evaluate_update_policy(policy(assignments=[group(mode="exclude")], settings=RING_OK), T, NOW)
    assert codes(only_exclusion) == {F.UPDATE_UNASSIGNED}
    empty = evaluate_update_policy(policy(assignments=[group("A", 0), group("B", 0)], settings=RING_OK), T, NOW)
    assert codes(empty) == {F.UPDATE_EMPTY_TARGETS} and empty.risk.value == "MEDIUM"
    unknown = evaluate_update_policy(policy(assignments=[group("A", None)], settings=RING_OK), T, NOW)
    assert not unknown.flags       # an unscanned group is not an empty one


def test_a_ring_without_deadlines_names_which_ones_are_missing():
    a = evaluate_update_policy(policy(settings={**RING_OK, "deadlineForFeatureUpdatesInDays": None}), T, NOW)
    assert codes(a) == {F.UPDATE_NO_DEADLINE} and a.risk.value == "MEDIUM"
    assert "no feature update deadline" in a.flags[0].explanation and "quality" not in a.flags[0].explanation
    both = evaluate_update_policy(policy(settings={}), T, NOW)
    assert "no quality and no feature" in both.flags[0].explanation


def test_a_pause_is_medium_while_active_and_low_once_it_has_lapsed():
    active = evaluate_update_policy(policy(settings={**RING_OK, "qualityUpdatesPaused": True, "qualityUpdatesPauseExpiryDateTime": iso(12)}), T, NOW)
    assert codes(active) == {F.UPDATE_PAUSED} and active.risk.value == "MEDIUM" and "paused on this ring until 2026-11-09" in active.flags[0].explanation
    lapsed = evaluate_update_policy(policy(settings={**RING_OK, "featureUpdatesPaused": True, "featureUpdatesPauseExpiryDateTime": iso(-3)}), T, NOW)
    assert lapsed.risk.value == "LOW" and "35 days" in lapsed.flags[0].explanation


@pytest.mark.parametrize("days,risk", [(-30, "HIGH"), (90, "MEDIUM")])
def test_a_feature_profile_on_a_version_out_of_support_or_nearly(days, risk):
    a = evaluate_update_policy(policy("feature", settings={"featureUpdateVersion": "Windows 11, version 24H2", "endOfSupportDate": iso(days)}), T, NOW)
    assert codes(a) == {F.UPDATE_FEATURE_ENDING} and a.risk.value == risk and "24H2" in a.flags[0].explanation


def test_a_feature_profile_far_from_the_end_of_support_is_fine():
    assert not evaluate_update_policy(policy("feature", settings={"featureUpdateVersion": "25H2", "endOfSupportDate": iso(900)}), T, NOW).flags
    assert not evaluate_update_policy(policy("feature", settings={"featureUpdateVersion": "25H2"}), T, NOW).flags   # date unknown: nothing guessed
    assert codes(evaluate_update_policy(policy("feature", settings={"endOfSupportDate": iso(200)}), Thresholds(eos_warning_days=365), NOW)) == {F.UPDATE_FEATURE_ENDING}


def test_driver_profiles_wait_only_with_manual_approval():
    waiting = evaluate_update_policy(policy("driver", settings={"approvalType": "manual", "newUpdates": 3}), T, NOW)
    assert codes(waiting) == {F.UPDATE_DRIVERS_WAITING} and "3 new driver update" in waiting.flags[0].explanation
    assert not evaluate_update_policy(policy("driver", settings={"approvalType": "automatic", "newUpdates": 3}), T, NOW).flags
    assert not evaluate_update_policy(policy("driver", settings={"approvalType": "manual", "newUpdates": 0}), T, NOW).flags


def test_an_old_expedite_profile_is_stale_and_the_threshold_is_configurable():
    old = policy("quality", modified_at=NOW - timedelta(days=200))
    assert codes(evaluate_update_policy(old, T, NOW)) == {F.UPDATE_STALE_EXPEDITE}
    assert not evaluate_update_policy(old, Thresholds(stale_days_expedite=365), NOW).flags


def test_overlap_names_the_other_policies_and_never_says_delete():
    a = evaluate_update_policy(policy("feature", overlaps=("Other A", "Other B"), settings={"featureUpdateVersion": "25H2", "endOfSupportDate": iso(900)}), T, NOW)
    assert codes(a) == {F.UPDATE_OVERLAP} and "'Other A', 'Other B'" in a.flags[0].explanation
    assert "delete" not in a.flags[0].explanation.lower()


def test_summaries_and_targets_read_well():
    ring = policy(settings={"qualityUpdatesDeferralPeriodInDays": 2, "deadlineForQualityUpdatesInDays": 5, "featureUpdatesPaused": True})
    assert "Quality: defer 2 d, deadline 5 d" in summarize(ring) and "deadline not set" in summarize(ring) and "paused: feature" in summarize(ring)
    assert targets_text(policy(assignments=[group("Pilot", 5), group("VIP", 2, "exclude")])) == "'Pilot' (5 members) (excluding VIP)"
    assert targets_text(policy(assignments=[])) == "nobody"
    expedite = policy("quality", settings={"expeditedUpdateSettings": {"qualityUpdateRelease": "2026-02-10T00:00:00Z", "daysUntilForcedReboot": 2}})
    assert summarize(expedite) == "Release 2026-02-10 · forced restart after 2 d"
    assert "support ends 2026-12-01" in summarize(policy("feature", settings={"featureUpdateVersion": "X", "endOfSupportDate": "2026-12-01T00:00:00Z"}))


# ------------------------------------------------------------- the demo tab ---
@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BROOM_DEMO", "1")
    return create_app().test_client()


def test_the_updates_tab_lists_every_policy_with_its_findings(client):
    html = client.get("/?tab=updates").get_data(as_text=True)
    for name in ("Update ring - Pilot", "Update ring - Broad", "Windows 11 24H2 - everyone", "Windows 11 25H2 - pilot and staff",
                 "Windows 11 26H2 - next", "Expedite critical fix", "Drivers - manual approval"):
        assert name in html
    assert "Wi-Fi corporate profile" not in html        # a custom profile is not an update policy
    for code in ("UPDATE_NO_DEADLINE", "UPDATE_PAUSED", "UPDATE_FEATURE_ENDING", "UPDATE_OVERLAP", "UPDATE_UNASSIGNED",
                 "UPDATE_STALE_EXPEDITE", "UPDATE_DRIVERS_WAITING"):
        assert code in html
    assert "Quality: defer 7 d, deadline not set" in html


def test_the_summary_strip_counts_what_the_table_shows(client):
    html = client.get("/?tab=updates").get_data(as_text=True)
    by_label = {label: int(n) for n, label in re.findall(r'<span class="num">(\d+)</span>\s*<span class="lbl">([^<]+)</span>', html)}
    assert by_label["Update policies"] == 7 and by_label["With findings"] == 6 and by_label["Assigned to nobody"] == 1
    assert by_label["Overlapping"] == 2 and by_label["Rings without deadline"] == 1 and by_label["Version out of support"] == 1
    assert 'data-tag="overlap"' in html


def test_the_updates_tab_exports_the_flagged_policies_as_csv(client):
    client.get("/?tab=updates")
    csv = client.get("/export/updates").get_data(as_text=True).lstrip("﻿")
    assert csv.splitlines()[0].startswith("policy_id,display_name,kind,settings,assigned_to,overlaps_with")
    assert len(csv.splitlines()) == 7 and "Windows 11 24H2 - everyone" in csv and "Expedite critical fix" in csv
    assert "Update ring - Pilot" not in csv      # nothing flagged on it


def test_a_group_used_only_by_an_update_policy_counts_as_used(client):
    client.get("/?tab=updates")
    page = client.get("/groups/g-17").get_data(as_text=True)      # the pilot group: targeted by a ring, two profiles and an expedite profile
    assert "Intune feature update profiles" in page and "Windows 11 25H2 - pilot and staff" in page and "Update ring - Pilot" in page
