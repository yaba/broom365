from datetime import datetime, timezone

import pytest

from dataclasses import replace

from broom365.models.types import (
    FlagCode as F, IntuneAppFacts, IntuneAssignment as A, IntuneRelationship as Rel, IntuneScriptFacts, RiskLevel as R, Thresholds,
)
from broom365.services.intune import evaluate_intune_app, evaluate_intune_script

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)
CREATED = datetime(2023, 10, 24, tzinfo=timezone.utc)


def app(*assignments):
    return IntuneAppFacts("a1", "Adobe Illustrator 2024", "win32LobApp", "Adobe", CREATED, datetime(2024, 5, 1, tzinfo=timezone.utc),
                          tuple(assignments))


def grp(intent, name="Remove Adobe", members=0, mode="include", gid="g1"):
    return A("group", mode, intent, gid, name, members)


def test_only_uninstall_assignments_is_flagged_medium_and_explained():
    a = evaluate_intune_app(app(grp("uninstall"), grp("uninstall", "Remove Adobe 2", 7, gid="g2")), NOW)
    assert a.codes == {F.UNINSTALL_ONLY_APP} and a.risk is R.MEDIUM
    text = a.flags[0].explanation
    assert "only uninstall assignments" in text and "'Remove Adobe' (0 members)" in text and "'Remove Adobe 2' (7 members)" in text
    assert "1 of 2 target group(s) are empty" in text and "created 2023-10-24" in text
    assert "candidates for review" in text and "safe to delete" not in text.lower()
    assert a.flags[0].evidence["empty_groups"] == 1 and a.flags[0].evidence["groups"] == 2


@pytest.mark.parametrize("install", ["required", "available", "availableWithoutEnrollment"])
def test_any_install_intent_means_not_flagged(install):
    assert evaluate_intune_app(app(grp("uninstall"), grp(install, "Install group", 5, gid="g2")), NOW).flags == ()


def test_exclusions_are_ignored_even_though_they_carry_an_intent():
    a = evaluate_intune_app(app(grp("uninstall"), grp("required", "Excluded", 3, mode="exclude", gid="g2")), NOW)
    assert a.codes == {F.UNINSTALL_ONLY_APP}


def test_uninstall_to_all_users_counts_and_is_named():
    a = evaluate_intune_app(app(A("all_users", "include", "uninstall"), grp("uninstall")), NOW)
    assert "All licensed users" in a.flags[0].explanation


def test_install_to_all_devices_is_not_flagged():
    assert evaluate_intune_app(app(A("all_devices", "include", "required"), grp("uninstall")), NOW).flags == ()


def test_exclusion_only_app_counts_as_unassigned():
    a = evaluate_intune_app(app(grp("uninstall", mode="exclude")), NOW)
    assert a.codes == {F.UNASSIGNED_APP}


def test_unknown_intent_is_treated_as_possibly_installing():
    assert evaluate_intune_app(app(grp("uninstall"), grp("", "Mystery", 1, gid="g2")), NOW).flags == ()


def test_unscanned_and_unknown_groups_are_disclosed_not_guessed():
    a = evaluate_intune_app(app(grp("uninstall", members=None), A("group", "include", "uninstall", "deadbeef-0000", None, None)), NOW)
    text = a.flags[0].explanation
    assert "members unknown: group not scanned" in text and "unknown group deadbeef" in text and "2 not scanned yet" in text
    assert "0 of 2 target group(s) are empty" in text


# ------------------------------------------------------------ unassigned apps ---
def unassigned(*rels, checked=True):
    return replace(app(), relationships=tuple(rels) if checked else None)


def test_unassigned_app_nobody_needs_is_low_and_says_why():
    a = evaluate_intune_app(unassigned(), NOW)
    assert a.codes == {F.UNASSIGNED_APP} and a.risk is R.LOW
    assert "No other app depends on it and no newer app supersedes it" in a.flags[0].explanation
    assert "safe to delete" not in a.flags[0].explanation.lower()


def test_unassigned_app_that_another_app_depends_on_is_not_flagged():
    a = evaluate_intune_app(unassigned(Rel("dependency", "parent", "x1", "Premiere 2023", True, "autoInstall")), NOW)
    assert a.flags == ()


def test_dependency_on_something_else_does_not_protect_it():
    a = evaluate_intune_app(unassigned(Rel("dependency", "child", "x1", "Runtime", True, "detect")), NOW)
    assert a.codes == {F.UNASSIGNED_APP}


def test_superseded_unassigned_app_is_medium_with_the_supersedence_warning():
    a = evaluate_intune_app(unassigned(Rel("supersedence", "parent", "n1", "7-Zip 23.01", True, "replace")), NOW)
    text = a.flags[0].explanation
    assert a.risk is R.MEDIUM and "superseded by '7-Zip 23.01' (assigned)" in text
    assert "no longer be upgraded" in text
    assert a.flags[0].evidence["superseded_by"] == ["7-Zip 23.01"]


def test_superseded_by_an_app_that_is_also_unassigned_is_stated():
    a = evaluate_intune_app(unassigned(Rel("supersedence", "parent", "n1", "New", False, "replace")), NOW)
    assert "'New' (also unassigned)" in a.flags[0].explanation


def test_unassigned_app_that_supersedes_others_mentions_them():
    a = evaluate_intune_app(unassigned(Rel("supersedence", "child", "o1", "Old 1.2", False, "replace")), NOW)
    assert "supersedes 1 older app(s): 'Old 1.2'" in a.flags[0].explanation


def test_relationships_not_read_is_disclosed_and_never_medium():
    a = evaluate_intune_app(unassigned(checked=False), NOW)
    assert a.risk is R.LOW and "could not be read" in a.flags[0].explanation and a.flags[0].evidence["relationships_checked"] is False


# --------------------------------------------------------------------- scripts ---
T = Thresholds()
OLD = datetime(2021, 3, 2, tzinfo=timezone.utc)
RECENT = datetime(2026, 9, 1, tzinfo=timezone.utc)


def script(kind="powershell", modified=OLD, assignments=None, run=None):
    return IntuneScriptFacts("s1", "Fix thing", kind, modified, modified,
                             tuple(assignments if assignments is not None else [A("group", "include", "", "g1", "Team", 50)]), run)


def test_healthy_recent_script_is_not_flagged():
    assert evaluate_intune_script(script(modified=RECENT, run={"successDeviceCount": 10}), T, NOW).flags == ()


def test_old_but_working_script_is_only_low_stale_not_obsolete():
    a = evaluate_intune_script(script(run={"successDeviceCount": 400, "errorDeviceCount": 1}), T, NOW)
    assert a.codes == {F.STALE_SCRIPT} and a.risk is R.LOW


def test_unassigned_script_flagged_low_and_old_makes_it_obsolete():
    assert evaluate_intune_script(script(modified=RECENT, assignments=[]), T, NOW).codes == {F.UNASSIGNED_SCRIPT}
    a = evaluate_intune_script(script(assignments=[]), T, NOW)
    assert {F.UNASSIGNED_SCRIPT, F.STALE_SCRIPT, F.LIKELY_OBSOLETE_SCRIPT} <= a.codes and a.risk is R.MEDIUM
    assert "unassigned" in next(f for f in a.flags if f.code is F.LIKELY_OBSOLETE_SCRIPT).explanation


def test_script_targeting_only_empty_groups():
    a = evaluate_intune_script(script(modified=RECENT, assignments=[A("group", "include", "", "g1", "Phoenix", 0)]), T, NOW)
    assert a.codes == {F.EMPTY_TARGETS_SCRIPT} and a.risk is R.MEDIUM and "'Phoenix'" in a.flags[0].explanation


def test_unknown_member_counts_or_other_targets_prevent_empty_targets():
    assert evaluate_intune_script(script(modified=RECENT, assignments=[A("group", "include", "", "g1", "X", None)]), T, NOW).flags == ()
    mixed = [A("group", "include", "", "g1", "X", 0), A("all_devices", "include", "")]
    assert evaluate_intune_script(script(modified=RECENT, assignments=mixed), T, NOW).flags == ()


@pytest.mark.parametrize("kind", ["powershell", "shell"])
def test_script_that_never_succeeded_is_failing(kind):
    a = evaluate_intune_script(script(kind, modified=RECENT, run={"successDeviceCount": 0, "errorDeviceCount": 535}), T, NOW)
    assert a.codes == {F.FAILING_SCRIPT} and "535" in a.flags[0].explanation and a.risk is R.MEDIUM


def test_script_with_some_success_is_not_failing_and_users_count_too():
    assert evaluate_intune_script(script(modified=RECENT, run={"successDeviceCount": 1, "errorDeviceCount": 500}), T, NOW).flags == ()
    assert evaluate_intune_script(script(modified=RECENT, run={"successUserCount": 3, "errorDeviceCount": 5}), T, NOW).flags == ()


def test_script_that_never_ran_is_not_called_failing():
    assert evaluate_intune_script(script(modified=RECENT, run={"successDeviceCount": 0, "errorDeviceCount": 0}), T, NOW).flags == ()


def test_old_failing_script_is_likely_obsolete():
    a = evaluate_intune_script(script(run={"successDeviceCount": 0, "errorDeviceCount": 120}), T, NOW)
    assert {F.FAILING_SCRIPT, F.STALE_SCRIPT, F.LIKELY_OBSOLETE_SCRIPT} <= a.codes


def test_remediation_idle_rules():
    old_run = {"lastScriptRunDateTime": "2025-01-01T00:00:00Z"}
    a = evaluate_intune_script(script("remediation", modified=RECENT, run=old_run), T, NOW)
    assert a.codes == {F.IDLE_REMEDIATION} and "last ran on 2025-01-01" in a.flags[0].explanation
    never = evaluate_intune_script(script("remediation", modified=RECENT, run={"lastScriptRunDateTime": None}), T, NOW)
    assert "has never run on any device" in never.flags[0].explanation
    recent = {"lastScriptRunDateTime": "2026-10-24T00:00:00Z"}
    assert evaluate_intune_script(script("remediation", modified=RECENT, run=recent), T, NOW).flags == ()


def test_unassigned_remediation_is_unassigned_not_idle():
    a = evaluate_intune_script(script("remediation", modified=RECENT, assignments=[], run={"lastScriptRunDateTime": None}), T, NOW)
    assert a.codes == {F.UNASSIGNED_SCRIPT}


def test_remediation_is_never_called_failing_and_scripts_never_idle():
    assert F.FAILING_SCRIPT not in evaluate_intune_script(script("remediation", modified=RECENT, run={"errorDeviceCount": 9}), T, NOW).codes
    assert F.IDLE_REMEDIATION not in evaluate_intune_script(script("powershell", modified=RECENT, run={}), T, NOW).codes


def test_missing_run_results_are_disclosed_not_guessed():
    a = evaluate_intune_script(script(modified=RECENT, run=None), T, NOW)
    assert a.flags == () and a.unavailable_signals


def test_thresholds_are_respected():
    assert evaluate_intune_script(script(modified=datetime(2026, 1, 1, tzinfo=timezone.utc)), Thresholds(stale_days_script=100), NOW).codes == {F.STALE_SCRIPT}
    assert evaluate_intune_script(script(modified=datetime(2026, 1, 1, tzinfo=timezone.utc)), Thresholds(stale_days_script=1000), NOW).flags == ()


# --------------------------------------------- on-demand: not checked yet ---
def test_unassigned_app_whose_relations_were_not_checked_is_not_flagged_but_says_why():
    a = evaluate_intune_app(replace(app(), scanned=False, relationships=None), NOW)
    assert a.flags == () and "scan this app" in a.unavailable_signals[0]


def test_uninstall_only_app_needs_no_check():
    a = evaluate_intune_app(replace(app(grp("uninstall")), scanned=False), NOW)
    assert a.codes == {F.UNINSTALL_ONLY_APP}


def test_unchecked_script_still_gets_the_inventory_level_flags_but_a_note_about_run_results():
    s = replace(script(assignments=[]), scanned=False, run=None)
    a = evaluate_intune_script(s, T, NOW)
    assert {F.UNASSIGNED_SCRIPT, F.STALE_SCRIPT, F.LIKELY_OBSOLETE_SCRIPT} <= a.codes
    assert "not read yet" in a.unavailable_signals[0] and "scan this script" in a.unavailable_signals[0]


def test_checked_script_with_unreadable_run_results_says_could_not_be_read():
    a = evaluate_intune_script(replace(script(modified=RECENT), scanned=True, run=None), T, NOW)
    assert "could not be read" in a.unavailable_signals[0]
